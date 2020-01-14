<#
    Written by Colby Bouma
    Copyright © 2019 PDQ.com Corporation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    This script executes 'rdpscan' and ingests the results into PDQ Inventory.
    https://github.com/robertdavidgraham/rdpscan
    https://github.com/Colby-PDQ/BlueKeep-Scanner-PS-Parser/blob/master/Find-BlueKeepVulnerableComputers.ps1
#>

################################################################################
## Setup
################################################################################

[CmdletBinding()]
param (
    [string]$RDPScanEXE,
    [array] $Collections,
    [array] $Computers,
    [int32] $MaxJobs,
    [string]$CustomFieldNameStatus = "BlueKeep Status",
    [string]$CustomFieldNameNotes = "BlueKeep Notes",
    [switch]$Randomize = $false,
    [int32] $Port = 3389
)

# Checking the PS version this way allows us to throw a more detailed error message, and to exit on a non-zero exit code
if ( $PSVersionTable.PSVersion.Major -lt 7 ) {

    Write-Error "This script requires PowerShell version 7 or greater. Detected version: $($PSVersionTable.PSVersion)"
    "You can download the latest version of PowerShell from GitHub: https://github.com/PowerShell/PowerShell/releases"
    Exit 5

}

$MaxJobsDefault = 32

if ( -not $MaxJobs ) {

    $MaxJobs = $MaxJobsDefault

} elseif ( $MaxJobs -lt 1 ) {

    Write-Warning "MaxJobs cannot be less than 1, setting it to $MaxJobsDefault"
    $MaxJobs = $MaxJobsDefault

}
Write-Verbose "MaxJobs: $MaxJobs"

if ( -not ( Test-Path "$RDPScanEXE" ) ) {

    Write-Error "Unable to access: $RDPScanEXE"
    Exit 10

}

# Both are specified
if ( (-not $Collections) -and (-not $Computers) ) {

    Write-Error "You cannot specify both -Collections and -Computers. Please choose 1"
    Exit 20

}

# Neither are specified
if ( ($Collections) -and ($Computers) ) {

    Write-Error "You must specify either -Collections or -Computers"
    Exit 30

}

Write-Verbose "Retrieving targets from collection(s)"
$Targets = New-Object System.Collections.Generic.List[string]
if ( $Collections ) {

    # I'm not sure if it's safe to make this one Parallel because of the array "deduping"
    ForEach ( $Collection in $Collections ) {
        
        $CollectionComputers = PDQInventory.exe GetCollectionComputers "$Collection" 2>&1
        if ( $CollectionComputers -eq "Collection not found: $Collection" ) {

            Write-Warning "Unable to find collection: $Collection"

        } else {

            ForEach ( $CollectionComputer in $CollectionComputers ) {

                # Dedupe the target list
                if ( $CollectionComputer -notin $Targets ) {

                    $Targets.Add($CollectionComputer)

                }

            }
            
        }

    }

}

# Dump $Computers directly into $Targets, no processing is required
if ( $Computers ) {

    $Targets = $Computers

}

if ( -not $Targets ) {

    Write-Error "No targets were found. Are the collections you specified empty?"
    Exit 40

}

# Randomize the target list. This may help avoid "hot spots", groups of targets that all scan slowly.
# This _should_ return the entire list in a random order. Please let me know if this ever returns duplicates!
if ( $Randomize ) {

    Write-Verbose "Randomizing target list"
    $Targets = Get-Random -InputObject $Targets -Count $Targets.Count

}

# Store the CSV file in your TEMP folder with a GUID as the filename to avoid potential conflicts
$ResultsCSV = "$env:TEMP\$(New-Guid).csv"
Write-Verbose "Creating $ResultsCSV"
"Computer Name, $CustomFieldNameStatus, $CustomFieldNameNotes" | Out-File -FilePath "$ResultsCSV"



################################################################################
## Functions
################################################################################

function Invoke-Cleanup {

    param (
        [array]$FilesToRemove
    )

    ForEach ( $File in $FilesToRemove ) {
    
        Write-Verbose "Removing $File"
        Remove-Item -Force -Path "$File"

    }

}



################################################################################
## Main
################################################################################

Write-Verbose "Scanning $($Targets.Count) targets"
$Results = $Targets | ForEach-Object -ThrottleLimit $MaxJobs -Parallel {
        
    $Target     = $_
    $Port       = $Using:Port
    $RDPScanEXE = $Using:RDPScanEXE
    $ResultsCSV = $Using:ResultsCSV
    
    $StopWatch = [Diagnostics.Stopwatch]::StartNew()
    $ScanResult = & "$RDPScanEXE" --port $Port "$Target" 2>&1
    $StopWatch.Stop()

    # The longest I've seen rdpscan.exe take is ~40 seconds, so write a warning if it took longer than that
    if ( $StopWatch.Elapsed.TotalSeconds -ge 45 ) {

        # Interesting note: I wanted this to be Verbose, but that doesn't work in jobs
        Write-Warning "$Target took $($StopWatch.Elapsed.TotalSeconds) seconds"

    }

    # Process multi-line results
    if ( $ScanResult.GetType().Name -eq "Object[]" ) {

        # Check for errors
        ForEach ( $Record in $ScanResult ) {

            if ( $Record.GetType().Name -eq "ErrorRecord" ) {

                $ErrorFound = $true

            } else {

                # Because there are multiple lines, this variable should always be created.
                # Please slap me with a trout if I am wrong.
                $ScanResultNormal = $Record

            }

        }

        if ( $ErrorFound ) {

            # Replace the computer name with 0.0.0.0 so it will pass the IP filter and go through result processor.
            $ScanResult = $ScanResultNormal -replace "$Target", "0.0.0.0"

        } else {
        
            # No errors were found, just grab the first line            
            Write-Warning "$Target returned multiple results, but there were no errors"
            $ScanResult = $ScanResult[0]

        }

    }
    
    # For some reason PowerShell inserts an empty line between every line.
    # If you know how to capture output from rdpscan.exe without the extraneous lines (without writing to a file), please let me know!
    # This _should_ let through both IPv4 and IPv6 addresses.
    if ( $ScanResult -match "^\d+\.\d+\.\d+\.\d+|^[\da-f]+:[\da-f:]*:[\da-f]+" ) {

        # Some results have --, but most have -. Putting -- first in the split makes it look for that pattern first
        # and prevents it from splitting twice.
        $SplitResult = $ScanResult -split "--|-"
        
        # .Trim() removes any extra whitespace from the beginning and end of each element in the array.
        $SplitResult = $SplitResult.Trim()

        # Computer name, SAFE/VULNERABLE/UNKNOWN, notes
        $CSVLine = "{0}, {1}, {2}" -f $Target, $SplitResult[1], $SplitResult[2]
        
        # Dump $CSVLine into the output stream so $Results can capture it
        $CSVLine
        
        # Use Write-Host to bypass the output stream since it's currently being captured by $Results
        Write-Host $CSVLine

    } else {

        Write-Warning "$Target --- $ScanResult"

    }
    
}

Write-Verbose "Writing results to CSV file"
$Results | Out-File -FilePath "$ResultsCSV" -Append

# Create Custom Fields if they don't exist
# This will throw an error if the Custom Field already exists, but we don't care about that, so just send it into the ether with `$null =`
Write-Verbose "Creating Custom Fields"
$null = PDQInventory.exe CreateCustomField -Name "$CustomFieldNameStatus" -Type "String" 2>&1
$null = PDQInventory.exe CreateCustomField -Name "$CustomFieldNameNotes" -Type "String" 2>&1

# Import scan results into Inventory
Write-Verbose "Importing CSV"
PDQInventory.exe ImportCustomFields -FileName "$ResultsCSV" -AllowOverwrite

Invoke-Cleanup -FilesToRemove $ResultsCSV