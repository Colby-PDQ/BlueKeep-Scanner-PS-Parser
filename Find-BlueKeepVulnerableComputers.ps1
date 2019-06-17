# This script executes 'rdpscan' and ingests the results into PDQ Inventory.
# https://github.com/robertdavidgraham/rdpscan
# https://github.com/Colby-PDQ/BlueKeep-Scanner-PS-Parser/blob/master/Find-BlueKeepVulnerableComputers.ps1
# 
# v 001

################################################################################
## Setup
################################################################################

[CmdletBinding()]
param (
    [string]$RDPScanEXE,
    [array] $Collections,
    [array] $Computers,
    [int32] $MaxJobs = ( ( Get-CimInstance Win32_Processor ).ThreadCount * 4 ),
    [int32] $FailSafeMax = 1200,
    [string]$CustomFieldNameStatus = "BlueKeep Status",
    [string]$CustomFieldNameNotes = "BlueKeep Notes",
    [switch]$Randomize = $false
)

if ( $MaxJobs -lt 1 ) { 

    Write-Warning "MaxJobs was set to $MaxJobs, and that's bad. Changing it to 1"
    $MaxJobs = 1

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
$Targets = New-Object System.Collections.ArrayList
if ( $Collections ) {

    ForEach ( $Collection in $Collections ) {
        
        $CollectionComputers = PDQInventory.exe GetCollectionComputers "$Collection" 2>&1
        if ( $CollectionComputers -eq "Collection not found: $Collection" ) {

            Write-Warning "Unable to find collection: $Collection"

        } else {

            ForEach ( $CollectionComputer in $CollectionComputers ) {

                # Dedupe the target list
                if ( $CollectionComputer -notin $Targets ) {

                    # https://foxdeploy.com/2016/03/23/coding-for-speed/
                    $null = $Targets.Add($CollectionComputer)

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

# Keep track of job IDs to avoid stomping on jobs that don't belong to this script
$Global:JobIDs = New-Object System.Collections.ArrayList



################################################################################
## Functions
################################################################################

function Get-RunningJobCount {
    
    # Get-Job doesn't like it when the value you specify for -Id is $null
    if ( $Global:JobIDs.Count -gt 0 ) {
    
        ( Get-Job -Id $Global:JobIDs | Where-Object State -eq "Running" ).Count

    } else {

        0

    }

}

function Invoke-Cleanup {

    param (
        [array]$FilesToRemove
    )
    
    if ( $Global:JobIDs.Count -gt 0 ) {
    
        Write-Verbose "Removing all jobs"
        Get-Job -Id $Global:JobIDs | Remove-Job -Force

    }

    ForEach ( $File in $FilesToRemove ) {
    
        Write-Verbose "Removing $File"
        Remove-Item -Force -Path "$File"

    }

}

function Clear-FinishedJobs {

    param (
        $MaxJobs,
        $FailSafeMax,
        $ResultsCSV
    )

    $FailSafe = 0
    $NumberOfJobs = Get-RunningJobCount

    # Once the job limit is reached, pause for a bit, then try again.
    while ( $NumberOfJobs -ge $MaxJobs ) {
        
        # I know this is redundant, but I don't want to pause if the job limit _hasn't_ been reached.
        $NumberOfJobs = Get-RunningJobCount

        # This may seem backwards, but I want to make sure the last action to be run is the cleanup.
        # I don't want a job to finish between the count and the cleanup and never get retrieved.
        $CompletedJobs = Get-Job -Id $Global:JobIDs | Where-Object State -eq "Completed"
        $CompletedJobs | Receive-Job | Tee-Object -FilePath "$ResultsCSV" -Append
        $CompletedJobs | Remove-Job
        ForEach ( $CompletedJob in $CompletedJobs ) {

            $Global:JobIDs.Remove($CompletedJob.Id)

        }

        if ( $FailSafe -ge $FailSafeMax ) {
            
            Write-Error "Got stuck waiting for jobs to finish, something is taking too long"
            Invoke-Cleanup -FilesToRemove $ResultsCSV
            Exit 50
            
        }
        $FailSafe ++
        
        Start-Sleep -Milliseconds 250
        
    }

}



################################################################################
## Main
################################################################################

Write-Verbose "Scanning $($Targets.Count) targets"
ForEach ( $Target in $Targets ) {

    $ScriptBlock = {

        $RDPScanEXE = $Using:RDPScanEXE
        $Target = $Using:Target
        
        $StopWatch = [Diagnostics.Stopwatch]::StartNew()
        $ScanResult = & "$RDPScanEXE" "$Target" 2>&1
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
            "{0}, {1}, {2}" -f $Target, $SplitResult[1], $SplitResult[2]

        } else {

            Write-Warning "$Target --- $ScanResult"

        }

    }

    Clear-FinishedJobs -MaxJobs $MaxJobs -FailSafeMax $FailSafeMax -ResultsCSV $ResultsCSV
    
    # Start this job
    $Job = Start-Job -ScriptBlock $ScriptBlock
    $null = $Global:JobIDs.Add($Job.Id)
    
}

# Process the remaining jobs
# -MaxJobs 1 makes the while loop run until there are no more running jobs
Clear-FinishedJobs -MaxJobs 1 -FailSafeMax $FailSafeMax -ResultsCSV $ResultsCSV

# This should never be True. I only created this because I'm paranoid :P
if ( $Global:JobIDs.Count -ne 0 ) {

    Write-Warning "The following job(s) did not get processed: $($Global:JobIDs)"

}

# Create Custom Fields if they don't exist
# This will throw an error if the Custom Field already exists, but we don't care about that, so just send it into the ether with `$null =`
Write-Verbose "Creating Custom Fields"
$null = PDQInventory.exe CreateCustomField -Name "$CustomFieldNameStatus" -Type "String" 2>&1
$null = PDQInventory.exe CreateCustomField -Name "$CustomFieldNameNotes" -Type "String" 2>&1

# Import scan results into Inventory
Write-Verbose "Importing CSV"
PDQInventory.exe ImportCustomFields -FileName "$ResultsCSV" -AllowOverwrite

Invoke-Cleanup -FilesToRemove $ResultsCSV