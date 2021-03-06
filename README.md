# BlueKeep-Scanner-PS-Parser

## Requirements

* [PowerShell 7!](https://github.com/PowerShell/PowerShell/releases)
* [PDQ Inventory](https://www.pdq.com/pdq-inventory/) with an [Enterprise license](https://sales.pdq.com/)
* [rdpscan](https://github.com/robertdavidgraham/rdpscan)

## Running this script

First, You need to open a PWSH session. If PS 7 is still in preview:  
`pwsh-preview`  
otherwise:  
`pwsh`

Next, execute this script with your desired parameters:  
`.\Find-BlueKeepVulnerableComputers.ps1 -Verbose -RDPScanEXE "C:\Users\Bob\Downloads\rdpscan-windows-3\rdpscan.exe" -Collections "All Computers" -MaxJobs 64`

If you want to see all of the parameters:  
`Get-Help .\Find-BlueKeepVulnerableComputers.ps1`

You can go pretty high with -MaxJobs if you have enough RAM. `-MaxJobs 128` used about 1.2 GB on my computer. Your mileage may vary.

## License

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.