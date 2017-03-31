<#
.NOTES
    Author: Robert D. Biddle
    https://github.com/RobBiddle
    https://github.com/RobBiddle/ACMESharpRoute53Automation
    ACMESharpRoute53Automation  Copyright (C) 2017  Robert D. Biddle
    This program comes with ABSOLUTELY NO WARRANTY; for details type `"help Get-NewLetsEncryptCertificate -full`".
    This is free software, and you are welcome to redistribute it
    under certain conditions; for details type `"help Get-NewLetsEncryptCertificate -full`".

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    The GNU General Public License does not permit incorporating your program
    into proprietary programs.  If your program is a subroutine library, you
    may consider it more useful to permit linking proprietary applications with
    the library.  If this is what you want to do, use the GNU Lesser General
    Public License instead of this License.  But first, please read
    <http://www.gnu.org/philosophy/why-not-lgpl.html>.
#>
function Push-LetsEncryptChallengeToRoute53 {
    [CmdletBinding(DefaultParameterSetName = "Set1",
        SupportsShouldProcess = $false,
        PositionalBinding = $true,
        HelpUri = 'http://www.microsoft.com/',
        ConfirmImpact = 'Medium')]
    [Alias()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param (
        # InputObject should be output from Register-LetsEncryptCertificateRequest
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = "Set1")]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $InputObject
    )
    begin {
        # Verify ACMESharp & AWSPowerShell modules are installed
        if (!(Get-Module -ListAvailable ACMESharp)) {
            Throw "ACMESharp PowerShell Module is required and was not found"
        }
        if (!(Get-Module -ListAvailable AWSPowerShell)) {
            Throw "AWSPowerShell PowerShell Module is required and was not found"
        }
        if (!(Get-Module ACMESharp)) {
            Import-Module ACMESharp -ErrorAction SilentlyContinue
        }
        if (!(Get-Module AWSPowerShell)) {
            Import-Module AWSPowerShell -ErrorAction SilentlyContinue
        }
        Function Update-R53ResourceRecordSet {
            param(
                [Parameter(Mandatory = $True)][String]$Value,
                [Parameter(Mandatory = $True)][ValidateSet("CNAME", "A", "AAAA", "MX", "TXT", "PTR", "SRV", "SPF", "NS", "SOA")]$Type,
                [Parameter(Mandatory = $True)]$RecordName,
                [Parameter(Mandatory = $True)]$TTL,
                [Parameter(Mandatory = $True)]$ZoneName,
                [Parameter(Mandatory = $False)]$Comment
            )
            $ZoneEntry = (Get-R53HostedZones) | Where-Object {$_.Name -eq "$($ZoneName)."}

            If ($ZoneEntry) {
                $CreateRecord = New-Object Amazon.Route53.Model.Change
                $CreateRecord.Action = "UPSERT"
                $CreateRecord.ResourceRecordSet = New-Object Amazon.Route53.Model.ResourceRecordSet
                $CreateRecord.ResourceRecordSet.Name = "$RecordName.$ZoneName"
                $CreateRecord.ResourceRecordSet.Type = $Type
                $CreateRecord.ResourceRecordSet.TTL = $TTL
                $CreateRecord.ResourceRecordSet.ResourceRecords.Add(@{Value = if ( $Type -eq "TXT" ) { """$Value""" } else { $Value } } )
                Edit-R53ResourceRecordSet -ProfileName $ProfileName -HostedZoneId $ZoneEntry.Id -ChangeBatch_Change $CreateRecord -ChangeBatch_Comment $Comment
            }
            Else {
                Write-Warning "Zone name '$ZoneName' not found"
                Write-Warning "This Cmdlet expects to be run on an EC2 Instance with an IAM Policy allowing Route53 updates"
            }
        } 
    }    
    process {
        # Adding Route53 Resource Records
        $InputObject | ForEach-Object {
            # Set Route53 DNS Record for Challenge verification
            Update-R53ResourceRecordSet -RecordName $_.ChallengeRecordHost -Type "TXT" -value $_.ChallengeRecordValue -TTL 60 -ZoneName $_.ChallengeRecordZone
        }
    }    
    end {

    }
}

