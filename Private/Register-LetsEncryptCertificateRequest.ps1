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
function Register-LetsEncryptCertificateRequest {
    [CmdletBinding(
        SupportsShouldProcess = $false,
        PositionalBinding = $false,
        HelpUri = 'https://github.com/RobBiddle/ACMESharpRoute53Automation/',
        ConfirmImpact = 'Medium')]
    [Alias()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param (
        # Domain Name(s) to be included in certificate.  First name will be primary, remaining will be additional hosts in SAN certificate
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        [Parameter(ParameterSetName = "Production")]
        [Parameter(ParameterSetName = "Staging")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $DomainNames,

        # Email Address(es) for LetsEncrypt Registration - used for all Domains
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Net.Mail.MailAddress[]]
        $Contacts,

        # ACME Challenge Type (This cmdlet only allows for DNS)
        [ValidateNotNullOrEmpty()]
        [ValidateSet('dns-01')]
        [String]
        $ChallengeType = 'dns-01',

        # Switch to LetEncrypt Staging instead of Production
        [Parameter(ParameterSetName = "Staging")]
        [Switch]
        $Staging
    )    
    begin {
        # Verify ACMESharp & AWSPowerShell modules are installed
        if (!(Get-Module -ListAvailable ACMESharp)) {
            Throw "ACMESharp PowerShell Module is required and was not found"
        }
        if (!(Get-Module ACMESharp)) {
            Import-Module ACMESharp -ErrorAction SilentlyContinue
        }
        # Set ACMESharp Vault to Staging or Production by ParameterSetName 
        if ($pscmdlet.ParameterSetName -like "Staging") {
            Write-Warning "Staging Mode --- Using ACMESharp BaseService LetsEncrypt-STAGING --- Certificates Are For Testing Purposes!"
            if (!(Get-ACMEVault)) {
                Initialize-ACMEVault -BaseService LetsEncrypt-STAGING -Alias Staging | Out-Null
            }
            Else {
                Set-ACMEVault -BaseService LetsEncrypt-STAGING -Alias Staging | Out-Null
            }
        }
        if ($pscmdlet.ParameterSetName -like "Production") {
            Write-Warning "Production Mode --- Using ACMESharp BaseService LetsEncrypt --- Certificates Are Valid for Production Use"
            Write-Warning "Actions Will Count Against LetsEncrypt Limits!!!"
            Write-Warning "See https://letsencrypt.org/docs/rate-limits/ for details"
            if (!(Get-ACMEVault)) {
                Initialize-ACMEVault -BaseService LetsEncrypt -Alias Production | Out-Null
            }
            Else {
                Set-ACMEVault -BaseService LetsEncrypt -Alias Production | Out-Null
            }
        }        
        # Create LetsEncrypt Registration if necessary
        if (!(Get-ACMERegistration | Where-Object Contacts -like "*$Contacts*")) {
            New-ACMERegistration -Contacts "mailto:$Contacts" -AcceptTos | Out-Null
        }
        # Generate a DateTime String to use as an Alias Salt for this run
        $AliasSalt = Get-Date -Format FileDateTime
        $Output = @()
    }
    process {
        $DomainNames | ForEach-Object {
            $DomainName = "$_"
            $Alias = "$DomainName-$AliasSalt"
            function NewLetsEncryptDomain ($DomainName, $Alias, $AliasSalt, $ChallengeType) {
                # Create new LetsEncrypt Domain
                $Alias = "$DomainName-$AliasSalt"
                $ACMEIdentifier = New-ACMEIdentifier -Dns $DomainName -alias $Alias

                # Specify DNS as the Challenge Type to be used
                $ACMEChallenge = Complete-ACMEChallenge -IdentifierRef $Alias -ChallengeType $ChallengeType -Handler 'manual'

                # Get DNS Challenge data
                $ChallengeRecordName = ($ACMEChallenge.Challenges | Where-Object Type -eq $ChallengeType).Challenge.RecordName
                $ChallengeRecordValue = ($ACMEChallenge.Challenges | Where-Object Type -eq $ChallengeType).Challenge.RecordValue

                # Parse the ChallengeRecordName to split root zone from hostname
                $splitFQDN = ($ChallengeRecordName).Split(".")
                $DnsZone = "$($splitFQDN[($splitFQDN.count -2)]).$($splitFQDN[($splitFQDN.count -1)])"
                $DnsHost = ''
                $splitFQDN[0 .. ($splitFQDN.count - 3)] | ForEach-Object {
                    $DnsHost = -join ("$DnsHost", "$_", ".")
                }
                $DnsHost = ($DnsHost).Trim(".")
                $NameServer = (Resolve-DnsName $DnsZone -Type NS).NameHost[0]

                # Build Object for Output
                $CurrentACMEIdentifier = Get-ACMEIdentifier | Where-Object Alias -like $Alias
                if ($CurrentACMEIdentifier.count -ne 1) {
                    Write-Error "FUBAR"
                }
                $obj = $null
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -NotePropertyName Alias -NotePropertyValue $CurrentACMEIdentifier.Alias
                $obj | Add-Member -NotePropertyName Dns -NotePropertyValue $CurrentACMEIdentifier.Dns
                $obj | Add-Member -NotePropertyName Label -NotePropertyValue $CurrentACMEIdentifier.Label
                $obj | Add-Member -NotePropertyName Id -NotePropertyValue $CurrentACMEIdentifier.Id
                $obj | Add-Member -NotePropertyName Seq -NotePropertyValue $CurrentACMEIdentifier.Seq
                $obj | Add-Member -NotePropertyName Status -NotePropertyValue $CurrentACMEIdentifier.Status
                $obj | Add-Member -NotePropertyName AliasSalt -NotePropertyValue $AliasSalt
                $obj | Add-Member -NotePropertyName ChallengeRecordName -NotePropertyValue $ChallengeRecordName
                $obj | Add-Member -NotePropertyName ChallengeRecordValue -NotePropertyValue $ChallengeRecordValue
                $obj | Add-Member -NotePropertyName ChallengeRecordHost -NotePropertyValue $DnsHost
                $obj | Add-Member -NotePropertyName ChallengeRecordZone -NotePropertyValue $DnsZone
                $obj | Add-Member -NotePropertyName ChallengeRecordDnsServer -NotePropertyValue $NameServer
                Return $obj
            }
            $Output += NewLetsEncryptDomain -DomainName $DomainName -Alias $Alias -AliasSalt $AliasSalt -ChallengeType $ChallengeType
        }
    }
    end {
        Return $Output
    }
}
