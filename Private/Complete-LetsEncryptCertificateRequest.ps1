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
function Complete-LetsEncryptCertificateRequest {
    [CmdletBinding(SupportsShouldProcess = $true,
        PositionalBinding = $false,
        HelpUri = 'https://github.com/RobBiddle/ACMESharpRoute53Automation/',
        ConfirmImpact = 'Medium')]
    [Alias()]
    [OutputType([String])]
    Param (
        # Password to protect PFX file
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertPwd,

        # Path to Output Certificates
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [String]
        $OutputPath,

        # Domain Name(s) to be included in certificate.  First name will be primary, remaining will be additional hosts in SAN certificate
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
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

        if (!(Get-ACMEVault)) {
            Throw "ACMEVault MISSING!!!  Hint: Register-LetsEncryptCertificateRequest must be run first"
        }
        $AliasSalt = $InputObject.AliasSalt | Select-Object -First 1
    }    
    process {
        # Wait for DNS TXT Record to Resolve using exponential backoff 
        $InputObject | ForEach-Object {
            $CurrentRecord = $_
            $BackOffSeconds = $null
            $TxtStrings = $null
            Write-Output "Attempting to Resolve: $($CurrentRecord.ChallengeRecordName)"
            foreach ($n in (1 .. 11)) {
                $BackOffSeconds = [Math]::Pow(2, $n)
                $TxtStrings = (Resolve-DnsName -Name $CurrentRecord.ChallengeRecordName -Type TXT -Server $CurrentRecord.ChallengeRecordDnsServer -ErrorAction SilentlyContinue).Strings
                if ($TxtStrings -like $CurrentRecord.ChallengeRecordValue) {
                    Start-Sleep -Seconds 1 # Submit-ACMEChallenge was throwing errors if proceeding too quickly after first successful name resolution
                    Return "Successfully Resolved: $($CurrentRecord.ChallengeRecordName)"
                }
                if ($BackOffSeconds -gt 1800) {
                    Throw "Timed out waiting for Challenge Response TXT record resolution"
                }
                Write-Output "$($CurrentRecord.ChallengeRecordName) has not resolved...Waiting for $BackOffSeconds Seconds"
                Start-Sleep -Seconds $BackOffSeconds
            }
        }            
        # ALL Domains should now be albe to complete LetsEncrypt Challenges
        $InputObject | ForEach-Object {
            $CurrentIdentifier = $_
            Get-ACMEIdentifier | Where-Object Status -like "pending" | Where-Object Alias -like "*$AliasSalt" | ForEach-Object {
                Submit-ACMEChallenge $CurrentIdentifier.Alias -ChallengeType 'dns-01'
                Update-ACMEIdentifier $CurrentIdentifier.Alias -ChallengeType 'dns-01'
            }
            $BackOffSeconds = $null
            foreach ($n in (1 .. 17)) {
                $BackOffSeconds = [Math]::Pow(2, $n)
                if (!(Get-ACMEIdentifier | Where-Object Status -like "pending" | Where-Object Alias -like "*$AliasSalt")) {
                    Return
                }
                Else {
                    Get-ACMEIdentifier | Where-Object Status -like "pending" | Where-Object Alias -like "*$AliasSalt" | ForEach-Object {
                        Submit-ACMEChallenge $_.Alias -ChallengeType 'dns-01'
                        Update-ACMEIdentifier $_.Alias
                    }
                }
                if ($BackOffSeconds -gt 43200) {
                    Throw "Timed out waiting for Domain Validation"
                }
                Else {
                    Write-Output "Domain Verification is still pending...Waiting for $BackOffSeconds Seconds"
                    Start-Sleep -Seconds $BackOffSeconds
                }
            }
        }
        # Request Certificates
        $ACMEIdentifiersToInclude = @()
        $ACMEIdentifiersToInclude += (Get-ACMEIdentifier | Where-Object Status -like valid | Where-Object Alias -like "*$AliasSalt" )
        # Generate Singular SSL Certificate Request
        if ($ACMEIdentifiersToInclude.count -lt 2) {
            $CertAlias = "$((Get-ACMEIdentifier | Where-Object Status -like valid | Where-Object Alias -like "*$AliasSalt").Dns[0])-$AliasSalt"
            New-ACMECertificate $ACMEIdentifiersToInclude.Alias -Generate -Alias $CertAlias    
            Submit-ACMECertificate $CertAlias
            Update-ACMECertificate $CertAlias
            $CertsToExport = @()
            $CertsToExport += Get-ACMECertificate | Where-Object Alias -like $CertAlias
        }
        # Determine Subject Alternate Names for Multiples
        $AlternateNames = @()
        0 .. ($ACMEIdentifiersToInclude.count - 1) | ForEach-Object {
            $AlternateNames += "$($ACMEIdentifiersToInclude.Alias[$_])"
        }
        # Generate SAN Certificate Requests
        if ($ACMEIdentifiersToInclude.count -ge 2) {
            $CertAlias = @()
            $NumberOfSets = [Math]::Ceiling($ACMEIdentifiersToInclude.count / 100)
            1 .. $NumberOfSets | ForEach-Object {
                $CurrentSet = $_
                if ($CurrentSet -eq 1) {
                    $TopOfRange = 99
                    $BottomOfRange = 0
                }
                Else {
                    $TopOfRange = $CurrentSet * 99
                    $BottomOfRange = $TopOfRange - 98
                }
                if ($TopOfRange -gt ($AlternateNames.count - 1) ) {
                    $TopOfRange = $AlternateNames.count - 1
                }
                $PartialAlternateNames = @()
                ($BottomOfRange + 1) .. $TopOfRange | ForEach-Object {
                    $PartialAlternateNames += $AlternateNames[$_]
                }
                $CertAlias += "$($ACMEIdentifiersToInclude.Dns[$BottomOfRange])-$AliasSalt"
                New-ACMECertificate $ACMEIdentifiersToInclude.Alias[$BottomOfRange] -Generate  -AlternativeIdentifierRefs $PartialAlternateNames -Alias $CertAlias[$CurrentSet - 1]
                Submit-ACMECertificate $CertAlias[$CurrentSet - 1]
                Update-ACMECertificate $CertAlias[$CurrentSet - 1]
            }
            $CertsToExport = @()
            $CertAlias | ForEach-Object {
                $CertsToExport += Get-ACMECertificate | Where-Object Alias -like $_ # Could be multiple if > 100 ResourceRecordSets
            }
        }
        # Retreive Certificates
        $CertsToExport | ForEach-Object {
            $CurrentCert = $_
            # Wait for Certificate using exponential backoff 
            $BackOffSeconds = $null
            foreach ($n in (1 .. 17)) {
                $BackOffSeconds = [Math]::Pow(2, $n)                
                if ((Get-ACMECertificate | Where-Object Alias -like $CurrentCert.Alias).SerialNumber) {
                    Return
                }
                Else {
                    Get-ACMECertificate | Where-Object Alias -like $CurrentCert.Alias | ForEach-Object {
                        Update-ACMECertificate $_.Alias
                    }
                }
                if ($BackOffSeconds -gt 43200) {
                    Throw "Timed out waiting for certificate"
                }
                Else {
                    Write-Output "Certificate Generation is still pending...Waiting for $BackOffSeconds Seconds"
                    Start-Sleep -Seconds $BackOffSeconds
                }
            }
        }
    }    
    end {
        # Test and Prepare Export Location
        if ($InputObject.count -lt 2) {
            $ExportZone = $InputObject.ChallengeRecordZone
        }
        Else {
            $ExportZone = $InputObject.ChallengeRecordZone[0]
        }
        $ACMEVaultPath = "$((Get-ACMEVaultProfile).VaultParameters.RootPath)"
        if ($OutputPath) {
            $ExportRoot = $OutputPath          
        }
        Else {
            $ExportRoot = "$((Get-ACMEVaultProfile).VaultParameters.RootPath)\certs"
        }
        if (!(Test-Path $ExportRoot)) {
            New-Item -ItemType Directory -Name (Split-Path $ExportRoot -Leaf) -Path (Split-Path $ExportRoot -Parent)
        }
        if (!(Test-Path $ExportRoot)) {
            Write-Warning "Output Path: $ExportRoot does not exist and failed creation!"
            Throw
        }
        if (!(Test-Path "$($ExportRoot)\$($ExportZone)")) {
            New-Item -ItemType Directory -Name "$($ExportZone)" -Path $ExportRoot
        }
        if (!(Test-Path "$($ExportRoot)\$($ExportZone)" )) {
            Write-Warning "Output Path: $($ExportRoot)\$($ExportZone) does not exist and failed creation!"
            Throw
        }
        if (!(Test-Path "$($ExportRoot)\$($ExportZone)\$($AliasSalt)")) {
            New-Item -ItemType Directory -Name $AliasSalt -Path "$($ExportRoot)\$($ExportZone)"
        }
        if (!(Test-Path "$($ExportRoot)\$($ExportZone)\$($AliasSalt)" )) {
            Write-Warning "Output Path: $($ExportRoot)\$($ExportZone)\$($AliasSalt) does not exist and failed creation!"
            Throw
        }
        $ExportPath = "$ExportRoot\$($ExportZone)\$AliasSalt"
        # Export Certificate in vaious formats, one copy in ExportRoot and second copy in subfolder structure by ZoneName\TimeStamp\
        $CertsToExport | ForEach-Object {
            $CurrentCert = $_
            #Export Get-ACMECertificate Object as JSON
            Get-ACMECertificate $CurrentCert.Alias | ConvertTo-Json | Out-File "$ExportPath\$($CurrentCert.IdentifierDns).json"
            Get-ACMECertificate $CurrentCert.Alias | ConvertTo-Json | Out-File "$ExportRoot\$($CurrentCert.IdentifierDns).json" -Force
            #Export Private Key
            Get-ACMECertificate $CurrentCert.Alias -ExportKeyPEM "$ExportPath\$($CurrentCert.IdentifierDns).key.pem"
            Get-ACMECertificate $CurrentCert.Alias -ExportKeyPEM "$ExportRoot\$($CurrentCert.IdentifierDns).key.pem" -Overwrite
            #Export Certificate Request 
            Get-ACMECertificate $CurrentCert.Alias -ExportCsrPEM "$ExportPath\$($CurrentCert.IdentifierDns).csr.pem"
            Get-ACMECertificate $CurrentCert.Alias -ExportCsrPEM "$ExportRoot\$($CurrentCert.IdentifierDns).csr.pem" -Overwrite
            #Export Certificate Issued By LE
            Get-ACMECertificate $CurrentCert.Alias -ExportCertificatePEM "$ExportPath\$($CurrentCert.IdentifierDns).crt.pem" -ExportCertificateDER "$ExportPath\$($CurrentCert.IdentifierDns).crt"
            Get-ACMECertificate $CurrentCert.Alias -ExportCertificatePEM "$ExportRoot\$($CurrentCert.IdentifierDns).crt.pem" -ExportCertificateDER "$ExportRoot\$($CurrentCert.IdentifierDns).crt" -Overwrite
            #Export Issuer Certificate
            Get-ACMECertificate $CurrentCert.Alias -ExportIssuerPEM "$ExportPath\$($CurrentCert.IdentifierDns)-issuer.crt.pem" -ExportIssuerDER "$ExportPath\$($CurrentCert.IdentifierDns)-issuer.crt"
            Get-ACMECertificate $CurrentCert.Alias -ExportIssuerPEM "$ExportRoot\$($CurrentCert.IdentifierDns)-issuer.crt.pem" -ExportIssuerDER "$ExportRoot\$($CurrentCert.IdentifierDns)-issuer.crt" -Overwrite
            #Export PKCS#12 (PFX) Archive
            if ($CertPwd) {
                Get-ACMECertificate $CurrentCert.Alias -ExportPkcs12 "$ExportPath\$($CurrentCert.IdentifierDns).pfx" -CertificatePassword $CertPwd
                Get-ACMECertificate $CurrentCert.Alias -ExportPkcs12 "$ExportRoot\$($CurrentCert.IdentifierDns).pfx" -CertificatePassword $CertPwd -Overwrite
            }
            Else {
                Get-ACMECertificate $CurrentCert.Alias -ExportPkcs12 "$ExportPath\$($CurrentCert.IdentifierDns).pfx"
                Get-ACMECertificate $CurrentCert.Alias -ExportPkcs12 "$ExportRoot\$($CurrentCert.IdentifierDns).pfx" -Overwrite
            }
        }
    }
}
