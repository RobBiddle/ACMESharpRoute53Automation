<#
.SYNOPSIS
    ACMESharpRoute53Automation is a PowerShell module which automates the ACMESharp process of obtaining SSL certificates from LetsEncrypt.org https://letsencrypt.org using Amazon AWS Route53 https://aws.amazon.com/route53/ to enable the DNS Domain Validation method
.DESCRIPTION
    --- REQUIRES AWSPowerShell & ACMESharp PowerShell Modules for use!!! ---

    Automates the following into a single process:
    * Accepts Parameter input specifying one of the following:
        * DomainNames - FQDN(s) from one or more Route53 Hosted Zone
        * ZoneNames - DNS zone(s) to query for all ResourceRecordSets in a Route53 Hosted Zone
        * -ALL to query ALL ResourceRecordSets in ALL Route53 Hosted Zones 
    * Registers Domains with LetsEncrypt
    * Requests Domain Validation Challenges
    * Adds/Updates Route53 DNS TXT records with Challenge Response values
    * Verifies DNS resolution of Challenge Response TXT records adhering to Exponential Backoff methodology
    * Submits for Challenge Response Verification
    * Generates one SAN Certificate per DNS Zone, adding all A & CNAME ResourceRecordSets as Subject Alternative Names
    * Waits for Certificate Generation adhering to Exponential Backoff methodology
    * Downloads SSL Certificates in various formats
  
  You will need to have permissions to read Route53 Hosted Zones and write to ResourceRecordSets
    
    This can be accomplished in multiple ways:
    Option 1: Run Get-NewLetsEncryptCertificate under a Windows User Profile which has AWS Credentials for an appropriate AWS IAM User stored via the Get-AWSCredentials cmdlet
        Set-AWSCredentials -AccessKey {AKIAIOSFODNN7EXAMPLE} -SecretKey {wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY} -StoreAs {MyProfileName}

    Option 2: Run Get-NewLetsEncryptCertificate on an EC2 Instance which has an IAM Role assigned with an appropriate IAM Policy.  
      An example of a CloudFormation snippet with such a policy can be found at: https://github.com/RobBiddle/ACMESharpRoute53Automation/Route53.IAM.Policy.snippet.json.template

.EXAMPLE
    Get-NewLetsEncryptCertificate -ALL -Staging -Contacts "me@privacy.net"

    This -ALL Example would generate SSL Certificates via LetsEncrypt for ALL of your Route53 A & CNAME records in ALL of your Route53 Hosted Zones. 
    One SAN Certificate would be generated per zone, containing all of the records for that zone.
    The -Contacts Parameter should be passed an email address, or a list of addresses, for someone responsible for the domains 
    Notice that this example is specifying **-Staging** which is a [Switch] Type Parameter; 
    this will result in the certificates being generated from the LetsEncrypt Staging systems, which is meant for testing and allows for much higher request limits.  
    It is suggested that you use the **-Staging** Switch until you are sure the output certificates are correct.  
    **NOTE:** The LetsEncrypt Staging system will not generate a well known trusted certificates, instead the certificates are issued by "Fake LE Intermediate X1".  
    For more details go here: https://letsencrypt.org/docs/staging-environment/

.EXAMPLE
    Get-NewLetsEncryptCertificate -ZoneNames "fabrikam.net" -Staging -CertPwd "test123" -Contacts "me@privacy.net" -OutputPath c:\temp\
    
    This -ZoneNames Example would generate a single SSL SAN Certificate for fabrikam.net which would include all A & CNAME records in the fabrikam.net DNS zone as Subject Alternative Names.  
    The -CertPwd Parameter is specified which is used to protect the .pfx formatted file.  
    An -OutputPath is specified which determines where the certificate files will be exported, the default location is determined by the ACMESharp Vault which can be found by pasting this into a PowerShell console for the user running the cmdlet "$((Get-ACMEVaultProfile).VaultParameters.RootPath)"

.EXAMPLE
    Get-NewLetsEncryptCertificate -DomainNames "fabrikam.net","contoso.com","www.acme.net","app2.contoso.com" -Contacts "me@privacy.net"
    
    This -DomainNames Example would end up generating 3 SSL Certificates, 1 for fabrikam.net, 1 for www.acme.net, and finally 1 for contoso.com which would be a SAN Certificate containing contoso.com & app2.contoso.com  

.INPUTS
    DomainNames and ZoneNames should be expressed in basic PowerShell array format like this: "domain1.com","domain1.com"
.OUTPUTS
    Certificates will be output in various formats to OutputPath OR "$((Get-ACMEVaultProfile).VaultParameters.RootPath)\certs" by default
    A second copy of files will be output to a subfolder structure by ZoneName\Timestamp\
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
function Get-NewLetsEncryptCertificate {
    [CmdletBinding(
        SupportsShouldProcess = $false,
        PositionalBinding = $false,
        HelpUri = 'https://github.com/RobBiddle/ACMESharpRoute53Automation/',
        ConfirmImpact = 'Medium')]
    [Alias()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param (
        # Get Certificates for ALL 'A' & 'CNAME' Records in ALL Route53 Hosted Zones
        #[Parameter(ParameterSetName = "Staging-ALL")]
        #[Parameter(ParameterSetName = "Production-ALL")]
        [Switch]
        $ALL,

        # Switch to LetEncrypt Staging instead of Production
        # [Parameter(ParameterSetName = "Staging")]
        # [Parameter(ParameterSetName = "Staging-ALL")]
        # [Parameter(ParameterSetName = "Staging-NAME")]
        # [Parameter(ParameterSetName = "Staging-ZONE")]
        [Switch]
        $Staging,

        # DNS Zone Name(s) filter, Certificates will be created for ALL 'A' & 'CNAME' Records in this Route53 Hosted Zone
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        # [Parameter(ParameterSetName = "Production-ZONE")]
        # [Parameter(ParameterSetName = "Staging-ZONE")]
        [String[]]
        $ZoneNames,

        # Domain Name(s) filter.  Only Create Certificates for these FQDNs.  First name will be primary, remaining will be additional hosts in SAN certificate
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false)]
        # [Parameter(ParameterSetName = "Production-NAME")]
        # [Parameter(ParameterSetName = "Staging-NAME")]
        [String[]]
        $DomainNames,

        # Path to Output Certificates
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [String]
        $OutputPath,

        # Password to protect PFX file
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertPwd,

        # Email Address(es) for LetsEncrypt Registration - used for all Domains
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Net.Mail.MailAddress[]]
        $Contacts,

        # ACME Challenge Type (This cmdlet only allows for DNS)
        [ValidateNotNullOrEmpty()]
        [ValidateSet('dns-01')]
        [String]
        $ChallengeType = 'dns-01'
    )
    # Notice
    Write-Output `@"    ACMESharpRoute53Automation  Copyright (C) 2017  Robert D. Biddle
    This program comes with ABSOLUTELY NO WARRANTY; for details type `'help Get-NewLetsEncryptCertificate -full`'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; for details type `'help Get-NewLetsEncryptCertificate -full`'"
    # Dot Source Private Function Files
    $Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )
    $Private | ForEach-Object {
        $FileToImport = $_
        Try {
            .$FileToImport.FullName
        }
        Catch {
            Write-Error -Message "Failed to import: $($FileToImport.FullName): $_"
        }
    }
    if (!$DomainNames -and !$ZoneNames -and !$ALL) {
        Write-Warning "Either a list of -DomainNames, OR a list of -ZoneNames, OR -ALL must be specified"
        Throw "Incorrect Parameters Entered"
    }
    # Get All Route53 RecordSets
    $R53Records = @()
    $R53Records = Get-AllRoute53Records | Where-Object RecordType -eq 'A'
    $R53Records += Get-AllRoute53Records | Where-Object RecordType -eq 'CNAME'
    # Filter out Wildcard Records
    $R53Records = $R53Records | Where-Object RecordName -notlike "`\052*"
    # Filter out Zones if public NS Records are not Route53 NameServers
    $R53RecordsToExclude = @()
    $R53Records | Select-Object ZoneName -Unique | ForEach-Object {
        $CurrentR53Record = $_
        if ( (Resolve-DnsName $CurrentR53Record.ZoneName -Type NS -Server 8.8.8.8).NameHost -notlike "*awsdns*" ) {
            $R53RecordsToExclude += $CurrentR53Record
        }
    }
    $R53Records = $R53Records | Where-Object ZoneName -NotIn $R53RecordsToExclude.ZoneName
    # Determine which records to process
    $HostAndZoneList = @()
    if ($ZoneNames) {
        $NamesToMatch = $ZoneNames
    }
    if ($DomainNames) {
        $NamesToMatch = $DomainNames
    }
    if ($ALL) {
        $NamesToMatch = $R53Records.RecordName
    }
    $NamesToMatch | ForEach-Object {
        $CurrentName = ($_).Trim(".")
        # Parse the ChallengeRecordName to split root zone from hostname
        $splitFQDN = $CurrentName.Split(".")
        $DnsZoneName = "$($splitFQDN[($splitFQDN.count -2)]).$($splitFQDN[($splitFQDN.count -1)])"
        $DnsHost = ''
        $splitFQDN[0 .. ($splitFQDN.count - 3)] | ForEach-Object {
            $DnsHost = -join ("$DnsHost", "$_", ".")
        }
        $DnsHost = "$DnsHost".Trim(".")
        $HostAndZoneList += [PSCustomObject]@{
            HostName = $DnsHost
            FQDN = $CurrentName
            Zone = $DnsZoneName
        }
    }
    $R53RecordsMatchingDomains = @()
    if ($ZoneNames -or $ALL) {
        $HostAndZoneList | Select-Object Zone -Unique | ForEach-Object {
            $CurrentHostOrZone = $_
            $R53RecordsMatchingDomains += $R53Records | Where-Object ZoneName -like "$($CurrentHostOrZone.Zone)."
        }
    }
    if ($DomainNames) {
        $HostAndZoneList | ForEach-Object {
            $CurrentHostOrZone = $_
            $R53RecordsMatchingDomains += $R53Records | Where-Object ZoneName -like "$($CurrentHostOrZone.Zone)." | Where-Object RecordName -like "$($CurrentHostOrZone.FQDN)."
        }      
    }
    $R53RecordsToProcess = @()
    $R53RecordsToProcess = $R53RecordsMatchingDomains
    # Process each Domain Zone and Associated Host Records
    $R53RecordsToProcess | Select-Object ZoneName -Unique  | ForEach-Object {
        Write-Output "Processing Records in Zone: $($_.ZoneName)"
        $CurrentZoneRecords = $R53RecordsToProcess | Where-Object ZoneName -eq $_.ZoneName
        # Build List of Strings for use in DomainNames Parameter
        $RecordNames = @()
        $CurrentZoneRecords | ForEach-Object {
            $RecordNames += ($_.RecordName).Trim(".")
        }
        Write-Output "Processing Hostnames:"
        Write-Output $RecordNames
        # Build Parameter Sets for Functions
        $Params = @{
            DomainNames = $RecordNames
            Contacts = $Contacts
            ChallengeType = $ChallengeType
        }
        if ($Staging) {
            $Params += @{Staging = $true}
        }
        $Requests = Register-LetsEncryptCertificateRequest @Params
        Push-LetsEncryptChallengeToRoute53 -InputObject $Requests
        $Params2 = @{
            InputObject = $Requests
        }
        if ($CertPwd) {
            $Params2 += @{CertPwd = $CertPwd}
        }
        if ($OutputPath) {
            $Params2 += @{OutputPath = $OutputPath}
        }
        Complete-LetsEncryptCertificateRequest @Params2
    }
}
