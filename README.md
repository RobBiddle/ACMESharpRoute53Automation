# ACMESharpRoute53Automation
#### Synopsis
>[ACMESharpRoute53Automation](https://github.com/RobBiddle/ACMESharpRoute53Automation) is a PowerShell module which automates the ACMESharp process of obtaining SSL certificates from [LetsEncrypt.org](https://letsencrypt.org) using Amazon AWS [Route53](https://aws.amazon.com/route53/) to enable the DNS Domain Validation method
#### Description
Upon importing the module, a single PowerShell cmdlet named **Get-NewLetsEncryptCertificate** is exported which makes use of [AWSPowerShell](https://www.powershellgallery.com/packages/AWSPowerShell) & [ACMESharp](https://github.com/ebekker/ACMESharp) 
PowerShell modules to automate the following into a single process:
- Accepts Parameter input specifying one of the following:
  - DomainNames - FQDN(s) from one or more [Route53](https://aws.amazon.com/route53/) Hosted Zone
  - ZoneNames - DNS zone(s) to query for all ResourceRecordSets in a [Route53](https://aws.amazon.com/route53/) Hosted Zone
  - \-ALL to query ALL ResourceRecordSets in ALL [Route53](https://aws.amazon.com/route53/) Hosted Zones 
- Registers Domains with [LetsEncrypt](https://letsencrypt.org)
- Requests Domain Validation Challenges
- Adds/Updates [Route53](https://aws.amazon.com/route53/) DNS TXT records with Challenge Response values
- Verifies DNS resolution of Challenge Response TXT records adhering to Exponential Backoff methodology
- Submits for Challenge Response Verification
- Generates one SAN Certificate per DNS Zone, adding all A & CNAME ResourceRecordSets as Subject Alternative Names
  - Splits large zones into multiple SAN Certificates as needed (100 name limit per cert)
- Waits for Certificate Generation adhering to Exponential Backoff methodology
- Downloads SSL Certificates
- Exports Certificates files

#### Table of Contents
- [Install](#Install)
- [Usage](#Usage)
- [Maintainer\(s\)](#Maintainer)
- [Credits](#Credits)
- [License](#License)
- [Support](#Support)

#### Install <a name="Install"></a>
- ###### Install PowerShell
  - [ACMESharpRoute53Automation](https://github.com/RobBiddle/ACMESharpRoute53Automation) should be compatible with PowerShell 3.0 and higher, howerver I still suggest using the latest verison of [PowerShell](https://aka.ms/wmf5latest) if possible so that you can use PowerShellGet cmdlets
  Download the latest PowerShell here: https://aka.ms/wmf5latest

- ###### Install [ACMESharpRoute53Automation](https://github.com/RobBiddle/ACMESharpRoute53Automation) & Requirements:
  (Assumes you have PowerShellGet and access to PowerShellGallery.com)
  - [ACMESharp](https://github.com/ebekker/ACMESharp) PowerShell Module
    - ```PowerShell
      Install-Module ACMESharp
      ```
  - [AWSPowerShell](https://www.powershellgallery.com/packages/AWSPowerShell) PowerShell Module
    - ```PowerShell
      Install-Module AWSPowerShell
      ```
  - [ACMESharpRoute53Automation](https://github.com/RobBiddle/ACMESharpRoute53Automation) PowerShell Module
    - ```PowerShell
      Install-Module ACMESharpRoute53Automation
      ```

#### Usage <a name="Usage"></a>
###### [Route53](https://aws.amazon.com/route53/) Requirements:
  - You will need to have permissions to read [Route53](https://aws.amazon.com/route53/) Hosted Zones and write to ResourceRecordSets
  - This can be accomplished in multiple ways:
    - Run Get-NewLetsEncryptCertificate under a Windows User Profile which has AWS Credentials for an appropriate AWS IAM User stored via the Get-AWSCredentials cmdlet
      - ```PowerShell
        Set-AWSCredentials -AccessKey {AKIAIOSFODNN7EXAMPLE} -SecretKey {wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY} -StoreAs {MyProfileName}
        ```
    - Run Get-NewLetsEncryptCertificate on an EC2 Instance which has an IAM Role assigned with an appropriate IAM Policy.  An example of a CloudFormation snippet with such a policy can be found at: https://github.com/RobBiddle/ACMESharpRoute53Automation/blob/master/Route53.IAM.Policy.snippet.json.template

###### Import the ACMESharpRoute53Automation module
```PowerShell
Import-Module ACMESharpRoute53Automation
```
<a name="Example"></a>
###### Example: -ALL
This Example would generate SSL Certificates via [LetsEncrypt](https://letsencrypt.org) for ALL of your [Route53](https://aws.amazon.com/route53/) A & CNAME records in ALL of your [Route53](https://aws.amazon.com/route53/) Hosted Zones. One SAN Certificate would be generated per zone, containing all of the records for that zone.

The -Contacts Parameter should be passed an email address, or a list of addresses, for someone responsible for the domains 

Notice that this example is specifying **-Staging** which is a [Switch] Type Parameter; this will result in the certificates being generated from the [LetsEncrypt](https://letsencrypt.org) Staging systems, which is meant for testing and allows for much higher request limits.  It is suggested that you use the **-Staging** Switch until you are sure the output certificates are correct.  **NOTE:** The [LetsEncrypt](https://letsencrypt.org) Staging system will not generate a well known trusted certificates, instead the certificates are issued by "Fake LE Intermediate X1".  For more details go here: https://letsencrypt.org/docs/staging-environment/
```PowerShell
Get-NewLetsEncryptCertificate -ALL -Staging -Contacts "me@privacy.net"
```

###### Example: -ZoneNames
This Example would generate a single SSL SAN Certificate for fabrikam.net which would include all A & CNAME records in the fabrikam.net DNS zone as Subject Alternative Names.  The -CertPwd Parameter is specified which is used to protect the .pfx formatted file.  An -OutputPath is specified which determines where the certificate files will be exported, the default location is determined by the ACMESharp Vault which can be found by pasting this into a PowerShell console for the user running the cmdlet "$((Get-ACMEVaultProfile).VaultParameters.RootPath)"
```PowerShell
Get-NewLetsEncryptCertificate -ZoneNames "fabrikam.net" -Staging -CertPwd "test123" -Contacts "me@privacy.net" -OutputPath c:\temp\
```

###### Example: -DomainNames
This Example would end up generating 3 SSL Certificates, 1 for fabrikam.net, 1 for www.acme.net, and finally 1 for contoso.com which would be a SAN Certificate containing contoso.com & app2.contoso.com  
```PowerShell
Get-NewLetsEncryptCertificate -DomainNames "fabrikam.net","contoso.com","www.acme.net","app2.contoso.com" -Contacts "me@privacy.net"
```

#### Maintainer(s) <a name="Maintainer"></a>
[Robert D. Biddle](https://github.com/RobBiddle) - https://github.com/RobBiddle

#### Contributing <a name="Contributing"></a>

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

#### Credits <a name="Credits"></a>
- Mad Props to [@ebekker](https://github.com/ebekker) for creating [ACMESharp](https://github.com/ebekker/ACMESharp) upon which this project **heavily** relies
- The [AWSPowerShell](https://www.powershellgallery.com/packages/AWSPowerShell) Devs for supporting all of us PowerShell users
- [LetsEncrypt](https://letsencrypt.org) Devs & Supporters for making SSL **Free** (As in :beer:) and accessible to everyone
- [Upic Solutions](https://upicsolutions.org/) for sponsoring my time to develop this project.  This code is being used as part of our mission to help United Ways be the best community solution leaders, in an increasingly competitive environment, by providing state of the art business and technology solutions.

#### License <a name="License"></a>

GNU General Public License v3.0
https://github.com/RobBiddle/ACMESharpRoute53Automation/LICENSE.txt

##### Support <a name="Support"></a>
- Please Star this repo if you found some of this code useful!
- If you're an unbelievably nice person and want to show your appreciation, I like beer :beer: ;-)
  - Send me beer money via LTC: MHJj5jaWFU2VeqEZXnLC4xaZdQ1Nu9NC48
  - Send me beer money via BTC: 38ieXk9rn2LJEsfimFWiyycUZZv5ABJPqM
  - Send me beer money via USD: https://paypal.me/RobertBiddle
