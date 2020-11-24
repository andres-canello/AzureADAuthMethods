# Authentication Methods API PS Module

## NOTE: This is not an officially supported Microsoft module. If you are looking for a Microsoft supported module to manage authentication methods check: https://www.powershellgallery.com/packages/Microsoft.Graph.Identity.signins

This is a community supported PowerShell module which simplifies managing Authentication Methods for Azure AD users. The module calls the Authentication Methods Graph API endpoints to perform common operations. Feel free to contribute.

There are two ways to authenticate to your tenant, using a user identity or using an application identity and a certificate. For automation, consider using an application identity and a correctly secured certificate.
Both ways require you to register an application on your tenant.

To use this module, follow these steps on your tenant:


## Register an Azure AD application with permissions to call the API using a user identity

The Graph authorization model requires that an application must be consented by a user or administrator prior to accessing an organization’s data.  
1.	Log into the Azure portal as a Global Administrator.
2.	Navigate to the Azure AD extension and click on “App registrations” in the Manage section.
3.	Click on “New registration” button at the top of the page.
4.	Provide a name for the application, set the Redirect URI to “Public client/Native”, and type the following as the Redirect URI:
urn:ietf:wg:oauth:2.0:oob
5.	Click “Register”.
6.	When the application is registered, copy the Application (client) ID value, and save the value for later.
7.	Click on “API permissions”, then click “Add a permission”
8.	Select “Microsoft Graph”, then click “Delegated permissions” and add the following permission
UserAuthenticationMethod.ReadWrite.All (if your use cases only require read or to interact with the signed in user’s authentication methods, you can choose to use UserAuthenticationMethod.Read.All, UserAuthenticationMethod.Read or UserAuthenticationMethod.ReadWrite)
9.	Under the API Permissions page, click on Grant admin consent for… and follow the prompts.


## Register an Azure AD application with permissions to call the API using an application identity

1.	Log into the Azure portal as a Global Administrator.
2.	Navigate to the Azure AD extension and click on “App registrations” in the Manage section.
3.	Click on “New registration” button at the top of the page.
4.	Provide a name for the application, do not set a Redirect URI.
5.	Click “Register”.
6.	When the application is registered, copy the Application (client) ID value, and save the value for later.
7.	Click on “API permissions”, then click “Add a permission”
8.	 Select “Application permissions” and add the following permission:
UserAuthenticationMethod.ReadWrite.All (if your use cases only require read, you can choose to use UserAuthenticationMethod.Read.All)
9.	Under the API Permissions page, Click on Grant admin consent for… and follow the prompts.

### Follow these steps to create a self signed certificate and associate it with your application.

Your application ObjectId
$appObjectId = ""

#### Create the self signed cert
$currentDate = Get-Date
$endDate = $currentDate.AddYears(1)
$notAfter = $endDate.AddYears(1)
$pwd = "ChooseAPassword"
$thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my -DnsName com.foo.bar -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
$pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
Export-PfxCertificate -cert "cert:\currentuser\my\$thumb" -FilePath c:\temp\examplecert.pfx -Password $pwd

#### Load the certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate("C:\temp\examplecert.pfx", $pwd)
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
#Connect-AzureAD

#### Add the cert credential to your application
New-AzureADApplicationKeyCredential -ObjectId $appObjectId -CustomKeyIdentifier "Test123" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue
Write-Host "Take note of this certificate thumbprint: $thumb"

Remember to take note of the certificate thumbprint.



## Connect to your tenant

### Using a user identity:

Connect-AzureADUserAuthenticationMethod -TenantId your_tenant.onmicrosoft.com -ClientID 'your_app_ClientId' -Thumbprint 'your_certificate_thumbprint'

### Using an application identity:

Connect-AzureADUserAuthenticationMethod -TenantId your_tenant.onmicrosoft.com -ClientID 'your_app_ClientId'



 
##   Using the PowerShell module

Available commands, run Get-Help command for additional info.

Get-AzureADUserAuthenticationMethod

New-AzureADUserAuthenticationMethod

Update-AzureADUserAuthenticationMethod

Remove-AzureADUserAuthenticationMethod

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
