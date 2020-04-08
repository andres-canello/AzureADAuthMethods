# Authentication Methods API

This PowerShell module simplifies managing Authentication Methods for Azure AD users. The module calls the Authentication Methods Graph API endpoints to perform common operations. 
To use this module, please take the following steps.

#   Register an Azure AD application with permissions to call the API .

The Graph authorization model requires that an application must be consented by a user or administrator prior to accessing an organization’s data.  
1.	Log into the Azure portal as a Global Administrator.
2.	Navigate to the Azure AD extension and click on “App registrations” in the Manage section.
3.	Click on “New registration” button at the top of the page.
4.	Provide a name for the application, set the Redirect URI to “Public client/Native”, and type the following as the Redirect URI:
urn:ietf:wg:oauth:2.0:oob
5.	Click “Register”.
6.	When the application is registered, copy the Application (client) ID value, and save the value for later – we will use it in the PS module.
7.	Click on “API permissions” and assign the following permissions:

  Graph API - UserAuthenticationMethod.ReadWrite.All

8.	Under the API Permissions page, click Grant admin consent for… and follow the prompts.

#   Edit PowerShell module

1.	Open AzureADAuthenticationMethods.psm1 and change the following: 
  a.	Replace $tenantDomain with the domain of your tenant
  b.	Replace $clientId with the App ID you created earlier. 
 
#   Using the PowerShell module

1.	Open PowerShell and navigate to the folder where you saved the AzureADAuthenticationMethods.psm1 file.
2.  Run Import-Module .\AzureADAuthenticationMethods.psm1 and authenticate with a user with appropiate permissions
Available commands:

Get-AzureADUserAuthenticationMethod

New-AzureADUserAuthenticationMethod

Set-AzureADUserAuthenticationMethod

Remove-AzureADUserAuthenticationMethod
