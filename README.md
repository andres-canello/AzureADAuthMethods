# Authentication Methods API PS Module

This PowerShell module simplifies managing Authentication Methods for Azure AD users. The module calls the Authentication Methods Graph API endpoints to perform common operations. 
To use this module, please take the following steps.

Latest version: 0.92 - 28 April 2020

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

  Graph API - DELEGATED - UserAuthenticationMethod.ReadWrite.All

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