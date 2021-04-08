# Changelog
## 1.2.2 (2021-04-09)
- Added support for softwareOathMethods

## 1.2.1 (2021-03-10)
- Added support for policy evaluation. Get-AzureADUserAuthenticationMethod user@contoso.com -PolicyEvaluation

## 1.2.0 (sometime ago)
- Added support for Temporary Access Pass

## 1.1.1 (2021-01-19)

- Removed support for deprecated passwordless phone sign in method
- Added support for Expand=Device on WHfB and Microsoft Authenticator via `-ReturnDevices` (requires Device.Read.All permissions)

## 1.0.1 (2021-01-13)

- Connect-AzureADUserAuthenticationMethod - added `-DeviceCode` parameter

## 1.0.0 (2020-10-06)

- Initial Release
