# Graph Token to use for queries
$script:msgraphToken = $null

# The API base URI to use for requests
$script:baseUri = 'https://graph.microsoft.com/beta/'

# Certificate used for authenticating inapplication authentication workflows
$script:clientCertificate = $null

# Connection Metadata
$script:tenantID = ''
$script:clientID = ''
$script:redirectUri = 'urn:ietf:wg:oauth:2.0:oob'