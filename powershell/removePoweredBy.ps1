# Remove "powered by" header

Import-Module WebAdministration

$Website = "AcmeWeb"
$PSPath =  'MACHINE/WEBROOT/APPHOST/' + $Website

$iis = new-object Microsoft.Web.Administration.ServerManager
$config = $iis.GetWebConfiguration($Website)
$httpProtocolSection = $config.GetSection("system.webServer/httpProtocol")
$headers = $httpProtocolSection.GetCollection("customHeaders")
Clear-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"