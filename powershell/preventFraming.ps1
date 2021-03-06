# Set http response headers to prevent framing

$Website = "AcmeWeb"
$PSPath =  'MACHINE/WEBROOT/APPHOST/' + $Website
  
Remove-WebConfigurationProperty -PSPath $PSPath -Name . -Filter system.webServer/httpProtocol/customHeaders -AtElement @{name =$HeaderName }
             
$iis = new-object Microsoft.Web.Administration.ServerManager
$config = $iis.GetWebConfiguration($WebSiteName) #i.e. "Default Web Site"
$httpProtocolSection = $config.GetSection("system.webServer/httpProtocol")
$headers = $httpProtocolSection.GetCollection("customHeaders")

$addElement = $headers.CreateElement("add")
$addElement["name"] = "X-Frame-Options"  
$addElement["value"] = "SameOrigin"

$customHeadersCollection.Add($addElement)

$iis.CommitChanges() 
write-host $iis