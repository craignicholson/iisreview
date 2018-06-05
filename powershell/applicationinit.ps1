Import-Module WebAdministration
Install-WindowsFeature Web-AppInit

$AppPoolName = 'AcmeWeb'
$SiteName = 'AcmeWeb'

set-itemproperty IIS:\Sites\$SiteName -name applicationDefaults.preloadEnabled -value True

$AppPool = Get-Item IIS:\AppPools\$AppPoolName

$AppPool.startMode = "alwaysrunning"
$AppPool.autoStart = $True

$AppPool.processModel.idleTimeout = [TimeSpan]::FromMinutes(1440)

$AppPool | Set-Item -Verbose