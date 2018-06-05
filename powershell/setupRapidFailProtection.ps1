Import-Module WebAdministration

$AppPoolName = "AcmeWeb"

if(Test-Path IIS:\AppPools\$AppPoolName)
{
   $AppPool.failure.orphanWorkerProcess = $true
   $AppPool.failure.orphanActionExe = 'C:\dbgtools\ntsd.exe'
   $AppPool.failure.orphanActionParams = '-g -p %1%'

   $AppPool.failure.rapidFailProtection = $true
   $AppPool.failure.rapidFailProtectionInterval = 10
   $AppPool.failure.rapidFailProtectionMaxCrashes = 2
   $AppPool.failure.autoShutdownExe = 'C:\some.exe'
   $AppPool.failure.AutoShutdownParams = '-l %1%'

   # signal to load balencer
   $AppPool.failure.loadBalancerCapabilities = 'TcpLevel'

}
else
{
  Write-Host "Application Pool" $AppPoolName "does not exist"
}