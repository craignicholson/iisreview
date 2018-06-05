Import-Module WebAdministration

$AppPoolName = "AcmeWeb"

if(Test-Path IIS:\AppPools\$AppPoolName)
{
    $AppPoolName.recycling.disallowOverlappingApplication = $true
    #$AppPool.recycling.periodicRestart.privateMemory = 120
    #$AppPool.recycling.periodicRestart.memory = 120
    #$AppPool.recycling.periodicRestart.requests = 2000
    #$AppPool.recycling.periodicRestart.time = '2:00:00'
    #$appPool | Set-Item

    #Set-ItemProperty IIS:\AppPools\$AppPoolName -Name recycling.periodicRestart.schedule `
    #-Value @{value="01:00:00"}

    #New-ItemProperty IIS:\AppPools\$AppPoolName -Name recycling.periodicRestart.schedule `
    #-Value @{value="02:00:00"}

    #$appPool.recycling.logEventOnRecycle = "Time, Memory, ConfigChange, PrivateMemory"
    #$appPool | Set-Item
}
else
{
  Write-Host "Application Pool" $AppPoolName "does not exist"
}