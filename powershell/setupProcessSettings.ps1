Import-Module WebAdministration

$AppPoolName = "AcmeWeb"

if(Test-Path IIS:\AppPools\$AppPoolName)
{
    #$AppPoolName.processModel.identifyType = 'NetworkService'
    #identifyType Options: 
    #LocalSystem: 0
    #LocalService: 1, runs under local service 
    #NetworkService: 2, computer account on the network account
    #SpecificUser: 3, requires specific user and pwd
    #ApplicationPoolIdentity: 4, default identify, account.
    #$AppPoolName.processModel.loadUserProfile = $true, set to fales for IIS compatibility
    
    #Process, in 10min terminate the connection.
    $AppPool.processModel.idleTimeout = '00:10:00'
    $AppPool.processModel.idleTimeoutAction = 'Terminate'

    $AppPool.processModel.maxProcesses = 1

    $AppPool.processModel.pingingEnabled = $true
    $AppPool.processModel.pingInterval = 30
    $AppPool.processModel.pingResponseTime = '00:00:30'

    $AppPool.processModel.startupTimeLimit = '00:00:30'
    $AppPool.processModel.shutdownTimeLimit = '00:00:30'
    $appPool | Set-Item
}
else
{
  Write-Host "Application Pool" $AppPoolName "does not exist"
}