Import-Module WebAdministration

$AppPoolName = "AcmeWeb"

if(Test-Path IIS:\AppPools\$AppPoolName)
{
    $appPool = Get-Item IIS:\AppPools\$AppPoolName
    $appPool.cpu.limit = 10000
    $appPool.cpu.action = 'ThrottleUnderLoad'
    # KillW3p, Throttle, ThrottleUnderLoad, NoAction

    $appPool.cpu.resetInterval = '00:01:00'

    # Assign app pool to specific CPU, 
    # Affniity mask spciifies the processor, you can also use multiple processors
    #$AppPoolName.cpu.smpAffinitized = $true  
    #$AppPoolName.cpu.smpProcessorAffinityMask = '0x1'
    #$AppPoolName.cpu.numaNodeAssignment = 'MostAvailableMemory'
    #$AppPoolName.cpu.numaNodeAssignment = 'WindowsScheduling'
    #$AppPoolName.cpu.numaNodeAffinityMode = "soft"  #hard
    $appPool | Set-Item
}
else
{
  Write-Host "Application Pool" $AppPoolName "does not exist"
}

# .cpu.limit = 10000 is 10%, reset everu 1 minute, 5-10minute is good
# after running this script run > iisreset
