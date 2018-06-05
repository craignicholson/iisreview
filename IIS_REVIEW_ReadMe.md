# IIS Review

## Plan

Install IIS8
Create Application Pool
Delete Default Web Site
Run this PS script which add sites
- Site Name & Default App Pool

### Add Site

Create DNS entry on DNS server

Define HostNames for all sites

Sitename: site1.com
Type: http
IP Address: All Unassigned
Port: 80
Host Name: site1.com
Bindings > Edit Bindings -> Add Additional Binding:  www.site1.com
Check - Start Web Site Immediately

Add Site
Sitename: site2.com
Type: http
IP Address: All Unassigned
Port: 80
Host Name: site2.com
Bindings > Edit Bindings -> Add Additional Site Bindings:  www.site2.com
Check - Start Web Site Immediately

### Add site with SSL

Click the Root of the Server, right above application pools

Click Create Self Signed Certificate
Specify a friendly name for the certificate: site1.com


Add SSL Binding to Site1.com
Bindings > Add Bindngs
Type: https
IP Address: All Unassigned
Port: 443
SSL Certificate: site.com

Browser complains
- Checks if date is range of the cert.
- was cert created by trusted cert authorities
- does the host name match what is in the cert

Wild Card Cerfifcate
use make cert aprt of windows sdk
https://msdn.microsoft.com/en-us/library/bfsktky3(VS.100).aspx
Review and test

So now...
Add SSL Binding to beta.Site1.com
Bindings > Add Bindngs
Type: https
IP Address: All Unassigned
Port: 443
Host Name: beta.site2.com
SSL Certificate: *.site.com

ElectSolve Sites

Wild Card Certificate *.ucentra.com
- ucentra.com -> Landing Page 
- appname.ucentra.com

to make it trusted

mmc > add certificate snap in . computer account >local computer
personal certificates.. it's issued to local host...
copy into Trusted Root Certificate Folder

No more warning...

IIS8
Application Initialzation Mode
 warm it up
SNI Support
 support multiple ssl certs on same IP
 ssl management

Note, sometimes development needs setting in web.config
But in production tohose setttings are more for development
For this scenario we need to add those settings to the IIS Settings instead.

Application Pools
Typically you want one application pool for site...
When you create each site you get an application site and it's own pool created.

Advanced settings
Enabled 32-Bit Applications: False [64 bit is better, memory and speed]
  do we have any 3rd party legacy comp. in 32 bit
Process Model:  ApplicationPoolIdentity
Idle Time-out (minutes): 0 for production and testing, 20min for dev
Ping Enabled: True

Recycling
Regular Time Interval (minutes): 1740

if any data is stored in session state and app pool recycles you will
lost all that information.  Poor user experience

We might need to to set a re-cycle time for 23:00 (11PM) and 430AM.

Set Multiple Sites to one Application Pool
Eliminate multiple app pools to save resources... MB's

Dis-advantage of combining app pools is if one app pool has a problem
then all sites using that app pool will have same problem and bring all sites down.

So if App Pool Greenv4 recycles, it affects all sites instead of the one site.

INSTALL Failed Request Module
Health and Dig
 Tracing
  
Open Site
    Failed Request Tracing

    All Content(*)
    

    Don't leave this one.  Turn on find issues and Turn on.

    Status Code 400-999
    Time Taken:  might be good for our slow poke sites

    Set max number of trace files to keep...

## Log Parser 

Search on folder..

SELECT TOP  * FROM C:\inetpub\logs\logfiles\W3SVC1\*.log

Plan or shipping the IIS log files....
- FTP them - Shade Tree route, use Log Parser
- Send to cloud provider - Easier route.. has everyting costs per month

 Middle ground... Our own Elastic Server at Colo.  Has files colelcted  from sftp site, and load into the server.

## Powershell tips

PS C:\Windows\system32> import-module webadministration
PS C:\Windows\system32> cd iis:\\
PS IIS:\> dir

Name
----
AppPools
Sites
SslBindings


PS IIS:\> cd .\AppPools\
PS IIS:\AppPools\> dir

Name                     State        Applications
----                     -----        ------------
.NET v4.5                Started
.NET v4.5 Classic        Started
DefaultAppPool           Started
GreenV4                  Started      Green
                                      /MDMPortal
                                      /MDMServices
                                      /MDMImportExport
                                      /MDMMessaging
                                      /MDMCharts
                                      /AccountWebAPI
                                      /MDMWebAPI
                                      /MessagePublisher
                                      /Dashboard
                                      /DataAnalysis
                                      /MDMVEE
                                      /GIS
                                      /CIMService
                                      /MDMMeterExchange
                                      /MultiSpeak30AC
                                      /MultiSpeak416
                                      /MultiSpeakBroker
                                      /TransformerLoadAnalysis
                                      /TransformerLoadAnalysisWebAPI
                                      /VirtualMeter
                                      /VirtualMeterWebAPI
                                      /UserAdmin
                                      /LARS
                                      /MeterExchange
                                      /PowerBilling
                                      /EsriDashboard
                                      /EventManagement
                                      /EventAnalysisWebAPI
                                      /Charts
                                      /VoltageAnalysis
                                      /VoltageAnalysisApi


PS IIS:\AppPools\> cd ..
PS IIS:\> cd .\Sites\
PS IIS:\Sites\> ls

Name             ID   State      Physical Path                  Bindings
----             --   -----      -------------                  --------
Green            1    Started    J:\ElectSolve\Green\LandingPag http *:80:
                                 e


PS IIS:\Sites\> dir

Name             ID   State      Physical Path                  Bindings
----             --   -----      -------------                  --------
Green            1    Started    J:\ElectSolve\Green\LandingPag http *:80:
                                 e


PS IIS:\Sites\> cd .\Green\
PS IIS:\Sites\Green\> ls

Type               Name                             Physical Path
----               ----                             -------------
application        AccountWebAPI                    J:\ElectSolve\Green\AccountWebAPI
directory          bin                              J:\ElectSolve\Green\LandingPage\bin
application        Charts                           J:\ElectSolve\Green\Charts
application        CIMService                       J:\ElectSolve\Green\CIMService
directory          Content                          J:\ElectSolve\Green\LandingPage\Content
application        Dashboard                        J:\ElectSolve\Green\Dashboard
application        DataAnalysis                     J:\ElectSolve\Green\DataAnalysis
application        EsriDashboard                    J:\ElectSolve\Green\EsriDashboard
application        EventAnalysisWebAPI              J:\ElectSolve\Green\EventAnalysis
application        EventManagement                  J:\ElectSolve\Green\EventManagement
directory          fonts                            J:\ElectSolve\Green\LandingPage\fonts
application        GIS                              J:\ElectSolve\Green\GIS
file               Global.asax                      J:\ElectSolve\Green\LandingPage\Global.asax
file               icon.png                         J:\ElectSolve\Green\LandingPage\icon.png
application        LARS                             J:\ElectSolve\Green\LARS
directory          logs                             J:\ElectSolve\Green\LandingPage\logs
application        MDMCharts                        J:\ElectSolve\Green\Charts
application        MDMImportExport                  J:\ElectSolve\Green\ImportExport
application        MDMMessaging                     J:\ElectSolve\Green\Messaging
application        MDMMeterExchange                 J:\ElectSolve\Green\MDMMeterExchange
application        MDMPortal                        J:\ElectSolve\Green\CSRPortal
application        MDMServices                      J:\ElectSolve\Green\MDMServices
application        MDMVEE                           J:\ElectSolve\Green\VEE
application        MDMWebAPI                        J:\ElectSolve\Green\MDMWebAPI
application        MessagePublisher                 J:\ElectSolve\Green\MessagePublisher
application        MeterExchange                    J:\ElectSolve\Green\MeterExchange
application        MultiSpeak30AC                   J:\ElectSolve\Green\MultiSpeak30AC
application        MultiSpeak416                    J:\ElectSolve\Green\MultiSpeak416
application        MultiSpeakBroker                 J:\ElectSolve\Green\MultiSpeakBroker
file               packages.config                  J:\ElectSolve\Green\LandingPage\packages.config
application        PowerBilling                     J:\ElectSolve\Green\PowerBilling
directory          Scripts                          J:\ElectSolve\Green\LandingPage\Scripts
application        TransformerLoadAnalysis          J:\ElectSolve\Green\TransformerLoadAnalysis
application        TransformerLoadAnalysisWebAPI    J:\ElectSolve\Green\TransformerLoadAnalysisWebAPI
application        UserAdmin                        J:\ElectSolve\Green\UserAdmin
directory          Views                            J:\ElectSolve\Green\LandingPage\Views
application        VirtualMeter                     J:\ElectSolve\Green\VirtualMeter
application        VirtualMeterWebAPI               J:\ElectSolve\Green\VirtualMeterWebAPI
application        VoltageAnalysis                  J:\ElectSolve\Green\VoltageAnalysis
application        VoltageAnalysisApi               J:\ElectSolve\Green\VoltageAnalysisAPI
file               Web.config                       J:\ElectSolve\Green\LandingPage\Web.config
file               Web.connections.config           J:\ElectSolve\Green\LandingPage\Web.connections.config
file               Web.Debug.config                 J:\ElectSolve\Green\LandingPage\Web.Debug.config
file               Web.Release.config               J:\ElectSolve\Green\LandingPage\Web.Release.config

Example to Create the sites
```powershell

cd iis:\\
New-Item iis:\Sites\ucentra.com -bindings @{protocol="http";bindinginformation="*.80:ucentra.com"} -physicalPath J:\ElectSolve\Green\ucentra.com

New-ItemProperty iis:\Sites\ucentra.com -name bindings -value @{protocol="http";bindinginformation="*.80:www.ucentra.com"} 
```

# WebDeploy Examples

Install Web Deploy
Source <-> Destination
Push sites from one server to another ....
Skip the ftp crap

Blue - Green stuff

C:\program Files\IIS\Microsoft Web Deploy> msdeploy -verb:sync -source:webServer -dest:webServer, computerName=etss-appdev -username= adminstiration, password='lkjasdlkfjdlkjflkdj

Run it 2x might fail on first push of the config

URL Rewrite
have links have www or not to have www



## NLTM 

https://support.microsoft.com/en-us/help/896861/you-receive-error-401-1-when-you-browse-a-web-site-that-uses-integrate

Loopback is this an issue???

## Demo Server
2.4  GHZ, what's typical CPU look like during use
8GB memeory, what's the memory lool like during use

## Reviewing IIS log files

Fast Way

## IIS 8 New Features

https://support.citrix.com/article/CTX221693
http://www.hanselman.com/blog/AnalyzeYourWebServerDataAndBeEmpoweredWithLogParserAndLogParserLizardGUI.aspx

New Built-in module "Application Initialization". It is often misunderstood how it works and that it also require an additional setting on the website instance to perform the "warm up" webadmins so often want.

Install it First
http://www.herlitz.nu/2017/11/07/enable-IIS-preloadEnabled-and-AlwaysRunning-using-PowerShell/

```powershell
$webAppInit = Get-WindowsFeature -Name "Web-AppInit"
Install-WindowsFeature $webAppInit -ErrorAction Stop
```

```powershell
import-module webadministration
Set-ItemProperty "IIS:\Sites\Green\AccountWebApi" -Name applicationDefaults.preloadEnabled -Value True
```

```bash

time wget -pq --no-cache --delete-after http://10.86.1.191
time wget -pq --no-cache --delete-after http://10.86.1.191/AccountWebAPI
time wget -pq --no-cache --delete-after http://10.86.1.191/Charts
time wget -pq --no-cache --delete-after http://10.86.1.191/CimService
time wget -pq --no-cache --delete-after http://10.86.1.191/Dashboard
time wget -pq --no-cache --delete-after http://10.86.1.191/DataAnalysis
time wget -pq --no-cache --delete-after http://10.86.1.191/EsriDashboard
time wget -pq --no-cache --delete-after http://10.86.1.191/EventAnalysisWebAPI
time wget -pq --no-cache --delete-after http://10.86.1.191/EventManagement
time wget -pq --no-cache --delete-after http://10.86.1.191/GIS
time wget -pq --no-cache --delete-after http://10.86.1.191/LARS
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMCharts
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMImportExport
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMMessaging
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMMeterExchange
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMPortal
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMServices
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMVEE
time wget -pq --no-cache --delete-after http://10.86.1.191/MDMWebAPI
time wget -pq --no-cache --delete-after http://10.86.1.191/MessagePublisher
time wget -pq --no-cache --delete-after http://10.86.1.191/MeterExchange
time wget -pq --no-cache --delete-after http://10.86.1.191/MultiSpeak30AC
time wget -pq --no-cache --delete-after http://10.86.1.191/MultiSpeak416
time wget -pq --no-cache --delete-after http://10.86.1.191/MultiSpeakBroker
time wget -pq --no-cache --delete-after http://10.86.1.191/PowerBilling
time wget -pq --no-cache --delete-after http://10.86.1.191/TransformerLoadAnalysis
time wget -pq --no-cache --delete-after http://10.86.1.191/TransformerLoadAnalysisWebAPI
time wget -pq --no-cache --delete-after http://10.86.1.191/UserAdmin
time wget -pq --no-cache --delete-after http://10.86.1.191/VirtualMeter
time wget -pq --no-cache --delete-after http://10.86.1.191/VirtalMeterWebAPI
time wget -pq --no-cache --delete-after http://10.86.1.191/VoltageAnalysis
time wget -pq --no-cache --delete-after http://10.86.1.191/VoltageAnalysisWebApi

```

## Application Pool

Name: GreenV4
Advanced Settings

- General-Start Mode: Always Running
- Process-Model-Idle-Time-Out: 0
- Recycling-Regular Time Interval (minutes): 1740 (Hmm 1440 is 24 hours, 1740 is 29 hours).  0 is never recycle.

[startMode] Configures Application Pool to run 'On Demand Mode' or 'Always Running Mode'

[idleTimeout] Amount of time in (minutes) a worker process will remain idle before it shuts down.
A worker process is idle if it is not processing requests and no new requests are received.

[time] Period of time (in minutes) after which an application pool will recycle.  A value of 0 means the application
pool does not recyle on a regular interval.

## Individual Sites Settings

Example:

Manage Application > Advanced Settings
General-Preload Enabled: True

## API Warming

- MultiSpeak
- Rest APIs
- All other APIs

## Issues Found

- Since we have LandingPage site as root, and has it's own web.config, any web.configs in sites under the root should not have the same web.config appsetting.

Example:
LandingPage
  <appSettings>
    <add key="Instance" value="Version 3.0.2.1 - Rev 345fd3" />
    <add key="BuildDate" value="01-16-2018" />
    <add key="SiteName" value="uCentra - Meter Data Management" />
    <add key="webpages:Version" value="3.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="PreserveLoginUrl" value="true" />
    <add key="c" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  </appSettings>

Site also unders the Green where Landing Page is root.

  <appSettings file="J:\ElectSolve\Green\Config\TLA.config">
    <add key="Instance" value="Build 8 - Rev 2cd342" />
    <add key="BuildDate" value="02-20-2018" />
    <add key="webpages:Version" value="2.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="PreserveLoginUrl" value="true" />
    <add key="ClientValidationEnabled" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
    <add key="MvcSiteMapProvider_IncludeAssembliesForScan" value="TransformerLoadAnalysis" />
    <add key="MvcSiteMapProvider_UseExternalDIContainer" value="false" />
    <add key="MvcSiteMapProvider_ScanAssembliesForSiteMapNodes" value="true" />
    <add key="MvcSiteMapProvider_SecurityTrimmingEnabled" value="true" />
  </appSettings>

Note we have duplicate Keys, a sample is listed below:

- Instance
- BuildDate
- webpages:version
- webpages:enabled
- ClientValidationEnabled
- UnobtrusiveJavaScriptEnabled

The fix is to move LandingPage to it's own application.
Then we can just redirect Localhost to Localhost/LandingPage
What does this mean for windows auth?
What does this mean for forms auth? Did we ever fix the issue of having to log in again from asp.net to mvc apps?

## Tuning for Performance

Application Initialization

Slow == application pool goes idle

websiteTest.ps1

```powershell
$url = 'http://etss-demo-app.etss.com/VoltageAnalysis'
$timeTaken = Measure-Command -Expression {
  $site = Invoke-WebRequest -Uri $url
}

$seconds = [Math]::Round($timeTaken.TotalSeconds,4)

"The page took $seconds seconds to load"
```

application_init.ps1

```powershell

Import-Module WebAdministration
Install-WindowsFeature Web-AppInit

$AppPoolName = 'GreenV4'
$SiteName = '\Green'

Set-ItemProperty IIS:\Sites\$SiteName -name applicationDefaults.preloadEnabled -Value True

$AppPool = Get-Item  IIS:\AppPools\$AppPoolName
$AppPool.startMode = "alwaysrunning"
$AppPool.autoStart = $True

$AppPool.processModel.idleTimeout = [TimeSpan]::FromMinutes(1440)

$AppPool | Set-Item -Verbose
```

Windows Command Prompt with Admin Privledges

```shell

> net stop w3svc & net start w3svc

```

## Using Configs

```powershell
> Install-WindowsFeature Web-AppInit

> iisreset
```

C:\Windows\System32\inetsrv\config\applicationhost.config

```xml
...
  <applicationPools>
    <add name="GreenV4" startMode="AlwaysRunning" managedRuntimeVersion="v4.5">
  </applicationPools>
<?xml version="1.0" encoding="UTF-8"?>
<!--

    IIS configuration sections.

    For schema documentation, see
    %windir%\system32\inetsrv\config\schema\IIS_schema.xml.
    
    Please make a backup of this file before making any changes to it.

-->

<configuration>

    <!--

        The <configSections> section controls the registration of sections.
        Section is the basic unit of deployment, locking, searching and
        containment for configuration settings.
        
        Every section belongs to one section group.
        A section group is a container of logically-related sections.
        
        Sections cannot be nested.
        Section groups may be nested.
        
        <section
            name=""  [Required, Collection Key] [XML name of the section]
            allowDefinition="Everywhere" [MachineOnly|MachineToApplication|AppHostOnly|Everywhere] [Level where it can be set]
            overrideModeDefault="Allow"  [Allow|Deny] [Default delegation mode]
            allowLocation="true"  [true|false] [Allowed in location tags]
        />
        
        The recommended way to unlock sections is by using a location tag:
        <location path="Default Web Site" overrideMode="Allow">
            <system.webServer>
                <asp />
            </system.webServer>
        </location>

    -->
    <configSections>
        <sectionGroup name="system.applicationHost">
            <section name="applicationPools" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="configHistory" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="customMetadata" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="listenerAdapters" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="log" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="serviceAutoStartProviders" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="sites" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="webLimits" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
        </sectionGroup>

        <sectionGroup name="system.webServer">
            <section name="asp" overrideModeDefault="Deny" />
            <section name="caching" overrideModeDefault="Allow" />
            <section name="cgi" overrideModeDefault="Deny" />
            <section name="defaultDocument" overrideModeDefault="Allow" />
            <section name="directoryBrowse" overrideModeDefault="Allow" />
            <section name="fastCgi" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="globalModules" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="handlers" overrideModeDefault="Deny" />
            <section name="httpCompression" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="httpErrors" overrideModeDefault="Allow" />
            <section name="httpLogging" overrideModeDefault="Deny" />
            <section name="httpProtocol" overrideModeDefault="Allow" />
            <section name="httpRedirect" overrideModeDefault="Allow" />
            <section name="httpTracing" overrideModeDefault="Deny" />
            <section name="isapiFilters" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="modules" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="applicationInitialization" allowDefinition="MachineToApplication" overrideModeDefault="Allow" />
            <section name="odbcLogging" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="access" overrideModeDefault="Deny" />
                <section name="applicationDependencies" overrideModeDefault="Deny" />
                <sectionGroup name="authentication">
                    <section name="anonymousAuthentication" overrideModeDefault="Deny" />
                    <section name="basicAuthentication" overrideModeDefault="Deny" />
                    <section name="clientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="digestAuthentication" overrideModeDefault="Deny" />
                    <section name="iisClientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="windowsAuthentication" overrideModeDefault="Deny" />
                </sectionGroup>
                <section name="authorization" overrideModeDefault="Allow" />
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="dynamicIpSecurity" overrideModeDefault="Deny" />
                <section name="isapiCgiRestriction" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Allow" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" />
            <section name="serverSideInclude" overrideModeDefault="Deny" />
            <section name="staticContent" overrideModeDefault="Allow" />
            <sectionGroup name="tracing">
                <section name="traceFailedRequests" overrideModeDefault="Allow" />
                <section name="traceProviderDefinitions" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="urlCompression" overrideModeDefault="Allow" />
            <section name="validation" overrideModeDefault="Allow" />
            <sectionGroup name="webdav">
                <section name="globalSettings" overrideModeDefault="Deny" />
                <section name="authoring" overrideModeDefault="Deny" />
                <section name="authoringRules" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="webSocket" overrideModeDefault="Deny" />
        </sectionGroup>
        <sectionGroup name="system.ftpServer">
            <section name="log" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="firewallSupport" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="caching" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="providerDefinitions" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Deny" />
                <section name="authorization" overrideModeDefault="Deny" />
                <section name="authentication" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
        </sectionGroup>
    </configSections>

    <configProtectedData>
        <providers>
            <add name="IISWASOnlyRsaProvider" type="" description="Uses RsaCryptoServiceProvider to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useMachineContainer="true" useOAEP="false" />
            <add name="AesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisConfigurationKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAA0/jqVAi7umP7Z/qxUvM/9rUmAb5yZlFGzyKOQrbNFQDO0FSAXxliblplztmVdqQBSMRvIOmLqta6Qu3omq+QCFaKwslCghsXLuMCFfU0mjuDt/tomqNkhzXUH8+xZGDz54oMeEJsmFy6RJb/FhFfPyOTB+bWEVr9kKElWhQYRJ59NdHC3G6gyR73TOyeCMxrkP1XwDaz39cIMrzthuWk+dSny+u8N96kcf2dqAN9Ie5yzytqlPTYPtk4xoMaOdh/jcVkcQn6OQFKaBK1vcbUJJCfBsVF+6p4k64wHDcNhBYyHBNISNJu4dRBEb55sHuOywVMuTznEJB8vVY5X7INZg==" />
            <add name="IISWASOnlyAesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAAaVkcy4djla2i6VV4fge4riralQXCsPJoDc5kisaE1RbZnTk6rBy0dSU5jYgN+x/RCCi4BopuRWZDAmoKiEVpbJnR2hAZFkhtEq/Of0Bqw0KVbjxTrj4QOl7Wc7qdzcsSN6yzwfnuG4g79cNoLaEhACemhtUlWnSPVHqMYdAqA6FQqQMTVJGMd30AMIBYsh0+Qgjupo78W7CT2JlpbBO0zEiAB8Mu/YiQnco98gZfyPvw4+XWbrjNNrS3co6iNndd/TS9uelMO1QRBdO0esiE/2eqdWYiC2PHXc5+YvqSsPi4vQIneMZWpPRceR/s0i6iJLxB+VdDAwRC0Ng/nF/+NA==" />
        </providers>
    </configProtectedData>

    <system.applicationHost>

        <applicationPools>
            <add name="DefaultAppPool" />
            <add name=".NET v4.5 Classic" managedRuntimeVersion="v4.0" managedPipelineMode="Classic" />
            <add name=".NET v4.5" managedRuntimeVersion="v4.0" />
            <add name="GreenV4" enable32BitAppOnWin64="true" startMode="AlwaysRunning">
                <processModel identityType="NetworkService" idleTimeout="1.00:00:00" />
            </add>
            <applicationPoolDefaults managedRuntimeVersion="v4.0">
                <processModel identityType="ApplicationPoolIdentity" />
            </applicationPoolDefaults>
        </applicationPools>

        <!--

          The <customMetadata> section is used internally by the Admin Base Objects
          (ABO) Compatibility component. Please do not modify its content.

        -->
        <customMetadata>
            <key path="LM/W3SVC/INFO">
                <property id="4012" dataType="String" userType="1" attributes="Inherit" value="NCSA Common Log File Format,Microsoft IIS Log File Format,W3C Extended Log File Format,ODBC Logging" />
                <property id="2120" dataType="MultiSZ" userType="1" attributes="None" value="400,0,,,0&#xA;" />
            </key>
        </customMetadata>

        <!--

          The <listenerAdapters> section defines the protocols with which the
          Windows Process Activation Service (WAS) binds.

        -->
        <listenerAdapters>
            <add name="http" />
        </listenerAdapters>

        <log>
            <centralBinaryLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
            <centralW3CLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
        </log>

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>

    <applicationInitialization>
      <add initializationPage="/VoltageAnalysis" />
    </applicationInitialization>

    <urlCompression doStaticCompression="true" doDynamicCompression="true" />

    <httpProtocol allowKeepAlive="true">
      <customerHeaders>
        <add name="Cache-Control" value="max-age=604800, private, public /">
      </customerHeaders>
    </httpProtocol>

    <staticContent>
      <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="7.00:00:00">
    </staticContent>

  </system.webServer>
</configuration>
                <application path="/MDMPortal" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\CSRPortal" />
                </application>
                <application path="/MDMServices" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MDMServices" />
                </application>
                <application path="/MDMImportExport" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\ImportExport" />
                </application>
                <application path="/MDMMessaging" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\Messaging" />
                </application>
                <application path="/MDMCharts" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\Charts" />
                </application>
                <application path="/AccountWebAPI" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\AccountWebAPI" />
                </application>
                <application path="/MDMWebAPI" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MDMWebAPI" />
                </application>
                <application path="/MessagePublisher" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MessagePublisher" />
                </application>
                <application path="/Dashboard" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\Dashboard" />
                </application>
                <application path="/DataAnalysis" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\DataAnalysis" />
                </application>
                <application path="/MDMVEE" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\VEE" />
                </application>
                <application path="/GIS" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\GIS" />
                </application>
                <application path="/CIMService" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\CIMService" />
                </application>
                <application path="/MDMMeterExchange" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MDMMeterExchange" />
                </application>
                <application path="/MultiSpeak30AC" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MultiSpeak30AC" />
                </application>
                <application path="/MultiSpeak416" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MultiSpeak416" />
                </application>
                <application path="/MultiSpeakBroker" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MultiSpeakBroker" />
                </application>
                <application path="/TransformerLoadAnalysis" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\TransformerLoadAnalysis" />
                </application>
                <application path="/TransformerLoadAnalysisWebAPI" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\TransformerLoadAnalysisWebAPI" />
                </application>
                <application path="/VirtualMeter" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\VirtualMeter" />
                </application>
                <application path="/VirtualMeterWebAPI" applicationPool="GreenV4">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\VirtualMeterWebAPI" />
                </application>
                <application path="/UserAdmin" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\UserAdmin" />
                </application>
                <application path="/LARS" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\LARS" />
                </application>
                <application path="/MeterExchange" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\MeterExchange" />
                </application>
                <application path="/PowerBilling" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\PowerBilling" />
                </application>
                <application path="/EsriDashboard" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\EsriDashboard" />
                </application>
                <application path="/EventManagement" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\EventManagement" />
                </application>
                <application path="/EventAnalysisWebAPI" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\EventAnalysis" />
                </application>
                <application path="/Charts" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\Charts" />
                </application>
                <application path="/VoltageAnalysis" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\VoltageAnalysis" />
                </application>
                <application path="/VoltageAnalysisApi" applicationPool="GreenV4" preloadEnabled="true">
                    <virtualDirectory path="/" physicalPath="J:\ElectSolve\Green\VoltageAnalysisApi" />
                </application>
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
                <applicationDefaults preloadEnabled="true" />
            </site>
            <siteDefaults>
                <logFile logFormat="W3C" directory="%SystemDrive%\inetpub\logs\LogFiles" />
                <traceFailedRequestsLogging directory="%SystemDrive%\inetpub\logs\FailedReqLogFiles" />
            </siteDefaults>
            <applicationDefaults applicationPool="DefaultAppPool" />
            <virtualDirectoryDefaults allowSubDirConfig="true" />
        </sites>

        <webLimits />

    </system.applicationHost>

    <system.webServer>

        <asp />

        <caching enabled="true" enableKernelCache="true">
        </caching>

        <cgi />

        <defaultDocument enabled="true">
            <files>
                <add value="Default.htm" />
                <add value="Default.asp" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
                <add value="default.aspx" />
            </files>
        </defaultDocument>

        <directoryBrowse enabled="false" />

        <fastCgi />

        <!--

          The <globalModules> section defines all native-code modules.
          To enable a module, specify it in the <modules> section.

        -->
        <globalModules>
            <add name="UriCacheModule" image="%windir%\System32\inetsrv\cachuri.dll" />
            <add name="FileCacheModule" image="%windir%\System32\inetsrv\cachfile.dll" />
            <add name="TokenCacheModule" image="%windir%\System32\inetsrv\cachtokn.dll" />
            <add name="HttpCacheModule" image="%windir%\System32\inetsrv\cachhttp.dll" />
            <add name="StaticCompressionModule" image="%windir%\System32\inetsrv\compstat.dll" />
            <add name="DefaultDocumentModule" image="%windir%\System32\inetsrv\defdoc.dll" />
            <add name="DirectoryListingModule" image="%windir%\System32\inetsrv\dirlist.dll" />
            <add name="ProtocolSupportModule" image="%windir%\System32\inetsrv\protsup.dll" />
            <add name="StaticFileModule" image="%windir%\System32\inetsrv\static.dll" />
            <add name="AnonymousAuthenticationModule" image="%windir%\System32\inetsrv\authanon.dll" />
            <add name="RequestFilteringModule" image="%windir%\System32\inetsrv\modrqflt.dll" />
            <add name="CustomErrorModule" image="%windir%\System32\inetsrv\custerr.dll" />
            <add name="HttpLoggingModule" image="%windir%\System32\inetsrv\loghttp.dll" />
            <add name="BasicAuthenticationModule" image="%windir%\System32\inetsrv\authbas.dll" />
            <add name="WindowsAuthenticationModule" image="%windir%\System32\inetsrv\authsspi.dll" />
            <add name="RequestMonitorModule" image="%windir%\System32\inetsrv\iisreqs.dll" />
            <add name="TracingModule" image="%windir%\System32\inetsrv\iisetw.dll" />
            <add name="FailedRequestsTracingModule" image="%windir%\System32\inetsrv\iisfreb.dll" />
            <add name="IsapiModule" image="%windir%\System32\inetsrv\isapi.dll" />
            <add name="IsapiFilterModule" image="%windir%\System32\inetsrv\filter.dll" />
            <add name="ManagedEngineV4.0_32bit" image="%windir%\Microsoft.NET\Framework\v4.0.30319\webengine4.dll" preCondition="integratedMode,runtimeVersionv4.0,bitness32" />
            <add name="ManagedEngineV4.0_64bit" image="%windir%\Microsoft.NET\Framework64\v4.0.30319\webengine4.dll" preCondition="integratedMode,runtimeVersionv4.0,bitness64" />
            <add name="ConfigurationValidationModule" image="%windir%\System32\inetsrv\validcfg.dll" />
            <add name="ApplicationInitializationModule" image="%windir%\System32\inetsrv\warmup.dll" />
        </globalModules>

        <httpCompression directory="%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files">
            <scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" />
            <staticTypes>
                <add mimeType="text/*" enabled="true" />
                <add mimeType="message/*" enabled="true" />
                <add mimeType="application/javascript" enabled="true" />
                <add mimeType="application/atom+xml" enabled="true" />
                <add mimeType="application/xaml+xml" enabled="true" />
                <add mimeType="*/*" enabled="false" />
            </staticTypes>
        </httpCompression>

        <httpErrors lockAttributes="allowAbsolutePathsWhenDelegated,defaultPath">
            <error statusCode="401" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="401.htm" />
            <error statusCode="403" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="403.htm" />
            <error statusCode="404" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="404.htm" />
            <error statusCode="405" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="405.htm" />
            <error statusCode="406" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="406.htm" />
            <error statusCode="412" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="412.htm" />
            <error statusCode="500" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="500.htm" />
            <error statusCode="501" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="501.htm" />
            <error statusCode="502" prefixLanguageFilePath="%SystemDrive%\inetpub\custerr" path="502.htm" />
        </httpErrors>

        <httpLogging dontLog="false" />

        <httpProtocol>
            <customHeaders>
                <clear />
                <add name="X-Powered-By" value="ASP.NET" />
            </customHeaders>
            <redirectHeaders>
                <clear />
            </redirectHeaders>
        </httpProtocol>

        <httpRedirect />

        <httpTracing>
        </httpTracing>

        <isapiFilters>
            <filter name="ASP.Net_4.0_32bit" path="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_filter.dll" enableCache="true" preCondition="runtimeVersionv4.0,bitness32" />
            <filter name="ASP.Net_4.0_64bit" path="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_filter.dll" enableCache="true" preCondition="runtimeVersionv4.0,bitness64" />
        </isapiFilters>

        <odbcLogging />

        <security>

            <access sslFlags="None" />

            <applicationDependencies />

            <authentication>

                <basicAuthentication enabled="false" />

                <clientCertificateMappingAuthentication />

                <digestAuthentication />

                <iisClientCertificateMappingAuthentication />

            </authentication>

            <authorization />

            <ipSecurity />

            <isapiCgiRestriction>
                <add path="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" allowed="true" groupId="ASP.NET v4.0.30319" description="ASP.NET v4.0.30319" />
                <add path="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" allowed="true" groupId="ASP.NET v4.0.30319" description="ASP.NET v4.0.30319" />
            </isapiCgiRestriction>

            <requestFiltering>
                <fileExtensions allowUnlisted="true" applyToWebDAV="true">
                    <add fileExtension=".asax" allowed="false" />
                    <add fileExtension=".ascx" allowed="false" />
                    <add fileExtension=".master" allowed="false" />
                    <add fileExtension=".skin" allowed="false" />
                    <add fileExtension=".browser" allowed="false" />
                    <add fileExtension=".sitemap" allowed="false" />
                    <add fileExtension=".config" allowed="false" />
                    <add fileExtension=".cs" allowed="false" />
                    <add fileExtension=".csproj" allowed="false" />
                    <add fileExtension=".vb" allowed="false" />
                    <add fileExtension=".vbproj" allowed="false" />
                    <add fileExtension=".webinfo" allowed="false" />
                    <add fileExtension=".licx" allowed="false" />
                    <add fileExtension=".resx" allowed="false" />
                    <add fileExtension=".resources" allowed="false" />
                    <add fileExtension=".mdb" allowed="false" />
                    <add fileExtension=".vjsproj" allowed="false" />
                    <add fileExtension=".java" allowed="false" />
                    <add fileExtension=".jsl" allowed="false" />
                    <add fileExtension=".ldb" allowed="false" />
                    <add fileExtension=".dsdgm" allowed="false" />
                    <add fileExtension=".ssdgm" allowed="false" />
                    <add fileExtension=".lsad" allowed="false" />
                    <add fileExtension=".ssmap" allowed="false" />
                    <add fileExtension=".cd" allowed="false" />
                    <add fileExtension=".dsprototype" allowed="false" />
                    <add fileExtension=".lsaprototype" allowed="false" />
                    <add fileExtension=".sdm" allowed="false" />
                    <add fileExtension=".sdmDocument" allowed="false" />
                    <add fileExtension=".mdf" allowed="false" />
                    <add fileExtension=".ldf" allowed="false" />
                    <add fileExtension=".ad" allowed="false" />
                    <add fileExtension=".dd" allowed="false" />
                    <add fileExtension=".ldd" allowed="false" />
                    <add fileExtension=".sd" allowed="false" />
                    <add fileExtension=".adprototype" allowed="false" />
                    <add fileExtension=".lddprototype" allowed="false" />
                    <add fileExtension=".exclude" allowed="false" />
                    <add fileExtension=".refresh" allowed="false" />
                    <add fileExtension=".compiled" allowed="false" />
                    <add fileExtension=".msgx" allowed="false" />
                    <add fileExtension=".vsdisco" allowed="false" />
                    <add fileExtension=".rules" allowed="false" />
                </fileExtensions>
                <verbs allowUnlisted="true" applyToWebDAV="true" />
                <hiddenSegments applyToWebDAV="true">
                    <add segment="web.config" />
                    <add segment="bin" />
                    <add segment="App_code" />
                    <add segment="App_GlobalResources" />
                    <add segment="App_LocalResources" />
                    <add segment="App_WebReferences" />
                    <add segment="App_Data" />
                    <add segment="App_Browsers" />
                </hiddenSegments>
            </requestFiltering>

        </security>

        <serverRuntime />

        <serverSideInclude />

        <staticContent lockAttributes="isDocFooterFileName">
            <mimeMap fileExtension=".323" mimeType="text/h323" />
            <mimeMap fileExtension=".3g2" mimeType="video/3gpp2" />
            <mimeMap fileExtension=".3gp2" mimeType="video/3gpp2" />
            <mimeMap fileExtension=".3gp" mimeType="video/3gpp" />
            <mimeMap fileExtension=".3gpp" mimeType="video/3gpp" />
            <mimeMap fileExtension=".aaf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".aac" mimeType="audio/aac" />
            <mimeMap fileExtension=".aca" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".accdb" mimeType="application/msaccess" />
            <mimeMap fileExtension=".accde" mimeType="application/msaccess" />
            <mimeMap fileExtension=".accdt" mimeType="application/msaccess" />
            <mimeMap fileExtension=".acx" mimeType="application/internet-property-stream" />
            <mimeMap fileExtension=".adt" mimeType="audio/vnd.dlna.adts" />
            <mimeMap fileExtension=".adts" mimeType="audio/vnd.dlna.adts" />
            <mimeMap fileExtension=".afm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ai" mimeType="application/postscript" />
            <mimeMap fileExtension=".aif" mimeType="audio/x-aiff" />
            <mimeMap fileExtension=".aifc" mimeType="audio/aiff" />
            <mimeMap fileExtension=".aiff" mimeType="audio/aiff" />
            <mimeMap fileExtension=".application" mimeType="application/x-ms-application" />
            <mimeMap fileExtension=".art" mimeType="image/x-jg" />
            <mimeMap fileExtension=".asd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".asf" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".asi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".asm" mimeType="text/plain" />
            <mimeMap fileExtension=".asr" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".asx" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".atom" mimeType="application/atom+xml" />
            <mimeMap fileExtension=".au" mimeType="audio/basic" />
            <mimeMap fileExtension=".avi" mimeType="video/avi" />
            <mimeMap fileExtension=".axs" mimeType="application/olescript" />
            <mimeMap fileExtension=".bas" mimeType="text/plain" />
            <mimeMap fileExtension=".bcpio" mimeType="application/x-bcpio" />
            <mimeMap fileExtension=".bin" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".bmp" mimeType="image/bmp" />
            <mimeMap fileExtension=".c" mimeType="text/plain" />
            <mimeMap fileExtension=".cab" mimeType="application/vnd.ms-cab-compressed" />
            <mimeMap fileExtension=".calx" mimeType="application/vnd.ms-office.calx" />
            <mimeMap fileExtension=".cat" mimeType="application/vnd.ms-pki.seccat" />
            <mimeMap fileExtension=".cdf" mimeType="application/x-cdf" />
            <mimeMap fileExtension=".chm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".class" mimeType="application/x-java-applet" />
            <mimeMap fileExtension=".clp" mimeType="application/x-msclip" />
            <mimeMap fileExtension=".cmx" mimeType="image/x-cmx" />
            <mimeMap fileExtension=".cnf" mimeType="text/plain" />
            <mimeMap fileExtension=".cod" mimeType="image/cis-cod" />
            <mimeMap fileExtension=".cpio" mimeType="application/x-cpio" />
            <mimeMap fileExtension=".cpp" mimeType="text/plain" />
            <mimeMap fileExtension=".crd" mimeType="application/x-mscardfile" />
            <mimeMap fileExtension=".crl" mimeType="application/pkix-crl" />
            <mimeMap fileExtension=".crt" mimeType="application/x-x509-ca-cert" />
            <mimeMap fileExtension=".csh" mimeType="application/x-csh" />
            <mimeMap fileExtension=".css" mimeType="text/css" />
            <mimeMap fileExtension=".csv" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".cur" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dcr" mimeType="application/x-director" />
            <mimeMap fileExtension=".deploy" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".der" mimeType="application/x-x509-ca-cert" />
            <mimeMap fileExtension=".dib" mimeType="image/bmp" />
            <mimeMap fileExtension=".dir" mimeType="application/x-director" />
            <mimeMap fileExtension=".disco" mimeType="text/xml" />
            <mimeMap fileExtension=".dll" mimeType="application/x-msdownload" />
            <mimeMap fileExtension=".dll.config" mimeType="text/xml" />
            <mimeMap fileExtension=".dlm" mimeType="text/dlm" />
            <mimeMap fileExtension=".doc" mimeType="application/msword" />
            <mimeMap fileExtension=".docm" mimeType="application/vnd.ms-word.document.macroEnabled.12" />
            <mimeMap fileExtension=".docx" mimeType="application/vnd.openxmlformats-officedocument.wordprocessingml.document" />
            <mimeMap fileExtension=".dot" mimeType="application/msword" />
            <mimeMap fileExtension=".dotm" mimeType="application/vnd.ms-word.template.macroEnabled.12" />
            <mimeMap fileExtension=".dotx" mimeType="application/vnd.openxmlformats-officedocument.wordprocessingml.template" />
            <mimeMap fileExtension=".dsp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dtd" mimeType="text/xml" />
            <mimeMap fileExtension=".dvi" mimeType="application/x-dvi" />
            <mimeMap fileExtension=".dvr-ms" mimeType="video/x-ms-dvr" />
            <mimeMap fileExtension=".dwf" mimeType="drawing/x-dwf" />
            <mimeMap fileExtension=".dwp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".dxr" mimeType="application/x-director" />
            <mimeMap fileExtension=".eml" mimeType="message/rfc822" />
            <mimeMap fileExtension=".emz" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".eot" mimeType="application/vnd.ms-fontobject" />
            <mimeMap fileExtension=".eps" mimeType="application/postscript" />
            <mimeMap fileExtension=".etx" mimeType="text/x-setext" />
            <mimeMap fileExtension=".evy" mimeType="application/envoy" />
            <mimeMap fileExtension=".exe" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".exe.config" mimeType="text/xml" />
            <mimeMap fileExtension=".fdf" mimeType="application/vnd.fdf" />
            <mimeMap fileExtension=".fif" mimeType="application/fractals" />
            <mimeMap fileExtension=".fla" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".flr" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".flv" mimeType="video/x-flv" />
            <mimeMap fileExtension=".gif" mimeType="image/gif" />
            <mimeMap fileExtension=".gtar" mimeType="application/x-gtar" />
            <mimeMap fileExtension=".gz" mimeType="application/x-gzip" />
            <mimeMap fileExtension=".h" mimeType="text/plain" />
            <mimeMap fileExtension=".hdf" mimeType="application/x-hdf" />
            <mimeMap fileExtension=".hdml" mimeType="text/x-hdml" />
            <mimeMap fileExtension=".hhc" mimeType="application/x-oleobject" />
            <mimeMap fileExtension=".hhk" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".hhp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".hlp" mimeType="application/winhlp" />
            <mimeMap fileExtension=".hqx" mimeType="application/mac-binhex40" />
            <mimeMap fileExtension=".hta" mimeType="application/hta" />
            <mimeMap fileExtension=".htc" mimeType="text/x-component" />
            <mimeMap fileExtension=".htm" mimeType="text/html" />
            <mimeMap fileExtension=".html" mimeType="text/html" />
            <mimeMap fileExtension=".htt" mimeType="text/webviewhtml" />
            <mimeMap fileExtension=".hxt" mimeType="text/html" />
            <mimeMap fileExtension=".ico" mimeType="image/x-icon" />
            <mimeMap fileExtension=".ics" mimeType="text/calendar" />
            <mimeMap fileExtension=".ief" mimeType="image/ief" />
            <mimeMap fileExtension=".iii" mimeType="application/x-iphone" />
            <mimeMap fileExtension=".inf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ins" mimeType="application/x-internet-signup" />
            <mimeMap fileExtension=".isp" mimeType="application/x-internet-signup" />
            <mimeMap fileExtension=".IVF" mimeType="video/x-ivf" />
            <mimeMap fileExtension=".jar" mimeType="application/java-archive" />
            <mimeMap fileExtension=".java" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".jck" mimeType="application/liquidmotion" />
            <mimeMap fileExtension=".jcz" mimeType="application/liquidmotion" />
            <mimeMap fileExtension=".jfif" mimeType="image/pjpeg" />
            <mimeMap fileExtension=".jpb" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".jpe" mimeType="image/jpeg" />
            <mimeMap fileExtension=".jpeg" mimeType="image/jpeg" />
            <mimeMap fileExtension=".jpg" mimeType="image/jpeg" />
            <mimeMap fileExtension=".js" mimeType="application/javascript" />
            <mimeMap fileExtension=".json" mimeType="application/json" />
            <mimeMap fileExtension=".jsx" mimeType="text/jscript" />
            <mimeMap fileExtension=".latex" mimeType="application/x-latex" />
            <mimeMap fileExtension=".lit" mimeType="application/x-ms-reader" />
            <mimeMap fileExtension=".lpk" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".lsf" mimeType="video/x-la-asf" />
            <mimeMap fileExtension=".lsx" mimeType="video/x-la-asf" />
            <mimeMap fileExtension=".lzh" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".m13" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".m14" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".m1v" mimeType="video/mpeg" />
            <mimeMap fileExtension=".m2ts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".m3u" mimeType="audio/x-mpegurl" />
            <mimeMap fileExtension=".m4a" mimeType="audio/mp4" />
            <mimeMap fileExtension=".m4v" mimeType="video/mp4" />
            <mimeMap fileExtension=".man" mimeType="application/x-troff-man" />
            <mimeMap fileExtension=".manifest" mimeType="application/x-ms-manifest" />
            <mimeMap fileExtension=".map" mimeType="text/plain" />
            <mimeMap fileExtension=".mdb" mimeType="application/x-msaccess" />
            <mimeMap fileExtension=".mdp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".me" mimeType="application/x-troff-me" />
            <mimeMap fileExtension=".mht" mimeType="message/rfc822" />
            <mimeMap fileExtension=".mhtml" mimeType="message/rfc822" />
            <mimeMap fileExtension=".mid" mimeType="audio/mid" />
            <mimeMap fileExtension=".midi" mimeType="audio/mid" />
            <mimeMap fileExtension=".mix" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mmf" mimeType="application/x-smaf" />
            <mimeMap fileExtension=".mno" mimeType="text/xml" />
            <mimeMap fileExtension=".mny" mimeType="application/x-msmoney" />
            <mimeMap fileExtension=".mov" mimeType="video/quicktime" />
            <mimeMap fileExtension=".movie" mimeType="video/x-sgi-movie" />
            <mimeMap fileExtension=".mp2" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mp3" mimeType="audio/mpeg" />
            <mimeMap fileExtension=".mp4" mimeType="video/mp4" />
            <mimeMap fileExtension=".mp4v" mimeType="video/mp4" />
            <mimeMap fileExtension=".mpa" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpe" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpeg" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpg" mimeType="video/mpeg" />
            <mimeMap fileExtension=".mpp" mimeType="application/vnd.ms-project" />
            <mimeMap fileExtension=".mpv2" mimeType="video/mpeg" />
            <mimeMap fileExtension=".ms" mimeType="application/x-troff-ms" />
            <mimeMap fileExtension=".msi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mso" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".mvb" mimeType="application/x-msmediaview" />
            <mimeMap fileExtension=".mvc" mimeType="application/x-miva-compiled" />
            <mimeMap fileExtension=".nc" mimeType="application/x-netcdf" />
            <mimeMap fileExtension=".nsc" mimeType="video/x-ms-asf" />
            <mimeMap fileExtension=".nws" mimeType="message/rfc822" />
            <mimeMap fileExtension=".ocx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".oda" mimeType="application/oda" />
            <mimeMap fileExtension=".odc" mimeType="text/x-ms-odc" />
            <mimeMap fileExtension=".ods" mimeType="application/oleobject" />
            <mimeMap fileExtension=".oga" mimeType="audio/ogg" />
            <mimeMap fileExtension=".ogg" mimeType="video/ogg" />
            <mimeMap fileExtension=".ogv" mimeType="video/ogg" />
            <mimeMap fileExtension=".one" mimeType="application/onenote" />
            <mimeMap fileExtension=".onea" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetoc" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetoc2" mimeType="application/onenote" />
            <mimeMap fileExtension=".onetmp" mimeType="application/onenote" />
            <mimeMap fileExtension=".onepkg" mimeType="application/onenote" />
            <mimeMap fileExtension=".osdx" mimeType="application/opensearchdescription+xml" />
            <mimeMap fileExtension=".otf" mimeType="font/otf" />
            <mimeMap fileExtension=".p10" mimeType="application/pkcs10" />
            <mimeMap fileExtension=".p12" mimeType="application/x-pkcs12" />
            <mimeMap fileExtension=".p7b" mimeType="application/x-pkcs7-certificates" />
            <mimeMap fileExtension=".p7c" mimeType="application/pkcs7-mime" />
            <mimeMap fileExtension=".p7m" mimeType="application/pkcs7-mime" />
            <mimeMap fileExtension=".p7r" mimeType="application/x-pkcs7-certreqresp" />
            <mimeMap fileExtension=".p7s" mimeType="application/pkcs7-signature" />
            <mimeMap fileExtension=".pbm" mimeType="image/x-portable-bitmap" />
            <mimeMap fileExtension=".pcx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pcz" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pdf" mimeType="application/pdf" />
            <mimeMap fileExtension=".pfb" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pfm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pfx" mimeType="application/x-pkcs12" />
            <mimeMap fileExtension=".pgm" mimeType="image/x-portable-graymap" />
            <mimeMap fileExtension=".pko" mimeType="application/vnd.ms-pki.pko" />
            <mimeMap fileExtension=".pma" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmc" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pml" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmr" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".pmw" mimeType="application/x-perfmon" />
            <mimeMap fileExtension=".png" mimeType="image/png" />
            <mimeMap fileExtension=".pnm" mimeType="image/x-portable-anymap" />
            <mimeMap fileExtension=".pnz" mimeType="image/png" />
            <mimeMap fileExtension=".pot" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".potm" mimeType="application/vnd.ms-powerpoint.template.macroEnabled.12" />
            <mimeMap fileExtension=".potx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.template" />
            <mimeMap fileExtension=".ppam" mimeType="application/vnd.ms-powerpoint.addin.macroEnabled.12" />
            <mimeMap fileExtension=".ppm" mimeType="image/x-portable-pixmap" />
            <mimeMap fileExtension=".pps" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".ppsm" mimeType="application/vnd.ms-powerpoint.slideshow.macroEnabled.12" />
            <mimeMap fileExtension=".ppsx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.slideshow" />
            <mimeMap fileExtension=".ppt" mimeType="application/vnd.ms-powerpoint" />
            <mimeMap fileExtension=".pptm" mimeType="application/vnd.ms-powerpoint.presentation.macroEnabled.12" />
            <mimeMap fileExtension=".pptx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.presentation" />
            <mimeMap fileExtension=".prf" mimeType="application/pics-rules" />
            <mimeMap fileExtension=".prm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".prx" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ps" mimeType="application/postscript" />
            <mimeMap fileExtension=".psd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".psm" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".psp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".pub" mimeType="application/x-mspublisher" />
            <mimeMap fileExtension=".qt" mimeType="video/quicktime" />
            <mimeMap fileExtension=".qtl" mimeType="application/x-quicktimeplayer" />
            <mimeMap fileExtension=".qxd" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ra" mimeType="audio/x-pn-realaudio" />
            <mimeMap fileExtension=".ram" mimeType="audio/x-pn-realaudio" />
            <mimeMap fileExtension=".rar" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".ras" mimeType="image/x-cmu-raster" />
            <mimeMap fileExtension=".rf" mimeType="image/vnd.rn-realflash" />
            <mimeMap fileExtension=".rgb" mimeType="image/x-rgb" />
            <mimeMap fileExtension=".rm" mimeType="application/vnd.rn-realmedia" />
            <mimeMap fileExtension=".rmi" mimeType="audio/mid" />
            <mimeMap fileExtension=".roff" mimeType="application/x-troff" />
            <mimeMap fileExtension=".rpm" mimeType="audio/x-pn-realaudio-plugin" />
            <mimeMap fileExtension=".rtf" mimeType="application/rtf" />
            <mimeMap fileExtension=".rtx" mimeType="text/richtext" />
            <mimeMap fileExtension=".scd" mimeType="application/x-msschedule" />
            <mimeMap fileExtension=".sct" mimeType="text/scriptlet" />
            <mimeMap fileExtension=".sea" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".setpay" mimeType="application/set-payment-initiation" />
            <mimeMap fileExtension=".setreg" mimeType="application/set-registration-initiation" />
            <mimeMap fileExtension=".sgml" mimeType="text/sgml" />
            <mimeMap fileExtension=".sh" mimeType="application/x-sh" />
            <mimeMap fileExtension=".shar" mimeType="application/x-shar" />
            <mimeMap fileExtension=".sit" mimeType="application/x-stuffit" />
            <mimeMap fileExtension=".sldm" mimeType="application/vnd.ms-powerpoint.slide.macroEnabled.12" />
            <mimeMap fileExtension=".sldx" mimeType="application/vnd.openxmlformats-officedocument.presentationml.slide" />
            <mimeMap fileExtension=".smd" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".smi" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".smx" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".smz" mimeType="audio/x-smd" />
            <mimeMap fileExtension=".snd" mimeType="audio/basic" />
            <mimeMap fileExtension=".snp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".spc" mimeType="application/x-pkcs7-certificates" />
            <mimeMap fileExtension=".spl" mimeType="application/futuresplash" />
            <mimeMap fileExtension=".spx" mimeType="audio/ogg" />
            <mimeMap fileExtension=".src" mimeType="application/x-wais-source" />
            <mimeMap fileExtension=".ssm" mimeType="application/streamingmedia" />
            <mimeMap fileExtension=".sst" mimeType="application/vnd.ms-pki.certstore" />
            <mimeMap fileExtension=".stl" mimeType="application/vnd.ms-pki.stl" />
            <mimeMap fileExtension=".sv4cpio" mimeType="application/x-sv4cpio" />
            <mimeMap fileExtension=".sv4crc" mimeType="application/x-sv4crc" />
            <mimeMap fileExtension=".svg" mimeType="image/svg+xml" />
            <mimeMap fileExtension=".svgz" mimeType="image/svg+xml" />
            <mimeMap fileExtension=".swf" mimeType="application/x-shockwave-flash" />
            <mimeMap fileExtension=".t" mimeType="application/x-troff" />
            <mimeMap fileExtension=".tar" mimeType="application/x-tar" />
            <mimeMap fileExtension=".tcl" mimeType="application/x-tcl" />
            <mimeMap fileExtension=".tex" mimeType="application/x-tex" />
            <mimeMap fileExtension=".texi" mimeType="application/x-texinfo" />
            <mimeMap fileExtension=".texinfo" mimeType="application/x-texinfo" />
            <mimeMap fileExtension=".tgz" mimeType="application/x-compressed" />
            <mimeMap fileExtension=".thmx" mimeType="application/vnd.ms-officetheme" />
            <mimeMap fileExtension=".thn" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tif" mimeType="image/tiff" />
            <mimeMap fileExtension=".tiff" mimeType="image/tiff" />
            <mimeMap fileExtension=".toc" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tr" mimeType="application/x-troff" />
            <mimeMap fileExtension=".trm" mimeType="application/x-msterminal" />
            <mimeMap fileExtension=".ts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".tsv" mimeType="text/tab-separated-values" />
            <mimeMap fileExtension=".ttf" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".tts" mimeType="video/vnd.dlna.mpeg-tts" />
            <mimeMap fileExtension=".txt" mimeType="text/plain" />
            <mimeMap fileExtension=".u32" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".uls" mimeType="text/iuls" />
            <mimeMap fileExtension=".ustar" mimeType="application/x-ustar" />
            <mimeMap fileExtension=".vbs" mimeType="text/vbscript" />
            <mimeMap fileExtension=".vcf" mimeType="text/x-vcard" />
            <mimeMap fileExtension=".vcs" mimeType="text/plain" />
            <mimeMap fileExtension=".vdx" mimeType="application/vnd.ms-visio.viewer" />
            <mimeMap fileExtension=".vml" mimeType="text/xml" />
            <mimeMap fileExtension=".vsd" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vss" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vst" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vsto" mimeType="application/x-ms-vsto" />
            <mimeMap fileExtension=".vsw" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vsx" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".vtx" mimeType="application/vnd.visio" />
            <mimeMap fileExtension=".wav" mimeType="audio/wav" />
            <mimeMap fileExtension=".wax" mimeType="audio/x-ms-wax" />
            <mimeMap fileExtension=".wbmp" mimeType="image/vnd.wap.wbmp" />
            <mimeMap fileExtension=".wcm" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wdb" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".webm" mimeType="video/webm" />
            <mimeMap fileExtension=".wks" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wm" mimeType="video/x-ms-wm" />
            <mimeMap fileExtension=".wma" mimeType="audio/x-ms-wma" />
            <mimeMap fileExtension=".wmd" mimeType="application/x-ms-wmd" />
            <mimeMap fileExtension=".wmf" mimeType="application/x-msmetafile" />
            <mimeMap fileExtension=".wml" mimeType="text/vnd.wap.wml" />
            <mimeMap fileExtension=".wmlc" mimeType="application/vnd.wap.wmlc" />
            <mimeMap fileExtension=".wmls" mimeType="text/vnd.wap.wmlscript" />
            <mimeMap fileExtension=".wmlsc" mimeType="application/vnd.wap.wmlscriptc" />
            <mimeMap fileExtension=".wmp" mimeType="video/x-ms-wmp" />
            <mimeMap fileExtension=".wmv" mimeType="video/x-ms-wmv" />
            <mimeMap fileExtension=".wmx" mimeType="video/x-ms-wmx" />
            <mimeMap fileExtension=".wmz" mimeType="application/x-ms-wmz" />
            <mimeMap fileExtension=".woff" mimeType="font/x-woff" />
            <mimeMap fileExtension=".wps" mimeType="application/vnd.ms-works" />
            <mimeMap fileExtension=".wri" mimeType="application/x-mswrite" />
            <mimeMap fileExtension=".wrl" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".wrz" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".wsdl" mimeType="text/xml" />
            <mimeMap fileExtension=".wtv" mimeType="video/x-ms-wtv" />
            <mimeMap fileExtension=".wvx" mimeType="video/x-ms-wvx" />
            <mimeMap fileExtension=".x" mimeType="application/directx" />
            <mimeMap fileExtension=".xaf" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".xaml" mimeType="application/xaml+xml" />
            <mimeMap fileExtension=".xap" mimeType="application/x-silverlight-app" />
            <mimeMap fileExtension=".xbap" mimeType="application/x-ms-xbap" />
            <mimeMap fileExtension=".xbm" mimeType="image/x-xbitmap" />
            <mimeMap fileExtension=".xdr" mimeType="text/plain" />
            <mimeMap fileExtension=".xht" mimeType="application/xhtml+xml" />
            <mimeMap fileExtension=".xhtml" mimeType="application/xhtml+xml" />
            <mimeMap fileExtension=".xla" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlam" mimeType="application/vnd.ms-excel.addin.macroEnabled.12" />
            <mimeMap fileExtension=".xlc" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlm" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xls" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xlsb" mimeType="application/vnd.ms-excel.sheet.binary.macroEnabled.12" />
            <mimeMap fileExtension=".xlsm" mimeType="application/vnd.ms-excel.sheet.macroEnabled.12" />
            <mimeMap fileExtension=".xlsx" mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" />
            <mimeMap fileExtension=".xlt" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xltm" mimeType="application/vnd.ms-excel.template.macroEnabled.12" />
            <mimeMap fileExtension=".xltx" mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.template" />
            <mimeMap fileExtension=".xlw" mimeType="application/vnd.ms-excel" />
            <mimeMap fileExtension=".xml" mimeType="text/xml" />
            <mimeMap fileExtension=".xof" mimeType="x-world/x-vrml" />
            <mimeMap fileExtension=".xpm" mimeType="image/x-xpixmap" />
            <mimeMap fileExtension=".xps" mimeType="application/vnd.ms-xpsdocument" />
            <mimeMap fileExtension=".xsd" mimeType="text/xml" />
            <mimeMap fileExtension=".xsf" mimeType="text/xml" />
            <mimeMap fileExtension=".xsl" mimeType="text/xml" />
            <mimeMap fileExtension=".xslt" mimeType="text/xml" />
            <mimeMap fileExtension=".xsn" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".xtp" mimeType="application/octet-stream" />
            <mimeMap fileExtension=".xwd" mimeType="image/x-xwindowdump" />
            <mimeMap fileExtension=".z" mimeType="application/x-compress" />
            <mimeMap fileExtension=".zip" mimeType="application/x-zip-compressed" />
        </staticContent>

        <tracing>

            <traceFailedRequests />

            <traceProviderDefinitions>
                <add name="WWW Server" guid="{3a2a4e84-4c21-4981-ae10-3fda0d9b0f83}">
                    <areas>
                        <clear />
                        <add name="Authentication" value="2" />
                        <add name="Security" value="4" />
                        <add name="Filter" value="8" />
                        <add name="StaticFile" value="16" />
                        <add name="CGI" value="32" />
                        <add name="Compression" value="64" />
                        <add name="Cache" value="128" />
                        <add name="RequestNotifications" value="256" />
                        <add name="Module" value="512" />
                        <add name="FastCGI" value="4096" />
                        <add name="WebSocket" value="16384" />
                    </areas>
                </add>
                <add name="ASP" guid="{06b94d9a-b15e-456e-a4ef-37c984a2cb4b}">
                    <areas>
                        <clear />
                    </areas>
                </add>
                <add name="ISAPI Extension" guid="{a1c2040e-8840-4c31-ba11-9871031a19ea}">
                    <areas>
                        <clear />
                    </areas>
                </add>
                <add name="ASPNET" guid="{AFF081FE-0247-4275-9C4E-021F3DC1DA35}">
                    <areas>
                        <add name="Infrastructure" value="1" />
                        <add name="Module" value="2" />
                        <add name="Page" value="4" />
                        <add name="AppServices" value="8" />
                    </areas>
                </add>
            </traceProviderDefinitions>

        </tracing>

        <urlCompression />

        <validation />
        <applicationInitialization />

    </system.webServer>
    <location path="" overrideMode="Allow">
        <system.webServer>

        <handlers accessPolicy="Read, Script">
                <add name="xamlx-ISAPI-4.0_64bit" path="*.xamlx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" />
                <add name="xamlx-ISAPI-4.0_32bit" path="*.xamlx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" />
                <add name="xamlx-Integrated-4.0" path="*.xamlx" verb="GET,HEAD,POST,DEBUG" type="System.Xaml.Hosting.XamlHttpHandlerFactory, System.Xaml.Hosting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="integratedMode,runtimeVersionv4.0" />
                <add name="rules-ISAPI-4.0_64bit" path="*.rules" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" />
                <add name="rules-ISAPI-4.0_32bit" path="*.rules" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" />
                <add name="rules-Integrated-4.0" path="*.rules" verb="*" type="System.ServiceModel.Activation.ServiceHttpHandlerFactory, System.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="integratedMode,runtimeVersionv4.0" />
                <add name="xoml-ISAPI-4.0_64bit" path="*.xoml" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" />
                <add name="xoml-ISAPI-4.0_32bit" path="*.xoml" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" />
                <add name="xoml-Integrated-4.0" path="*.xoml" verb="*" type="System.ServiceModel.Activation.ServiceHttpHandlerFactory, System.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="integratedMode,runtimeVersionv4.0" />
                <add name="svc-ISAPI-4.0_64bit" path="*.svc" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" />
                <add name="svc-ISAPI-4.0_32bit" path="*.svc" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" />
                <add name="svc-Integrated-4.0" path="*.svc" verb="*" type="System.ServiceModel.Activation.ServiceHttpHandlerFactory, System.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="ISAPI-dll" path="*.dll" verb="*" modules="IsapiModule" resourceType="File" requireAccess="Execute" allowPathInfo="true" />
            <add name="AXD-ISAPI-4.0_64bit" path="*.axd" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="PageHandlerFactory-ISAPI-4.0_64bit" path="*.aspx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="SimpleHandlerFactory-ISAPI-4.0_64bit" path="*.ashx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="WebServiceHandlerFactory-ISAPI-4.0_64bit" path="*.asmx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="HttpRemotingHandlerFactory-rem-ISAPI-4.0_64bit" path="*.rem" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="HttpRemotingHandlerFactory-soap-ISAPI-4.0_64bit" path="*.soap" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="aspq-ISAPI-4.0_64bit" path="*.aspq" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="cshtm-ISAPI-4.0_64bit" path="*.cshtm" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="cshtml-ISAPI-4.0_64bit" path="*.cshtml" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="vbhtm-ISAPI-4.0_64bit" path="*.vbhtm" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="vbhtml-ISAPI-4.0_64bit" path="*.vbhtml" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="TraceHandler-Integrated-4.0" path="trace.axd" verb="GET,HEAD,POST,DEBUG" type="System.Web.Handlers.TraceHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="WebAdminHandler-Integrated-4.0" path="WebAdmin.axd" verb="GET,DEBUG" type="System.Web.Handlers.WebAdminHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="AssemblyResourceLoader-Integrated-4.0" path="WebResource.axd" verb="GET,DEBUG" type="System.Web.Handlers.AssemblyResourceLoader" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="PageHandlerFactory-Integrated-4.0" path="*.aspx" verb="GET,HEAD,POST,DEBUG" type="System.Web.UI.PageHandlerFactory" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="SimpleHandlerFactory-Integrated-4.0" path="*.ashx" verb="GET,HEAD,POST,DEBUG" type="System.Web.UI.SimpleHandlerFactory" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="WebServiceHandlerFactory-Integrated-4.0" path="*.asmx" verb="GET,HEAD,POST,DEBUG" type="System.Web.Script.Services.ScriptHandlerFactory, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="HttpRemotingHandlerFactory-rem-Integrated-4.0" path="*.rem" verb="GET,HEAD,POST,DEBUG" type="System.Runtime.Remoting.Channels.Http.HttpRemotingHandlerFactory, System.Runtime.Remoting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="HttpRemotingHandlerFactory-soap-Integrated-4.0" path="*.soap" verb="GET,HEAD,POST,DEBUG" type="System.Runtime.Remoting.Channels.Http.HttpRemotingHandlerFactory, System.Runtime.Remoting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="aspq-Integrated-4.0" path="*.aspq" verb="GET,HEAD,POST,DEBUG" type="System.Web.HttpForbiddenHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="cshtm-Integrated-4.0" path="*.cshtm" verb="GET,HEAD,POST,DEBUG" type="System.Web.HttpForbiddenHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="cshtml-Integrated-4.0" path="*.cshtml" verb="GET,HEAD,POST,DEBUG" type="System.Web.HttpForbiddenHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="vbhtm-Integrated-4.0" path="*.vbhtm" verb="GET,HEAD,POST,DEBUG" type="System.Web.HttpForbiddenHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="vbhtml-Integrated-4.0" path="*.vbhtml" verb="GET,HEAD,POST,DEBUG" type="System.Web.HttpForbiddenHandler" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="ScriptHandlerFactoryAppServices-Integrated-4.0" path="*_AppService.axd" verb="*" type="System.Web.Script.Services.ScriptHandlerFactory, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31BF3856AD364E35" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="ScriptResourceIntegrated-4.0" path="*ScriptResource.axd" verb="GET,HEAD" type="System.Web.Handlers.ScriptResourceHandler, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31BF3856AD364E35" preCondition="integratedMode,runtimeVersionv4.0" />
            <add name="AXD-ISAPI-4.0_32bit" path="*.axd" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="PageHandlerFactory-ISAPI-4.0_32bit" path="*.aspx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="SimpleHandlerFactory-ISAPI-4.0_32bit" path="*.ashx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="WebServiceHandlerFactory-ISAPI-4.0_32bit" path="*.asmx" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="HttpRemotingHandlerFactory-rem-ISAPI-4.0_32bit" path="*.rem" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="HttpRemotingHandlerFactory-soap-ISAPI-4.0_32bit" path="*.soap" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="aspq-ISAPI-4.0_32bit" path="*.aspq" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="cshtm-ISAPI-4.0_32bit" path="*.cshtm" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="cshtml-ISAPI-4.0_32bit" path="*.cshtml" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="vbhtm-ISAPI-4.0_32bit" path="*.vbhtm" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="vbhtml-ISAPI-4.0_32bit" path="*.vbhtml" verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="TRACEVerbHandler" path="*" verb="TRACE" modules="ProtocolSupportModule" requireAccess="None" />
            <add name="OPTIONSVerbHandler" path="*" verb="OPTIONS" modules="ProtocolSupportModule" requireAccess="None" />
            <add name="ExtensionlessUrlHandler-ISAPI-4.0_32bit" path="*." verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness32" responseBufferLimit="0" />
            <add name="ExtensionlessUrlHandler-ISAPI-4.0_64bit" path="*." verb="GET,HEAD,POST,DEBUG" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" preCondition="classicMode,runtimeVersionv4.0,bitness64" responseBufferLimit="0" />
            <add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="GET,HEAD,POST,DEBUG" type="System.Web.Handlers.TransferRequestHandler" preCondition="integratedMode,runtimeVersionv4.0" responseBufferLimit="0" />
            <add name="StaticFile" path="*" verb="*" modules="StaticFileModule,DefaultDocumentModule,DirectoryListingModule" resourceType="Either" requireAccess="Read" />
        </handlers>

        <modules>
            <add name="HttpCacheModule" lockItem="true" />
            <add name="StaticCompressionModule" lockItem="true" />
            <add name="DefaultDocumentModule" lockItem="true" />
            <add name="DirectoryListingModule" lockItem="true" />
            <add name="IsapiFilterModule" lockItem="true" />
            <add name="ProtocolSupportModule" lockItem="true" />
            <add name="StaticFileModule" lockItem="true" />
            <add name="AnonymousAuthenticationModule" lockItem="true" />
            <add name="RequestFilteringModule" lockItem="true" />
            <add name="CustomErrorModule" lockItem="true" />
            <add name="BasicAuthenticationModule" lockItem="true" />
            <add name="IsapiModule" lockItem="true" />
            <add name="HttpLoggingModule" lockItem="true" />
            <add name="WindowsAuthenticationModule" lockItem="true" />
            <add name="FailedRequestsTracingModule" lockItem="true" />
            <add name="UrlRoutingModule-4.0" type="System.Web.Routing.UrlRoutingModule" preCondition="managedHandler,runtimeVersionv4.0" />
            <add name="ScriptModule-4.0" type="System.Web.Handlers.ScriptModule, System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="managedHandler,runtimeVersionv4.0" />
            <add name="OutputCache" type="System.Web.Caching.OutputCacheModule" preCondition="managedHandler" />
            <add name="Session" type="System.Web.SessionState.SessionStateModule" preCondition="managedHandler" />
            <add name="WindowsAuthentication" type="System.Web.Security.WindowsAuthenticationModule" preCondition="managedHandler" />
            <add name="FormsAuthentication" type="System.Web.Security.FormsAuthenticationModule" preCondition="managedHandler" />
            <add name="DefaultAuthentication" type="System.Web.Security.DefaultAuthenticationModule" preCondition="managedHandler" />
            <add name="RoleManager" type="System.Web.Security.RoleManagerModule" preCondition="managedHandler" />
            <add name="UrlAuthorization" type="System.Web.Security.UrlAuthorizationModule" preCondition="managedHandler" />
            <add name="FileAuthorization" type="System.Web.Security.FileAuthorizationModule" preCondition="managedHandler" />
            <add name="AnonymousIdentification" type="System.Web.Security.AnonymousIdentificationModule" preCondition="managedHandler" />
            <add name="Profile" type="System.Web.Profile.ProfileModule" preCondition="managedHandler" />
            <add name="UrlMappingsModule" type="System.Web.UrlMappingsModule" preCondition="managedHandler" />
                <add name="ConfigurationValidationModule" lockItem="true" />
                <add name="ServiceModel-4.0" type="System.ServiceModel.Activation.ServiceHttpModule, System.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" preCondition="managedHandler,runtimeVersionv4.0" />
                <add name="ApplicationInitializationModule" lockItem="true" />
        </modules>
            <security>
                <authentication>

                <anonymousAuthentication enabled="true" userName="IUSR" />

                <windowsAuthentication enabled="false" authPersistNonNTLM="true">
                    <providers>
                        <add value="Negotiate" />
                        <add value="NTLM" />
                    </providers>
                </windowsAuthentication>
                </authentication>
            </security>
        </system.webServer>
    </location>

</configuration>

...

```

web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--    For more information on how to configure your ASP.NET application, please visit   http://go.microsoft.com/fwlink/?LinkId=169433   -->
<configuration>
  <connectionStrings configSource="Web.connections.config" />
  <appSettings file="J:\ElectSolve\Green\Config\CVR.config">
    <add key="Instance" value="Build 47 - Rev c61d50" />
    <add key="BuildDate" value="03-27-2018" />
    <add key="LogoUrl" value="Content/images/logo_new.png" />
    <add key="Stylesheet.Style" value="Content/style_New.css" />
    <add key="Stylesheet.bootstrap" value="Content/bootstrap_New.css" />
    <add key="FavIcon" value="Content/images/favicon_etss.ico" />
    <add key="SiteName" value="VoltageAnalysis" />
  </appSettings>
  <!--     For a description of web.config changes for .NET 4.5 see http://go.microsoft.com/fwlink/?LinkId=235367.      The following attributes can be set on the <httpRuntime> tag.       <system.Web>         <httpRuntime targetFramework="4.5" />       </system.Web>   -->
  <system.web>
    <httpRuntime enableVersionHeader="false" />
    <compilation debug="true" targetFramework="4.5" />
    <globalization culture="auto" uiCulture="auto" />
    <authentication mode="Windows">
      <forms loginUrl="~/Account/Login" timeout="60" />
    </authentication>	
    <machineKey decryption="AES" decryptionKey="16e58b704f4b03cef98284cdecc5c68ea2775820e9ad9683e3207a8687226743" validation="SHA1" validationKey="5b59bc1fd57b2daf77ff872beea51f61da0d9238d3de421f19630e975c77a6769d8b4f0c64089f7dac046dc829324b211f20bcdcdd5ba89cd9796d87e8f90b14" />
    <pages controlRenderingCompatibilityVersion="4.0">
      <namespaces>
        <add namespace="System.Web.Helpers" />
        <add namespace="System.Web.Mvc" />
        <add namespace="System.Web.Mvc.Ajax" />
        <add namespace="System.Web.Mvc.Html" />
        <add namespace="System.Web.Routing" />
        <add namespace="System.Web.WebPages" />
      </namespaces>
    </pages>
    <membership defaultProvider="SqlMembershipProvider">
      <providers>
        <clear />
        <add name="SqlMembershipProvider" type="System.Web.Security.SqlMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ApplicationServices" enablePasswordRetrieval="false" enablePasswordReset="true" requiresQuestionAndAnswer="true" applicationName="/" requiresUniqueEmail="true" passwordFormat="Hashed" maxInvalidPasswordAttempts="5" minRequiredPasswordLength="7" minRequiredNonalphanumericCharacters="1" passwordAttemptWindow="10" passwordStrengthRegularExpression="" />
      </providers>
    </membership>
    <roleManager enabled="true" defaultProvider="SqlRoleProvider" cacheRolesInCookie="false" cookieName=".ASPXROLES" cookieTimeout="15" cookiePath="/" cookieRequireSSL="false" cookieSlidingExpiration="true" cookieProtection="All" createPersistentCookie="false" maxCachedResults="25">
      <providers>
        <clear />
        <add name="SqlRoleProvider" connectionStringName="ApplicationServices" applicationName="CVR" type="System.Web.Security.SqlRoleProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" />
      </providers>
    </roleManager>
    <!-- prevent scripts from accessing cookies and cookie theft-->
    <!--      http://www.troyhunt.com/2013/03/c-is-for-cookie-h-is-for-hacker.html       -->
    <httpCookies httpOnlyCookies="true" />
  </system.web>
  
  <location path="bin">
	<system.web>
		<authorization>
			<allow users="*" />
		</authorization>
	</system.web>
  </location>
  
  <system.webServer>
	   <applicationInitialization>
		  <add initializationPage="/VoltageAnalysis" />
	   </applicationInitialization>
    <httpProtocol>
      <customHeaders>
        <clear />
        <!-- remove custom headers that reveal technology stack-->
        <remove name="X-Powered-By" />
        <remove name="X-UA-Compatible" />
        <add name="X-UA-Compatible" value="IE=Edge" />
      </customHeaders>
    </httpProtocol>
    <handlers>
      <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
      <remove name="OPTIONSVerbHandler" />
      <remove name="TRACEVerbHandler" />
      <add name="ExtensionlessUrlHandler-Integrated-4.0" path="*." verb="*" type="System.Web.Handlers.TransferRequestHandler" preCondition="integratedMode,runtimeVersionv4.0" />
    </handlers>
        <security>
            <authentication>
                <windowsAuthentication enabled="true">
                    <providers>
                        <clear />
                        <add value="Negotiate" />
                        <add value="NTLM" />
                    </providers>
                </windowsAuthentication>
            </authentication>
        </security>
  </system.webServer>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Web.WebPages.Razor" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-11.0.0.0" newVersion="11.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="WebGrease" publicKeyToken="31bf3856ad364e35" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-1.6.5135.21930" newVersion="1.6.5135.21930" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Antlr3.Runtime" publicKeyToken="eb42632606e9261f" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-3.5.0.2" newVersion="3.5.0.2" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Helpers" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.WebPages" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <!-- WHAT IS GOING ON HERE: See Above Assembly too - conflicts between different versions of the same dependent assembly.        In Visual Studio, double-click this warning (or select it and press Enter) to fix the conflicts; otherwise, add the following        binding redirects to the "runtime" node in the application configuration file: <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">-->
      <dependentAssembly>
        <assemblyIdentity name="System.Net.Http.Formatting" culture="neutral" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.3.0" newVersion="5.2.3.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Mvc" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-5.2.3.0" newVersion="5.2.3.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>

```

```shell

> net stop w3svc & net start w3svc

```

Output:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>net stop w3svc & net start w3svc
The World Wide Web Publishing Service service is stopping.
The World Wide Web Publishing Service service was stopped successfully.

The World Wide Web Publishing Service service is starting.
The World Wide Web Publishing Service service was started successfully.

Warm Up

- Compliing
- In memory cache operations
- queries
- content generation (csss, js, etc..)

Tweak HTTP headers and Cacheing

## Confirm Compression with Fiddler

```powershell
Import-Module ServerManager
Add-WindowsFeature Web-Server, Web-Dyn-Compression
```

IIS Manager
Sites
 Green
  Compression
    Check Enable Dynamic content compression
    Check Enable static content compression

Header Changes and compression with Fiddler



web.config setup for gzip compression.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>

    <httpCompression directory="%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files">
      <scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" staticCompressionLevel="9" />
      <dynamicTypes>
        <add mimeType="text/*" enabled="true" />
        <add mimeType="message/*" enabled="true" />
        <add mimeType="application/x-javascript" enabled="true" />
        <add mimeType="application/json" enabled="true" />
        <add mimeType="*/*" enabled="false" />
      </dynamicTypes>
      <staticTypes>
        <add mimeType="text/*" enabled="true" />
        <add mimeType="message/*" enabled="true" />
        <add mimeType="application/x-javascript" enabled="true" />
        <add mimeType="application/atom+xml" enabled="true" />
        <add mimeType="application/xaml+xml" enabled="true" />
        <add mimeType="*/*" enabled="false" />
      </staticTypes>
    </httpCompression>

    <urlCompression doStaticCompression="true" doDynamicCompression="true" />

  </system.webServer>
</configuration>
```

How to see it in fidder
GET http://10.86.1.191/VoltageAnalysis/EventReport HTTP/1.1
Accept: text/html, application/xhtml+xml, image/jxr, */*
Accept-Language: en-US,en;q=0.5
Referer: http://10.86.1.191/VoltageAnalysis/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299
Accept-Encoding: gzip, deflate
Host: 10.86.1.191
Connection: Keep-Alive

HTTP/1.1 200 OK
Cache-Control: private, s-maxage=0
Content-Type: text/html; charset=utf-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/8.5
Persistent-Auth: true
X-UA-Compatible: IE=Edge
Date: Tue, 10 Apr 2018 23:19:51 GMT
Content-Length: 5331

WHERE IS s-maxage=0 coming from??????

THIS IS NOT CORRECT DO IT AGAIN

## Tweaking the HTTP Headers

Enable HTTP Keep-alive on all sites and applicatins
Enable Web Content
    After 1 or 7 days
    If you update images and static files daily set it to 1 day
    otherwise 7 days... really need to review this by each individual 
    application.

Cache Control Header
    Rt. Click Add
    max-age=604800 
    seconds in one week
    private, public

Trade Offs, no silver bullets
need balance of fresh content and content that has not changed.
need analysis and good testing

web.config setup individual sites...
Need to comment what each config line does

```xml

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>

    <applicationInitialization>
      <add initializationPage="/VoltageAnalysis" />
    </applicationInitialization>

    <urlCompression doStaticCompression="true" doDynamicCompression="true" />

    <httpProtocol allowKeepAlive="true">
      <customerHeaders>
        <add name="Cache-Control" value="max-age=604800, private, public /">
      </customerHeaders>
    </httpProtocol>

    <staticContent>
      <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="7.00:00:00">
    </staticContent>

  </system.webServer>
</configuration>

```

## Output Caching Modes

Doing any of these cacheing mechanism's requires work to review each application
on what parts are static and dynamic.

Kernal Mode (http.sys)
  top choice
  Autentication and Authorization don't work here...
  full access to hardware and CPU and memory
  fastest, can execute mailicous code
  only allows static content

User Mode (w3wp.exe) Worker Processes
  IIS features and still caches so expensive db calls are cached..
  processes are run in container
  secured sand box


Type of Web Content for Kernal Mode (Static content)
  html
  javascript
  css
  images

dyanmic User Mode
  asp
  php
  cgi


semi dymanic (output cache'ing greatest affect)
  queries
  ORM operations

## How to setup output caching

IIS Server
    Output Caching
        Right click your server
        Right Click White Area
        Edit Feature Settings
            Select Enable Cache
            Enable kernal cache

            maximum output cache size to be stored

    Click on your site
    Select Output Caching
        Right click your server
        Right Click White Area
        Edit Feature Settings
            Select Enable Cache
            Enable kernal cache

Might need to setup kernal cache for the .js files.
.jpg, .css anything else?

What about any queries... maybe the data for each home
page that loads refreshed every morning in the AM, about
... 630AM, re-cycle the app pools and warm up all the pages
for the day.

Maybe setup caching to prevent cache for specific file
types.

PerfMon

Right click add counter, 
    processors, 
        % processor time

    web service cache
        current uri's cached

```xml

<system.web>
<outputCachesettings>
<profiles>
<add extension=".jpg" policy="CacheForTimePeriod" duration="00:10:00" />
</profiles>
</outputCachesettings>
</system.web>

--- another way

<configuration>
<location path="somepage.aspx">
<system.webserver>
<caching>
<profiles>
<add extension=".js" kernalCachePolicy="CacheForTimePeriod" duration="00:10:00" />
</profiles>
</caching>
</system.webserver>
</location>
</configuration>
```

POTENTIAL FIX TO MAKE IT LESS SECURE

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
 <system.webServer>
   <httpProtocol>
     <customHeaders>
       <add name="Access-Control-Allow-Origin" value="*" />
     </customHeaders>
   </httpProtocol>
 </system.webServer>
</configuration>
```
## Application Pool Settings

$AppPoolName = "AcmeWeb"

if(Test-Path IIS:\AppPools\$AppPoolName)
{
    $appPool = Get-Item IIS:\AppPools\$AppPoolName
    $appPool.managedRuntimeVersion = 'v4.0'
    $appPool.autoStart = 'true'
    $appPool.startmode = 'alwaysrunning'
    $appPool.managedPipelineMode = 'Integrated'
    $appPool.queueLength = 1000
    $appPool | Set-Item
}
else
{
  Write-Host "Application Pool" $AppPoolName "does not exist"
}

--     $appPool.queueLength = 50, in case we get flooded with request 
this helps reduce the amount of load

```shell

appcnd.exe list request

```

## Multitetnats

## Application Isolation in IIS

## Application Pool Tuning

Must recycle the time pool every night to keep it healty

    #Set-ItemProperty IIS:\AppPools\$AppPoolName -Name recycling.periodicRestart.schedule `
    #-Value @{value="01:00:00"}

## Analyzing your IIS secuity profile

Microsoft Securtiy Assement Tools

- Infrastructure
- Applications
- Operations
- People


## Microsoft Baseline Security Analyzer

Tools for securing server and IIS

## Checking Your IIS Servers for Vulnerabilities : Demo - Running the Microsoft Baseline Security Analyzer

download and run against the server.

## Checking Your IIS Servers for Vulnerabilities : Demo - Scanning for Open Ports

nmap - GUI zenamp

Command promot

netstat -ano | find /i "listening"
netstat -ano | find /i "listening" | ports.txt


port 3389 is the RDP session port

Note, always download locally and push files to the server.

## Secure IIS Server

content security polices
avoid content framed in another site of XSS

Http Response Headers

Name: X-Frame-Options
Value: SameOrigin

Name: Content-Security-Policy
options
Value: frame-ancestors 'none'
Value: frame-ancestors 'self'
Value: frame-ancestors 'www.trustedsite.com'


Name: Strict-Transport-Security
Value: 43200

Does not allow content that is not serverd over https to be served
refuses to conenct not allow content tobe sereved when certificate error
Use transport security for x seconds

Still need you need to changed your IIS to server https / SSL
Still your IIS might server a mix mode of no and ssl content

Strict-Transport-Security forces everthing to be loaded via SSL
regardless of how it is called.

Name: X-Content-Type-Options
Value: nosniff

Keep IIS from sniffing the file type to avoid malware

Name: X-Download-Options
Value: noopen

Don't open files immediately after download,security for your clients

Cross site scripting... protection...

Name: X-Content-Security-Policy
Value: default-src 'self' script-src ajax.googleapos.com analytics.google.com

options - owasp review tags
none - nothing is loaded
self - 
unsafe-inline
unsafe-eval

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>

    <applicationInitialization>
      <add initializationPage="/VoltageAnalysis" />
    </applicationInitialization>

    <urlCompression doStaticCompression="true" doDynamicCompression="true" />

    <httpProtocol allowKeepAlive="true">
      <customerHeaders>
        <add name="X-Frame-Options" value="SameOrigin"/>
      </customerHeaders>
    </httpProtocol>

    <staticContent>
      <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="7.00:00:00">
    </staticContent>

  </system.webServer>
</configuration>
```

### config dynamic ip restriction

stop brute force
Netling to send commands

protects agains brust force
and Denial of Service Attack

browser extension that runs macros to try and login to a page
Netling
https://github.com/hallatore/Netling


Dynamic IP Restrictions

- Brute Force protection
- DoS proection

Install the Dynamic IP restriction Module

Local Server > Add Roles and FEatures > Next
Role Bsed or feature based installation
web server, web server,  Secruity
IP and Domain Restirctions
next next install...

IIS Manager
 Server
    Site
        IP and Domain Restrictopns
        Edit Dynmaic Restirction
        Deny IP address based on the nuber of cuoncurrent request
        Deny IP Address based on the number of requests over a period of time/
        max number of requests

        Lots of options... 

        Edit FEature settings to return the type of response 
        we want to send...
        401
        404
        403 etc...

        You can block by specific IP address 
        Add Deny Entry... 

configure request filtering

so cool...

## Simple script to encrypt/decrypt a connection string

## Use this for a site or application

cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pe connectionStrings -app /acmebilling"
cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pd connectionStrings -app /acmebilling"

## If you've removed the "default web site" or renamed it, you must specify site 1

cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pe connectionStrings -app / -site 1"
cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pd connectionStrings -app / -site 1"

HTTP Error Codes

1xx - wait please, 101 switching protocols rarely seen
2xx - successful, all is good, it worked, 202 accepted like for async task
3xx - we're sending you somewhere else, redirects... 302 is temporary
4xx - you messed up, client error codes, 404 not found...
5xx - We messed up, server messed up... mis config, server unavial.

401 - unauthorized
403 - if you are forbidden to access an area of document
404.0 - not found
404.1 site not found
404.6 verb denied
404.14 - request url too long

TODO:
<customeErrors mode="RemoteOnly">

## Application Hanging and Timingout

1. Worker Processes

Virutal Bytes is shared and cached ...
Rt Click View Requests

> cd C:\windows\System32\inetserv

### List requested more than 30000 miliseconds

> C:\windows\System32\inetserv> appcmd list requests /elapsed:30000

ALSO 
Run as admin

choco install WestwindWebSurge


## Configuring IIS Logging
https://blogs.msdn.microsoft.com/webtopics/2010/03/19/iis-7-5-how-to-enable-iis-configuration-auditing/


### Formats

IIS by http.sys - fix format
time is stored as local time

NCSA - fixed text fields are spaced and time is in UTC

W3C similar to NCSA ... utc for time

binary... not widely used, but does save resource

custom - diabled logging and logging passed off the custom model

Logging levels

- Server
- per site at site level
- site level logging


Setup One Log file per SERVER for us.  Easier to ship.


<system.web>
    <trace enabled="true" localOnly="false" requestLimit="100" />
</system.web>


https://serverfault.com/questions/548007/improving-windows-authentication-performance-on-iis

Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> nltest /dclist:etss
Get list of DCs in domain 'etss' from '\\ETSS-DDC1'.
     etss-adc.etss.com        [DS] Site: Austin
      etss-dx.etss.com        [DS] Site: Default-First-Site-Name
     ETSS-DC6.etss.com        [DS] Site: Default-First-Site-Name
     ETSS-DC1.etss.com [PDC]  [DS] Site: Default-First-Site-Name
    etss-ddc1.etss.com        [DS] Site: Dallas
The command completed successfully


Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> nltest /dsgetdc:etss
           DC: \\ETSS-DDC1
      Address: \\10.86.1.20
     Dom Guid: c0f9ef5c-c9fa-41af-aeec-9ea51c686c67
     Dom Name: ETSS
  Forest Name: etss.com
 Dc Site Name: Dallas
Our Site Name: Dallas
        Flags: GC DS LDAP KDC TIMESERV WRITABLE DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9
The command completed successfully
PS C:\Windows\system32>

http://etss-demo-app.etss.com


## list the worker processes

> appcmd list wp
> appcmd list requests

## perform

Typically Categories
Also we need some baseline... too so do this during normal hours.

### Network

- Network Adapter
 -- Bytes Received/sec
 -- Bytes Sent/sec
 -- Bytes Total/sec

 -- Packets Outbound Discarded
 -- Packets Outbound Errors
 -- Packets Received Discarded
 -- Packets Received Errors
 -- Packets Received/sec
 -- Packets Sent/sec



### Physical Disk

- Physical Disk
 -- Add them all and Select the J:/

 Use check boxes to show and hide

### Memory

-- Add them All

-- Page Faults....
-- cached faults
-- Available Bytes - memory left over...
-- Available MBytes - memory left over...

### CPU

processor time

### Processes

w3wp....
add all counters and show and hide individually

sqlserver


## References

windows-authentication-http-request-flow-in-iis (This is good for seeing the flow you will see in Fidler and Wireshark)
https://blogs.technet.microsoft.com/mist/2018/02/14/windows-authentication-http-request-flow-in-iis/

improving-windows-authentication-performance-on-iis
https://serverfault.com/questions/548007/improving-windows-authentication-performance-on-iis

iis-7-5-how-to-enable-iis-configuration-auditing
https://blogs.msdn.microsoft.com/webtopics/2010/03/19/iis-7-5-how-to-enable-iis-configuration-auditing/

