# Script to encrypt a connection string

# Use this for a site or application
cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pe connectionStrings -app /green"

# If you've removed the "default web site" or renamed it, you must specify site 1
#cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pe connectionStrings -app / -site 1"


cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pd connectionStrings -app /green"

# If you've removed the "default web site" or renamed it, you must specify site 1
#cmd /c "%windir%\Microsoft.NET\Framework\v4.0.30319\aspnet_regiis.exe -pd connectionStrings -app / -site 1"

# References:  
# Encrypt - https://msdn.microsoft.com/en-us/library/zhhddkxy.aspx
# Decrypt - https://msdn.microsoft.com/en-us/library/bb986792.aspx
