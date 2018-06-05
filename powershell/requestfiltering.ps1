Import-Module WebAdministration

# Note that this script is simply a list of appcmd executions, you can add error handling and special output to make it more robust

# Remove high bit chars and disallow double escaping
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowhighbitcharacters:false"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /allowDoubleEscaping:false"

# Allow unlisted file extensions ( to specify what to deny )
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering/fileExtensions.allowunlisted:true"

# A collection of file name extensions I like to deny
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.back',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.bak',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.bat',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.bas',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.cer',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.cfg',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.com',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.config',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.dat',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.dll',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.exe',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.fcgi',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.jsp',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.log',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.mdb',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.pfx',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.php',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.php3',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.ps1',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.sql',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.tmp',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.vbe',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+fileExtensions.[fileextension='.vbs',allowed='false']"

# Allow unlisted verbs ( to specify what to deny )
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /verbs.allowunlisted:true"

# Apply to WebDAV
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /verbs.applyToWebDAV:true"

# Disallowed verbs
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='PROPPATCH',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='MKCOL',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='DELETE',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='PUT',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='COPY',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='MOVE',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='LOCK',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='TRACE',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='UNLOCK',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='OPTIONS',allowed='false']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+verbs.[verb='SEARCH',allowed='false']"

# Disallowed sequences
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='..']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='./']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence='\']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence=';:']"
cmd /c "%windir%\system32\inetsrv\appcmd.exe set config /section:requestfiltering /+denyurlsequences.[sequence=`"';&'`"]"