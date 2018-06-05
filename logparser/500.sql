SELECT Text as LineFromFile
FROM C:\inetpub\logs\LogFiles\W3SVC1\*.log 
WHERE Text 
LIKE '%500 0 0%'