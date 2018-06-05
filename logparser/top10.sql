Select Top 10
cs-uri-stem as [Request URI],
COUNT(*) AS Hits 
INTO top10pages.gif 
FROM C:\inetpub\logs\LogFiles\W3SVC1\*.log
Group by cs-uri-stem ORDER BY Hits DESC