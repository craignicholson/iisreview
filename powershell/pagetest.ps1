# Replace with your URL
$url = 'http://www.acmewidgetcorp.com' 

# This invokes a web request and measures the amount of time it takes
$timeTaken = Measure-Command -Expression {
  $site = Invoke-WebRequest -Uri $url
}

# This rounds down the number
$seconds = [Math]::Round($timeTaken.TotalSeconds, 4)

# Then we display it
"The page took $seconds seconds to load"