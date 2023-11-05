#Connect Exchange Powershell First https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps

$csv = Import-CSV 'YOUR CSV'

foreach($line in $csv){
    $url = $line.IndicatorValue 
    New-TenantAllowBlockListItems -ListType Sender -Block -Entries $url -NoExpiration -Notes "DNS Twist Block"
}
