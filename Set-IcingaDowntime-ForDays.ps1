Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [int]$Days
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$start_time = Get-Date -UFormat %s
$end_time = Get-Date (Get-Date).AddDays($Days) -UFormat %s
  
# Authentication
$bytes = [System.Text.Encoding]::ASCII.GetBytes($env:ICINGA_CREDENTIALS)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
    
# Icinga stuff
$Uri = "http://<subdomain>.<domain>.com:5665/v1/actions/schedule-downtime?type=Service&filter=host.name==%22$env:COMPUTERNAME.<domain>.com%22"
$headers = @{ "Authorization" = "$basicAuthValue"; "Accept" = "application/json" }
$body = @{
    author          = 'DevOps'
    comment         = 'Deploying ProCon'
    fixed           = "0.00"
    duration        = 90
    apply_to        = "hosts"
    start_time      = "$start_time"
    end_time        = "$end_time"
    #all_services    = "true"
}
$body = $body | ConvertTo-Json
   
# Schedule the downtime
Invoke-RestMethod -Headers $headers -Uri $Uri -Method Post -ContentType 'application/json' -Body $body