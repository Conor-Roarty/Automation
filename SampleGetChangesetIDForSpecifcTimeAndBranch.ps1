## Non-Practical way of finding changeset ID and associated workitem, 
### Should NOT be used in final work

[string] $tfsCollectionPath = "URL TO COLLECTION IN TFS"
[Microsoft.TeamFoundation.Client.TfsTeamProjectCollection] $tfs = get-tfsserver $tfsCollectionPath
$loc = "<PATH TO BRANCH AND FOLDER YOU WANT HISTORY OF>"
$Date = (Get-Date).AddMinutes(-2).ToString("dd/MM/yyyy hh:mm:ss")
[string] $dateRange = "D" + $Date +"Z~" 
Get-TfsItemHistory $loc -Server $tfs -Version $dateRange -Recurse -IncludeItems |  Select ChangesetId -exp WorkItems |  Format-Table Id,Title -GroupBy ChangesetId -Auto