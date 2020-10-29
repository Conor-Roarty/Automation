####################################################################################################################################################################
#
# RUN FROM SERVER WITH REQUIRED CAPABILITIES 
# i.e.to avoid "The Windows PowerShell snap-in 'Microsoft.TeamFoundation.PowerShell' is not installed on this computer."
#
#####################################################################################################################################################################
Param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [int]$ID
)
Import-Module WebAdministration
Set-ExecutionPolicy Unrestricted -Force -ErrorAction Continue
Add-PSSnapin Microsoft.TeamFoundation.PowerShell
$tfsServer="http://tfs2013:8080/tfs"
$tfs=get-tfsserver $tfsServer
$WIT = $tfs.GetService([Microsoft.TeamFoundation.WorkItemTracking.Client.WorkItemStore])
$item = $WIT.GetWorkItem(317928) 
foreach($i in $item.Links)
{
    $WIT.GetWorkItem($i.RelatedWorkItemId) #.LinkTypeEnd.Name #here it says is it 'Parent' or 'Child' 
}