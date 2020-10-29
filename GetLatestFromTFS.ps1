Add-PSSnapin Microsoft.TeamFoundation.PowerShell;
if (!$?) {
    Write-Error "You must install the TFS Power Tools cmdlets to use this script.";
    pause;
    exit;
}

$rootPath = $env:PROCON_HOME;
$workspaces = @("Build", "Source\Main", "Source\Core", "Source\Analytics"); #sample workspaces

foreach ($workspace in $workspaces) {
	if (Test-Path "$rootPath\$workspace") {
		Write-Progress -Activity "Getting latest files from source control" -Status "$rootPath\$workspace" -PercentComplete $($workspaces.IndexOf($workspace) / $workspaces.Count * 100);
		Update-TfsWorkspace -Recurse "$rootPath\$workspace" | Out-Null;
	}
}
Write-Progress -Activity "Getting latest files from source control" -Completed;
Write-Host ("All files up to date" + [Environment]::NewLine);