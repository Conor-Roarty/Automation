$RequiredAssemblies = @("Microsoft.TeamFoundation.Client", "Microsoft.TeamFoundation.VersionControl.Client");
foreach ($assembly in $RequiredAssemblies) {
    try {
		Add-Type -Path "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\$assembly.dll" -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Error loading TFS assemblies";
        pause;
        exit;
    }
}

$TfsConnectionString = "http://tfs2013:8080/tfs/8over8Collection";
$TeamProjectCollection = [Microsoft.TeamFoundation.Client.TfsTeamProjectCollectionFactory]::GetTeamProjectCollection($TfsConnectionString);
$VersionControlServer = $TeamProjectCollection.GetService("Microsoft.TeamFoundation.VersionControl.Client.VersionControlServer");
$Workspace = $VersionControlServer.QueryWorkspaces(
    [System.Management.Automation.Language.NullString]::Value,
    [System.Management.Automation.Language.NullString]::Value,
    $Env:ComputerName
) | Select-Object -First 1;

$Shelveset = New-Object Microsoft.TeamFoundation.VersionControl.Client.ShelveSet($VersionControlServer, "TFS Backup $([DateTime]::Now.ToString("yyyy-MM-dd"))", $Workspace.OwnerName);
$VersionControlServer.QueryShelvesets($Shelveset.Name, $Shelveset.OwnerName) | ForEach-Object {
    $VersionControlServer.DeleteShelveset($_);
};

$ShelvesetDate = [DateTime]::Now;
$ExistingBackups = @{};
$VersionControlServer.QueryShelvesets(
    [System.Management.Automation.Language.NullString]::Value,
    $Env:UserName
) | Where-Object {
    return $_.Name -match '^TFS Backup (?<Date>\d\d\d\d\-\d\d\-\d\d)$' -and
           [DateTime]::TryParseExact(
               $Matches.Date,
               "yyyy-MM-dd",
               [System.Globalization.CultureInfo]::InvariantCulture,
               [System.Globalization.DateTimeStyles]::None,
               [ref] $ShelvesetDate
           );
} | ForEach-Object {
    $ExistingBackups[$ShelvesetDate] = $_;
};

$ExistingBackups.Keys | Sort-Object -Descending | Select-Object -Skip 2 | ForEach-Object {
    $VersionControlServer.DeleteShelveset($ExistingBackups[$_]);
};

$Workspace.Shelve(
    $Shelveset,
    $Workspace.GetPendingChanges(),
    [Microsoft.TeamFoundation.VersionControl.Client.ShelvingOptions]::None
);