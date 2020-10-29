param(
    [Parameter(Mandatory=$true)]
    [Alias("Name","CN","Computer")]
    [string]$ComputerName
)

function GetName([string]$Name) {
    if ($Name.StartsWith("VM", [StringComparison]::CurrentCultureIgnoreCase) -or $Name.StartsWith("SERVER", [StringComparison]::CurrentCultureIgnoreCase)) {
        return $Name;
    }

    return "$Name";
}

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "<DOMAIN>\QA", $(ConvertTo-SecureString "password" -AsPlainText -Force);

Invoke-Command -ComputerName $(GetName $ComputerName) -Credential $credential -ScriptBlock {
    $dbMapping = @{
        "Ben" = "BEN_Upgrade";
        "Benbaun" = "BENBAUN_Upgrade";
        "Caher" = "CAHER";
        "Callan" = "CALLAN_Upgrade";
        "Djouce" = "DJOUCE_Upgrade";
        "Trostan" = "TROSTAN";
        "DEVOPS" = "DEVOPS_UPGRADEDB";
        "QA03" = "QA03_Upgrade";
    };

    $dbName = $dbMapping[$env:ComputerName];
    if ($dbName -like $null) {
        Write-Host "No db mapping found for $env:ComputerName";
        $dbName = Read-Host "Enter the db name for $env:ComputerName. Alternatively press Ctrl+C to exit";

        if ($dbName -like $null) {
            exit;
        }
    }

    Write-Host "Database found. Extending timeout to 7 days.";
    $sqlQuery = "UPDATE o SET o.SessionTimeout = 10080 FROM dbo.Organisation o WHERE o.Organisation_Id = 1;";
    Invoke-Sqlcmd -Query $sqlQuery -ServerInstance "Croob" -Database $dbName -Username "fakeuser" -Password "password";    
    Write-Host "Timeout extended.";
};
pause;