$connString = $(Get-SBAuthorizationRule -NamespaceName "ServiceBusDefaultNamespace").ConnectionString
Get-ChildItem -Path "<LOCAL WORKSPACE PATH TO BRANCH>" -Include App.config, Web.config, ProConWebAppSettings.config -Recurse | ? {
    $xml = [xml](Get-Content -Path $_.FullName);
    return $xml -ne $null -and $xml.SelectSingleNode("//appSettings/add[@key='Microsoft.ServiceBus.ConnectionString']") -ne $null;
} | % {
    sp $_.FullName IsReadOnly $false;
    [System.IO.File]::WriteAllText(
        $_.FullName,
        $([System.IO.File]::ReadAllText($_.FullName) -ireplace '(?<=add\s*key="Microsoft.ServiceBus.ConnectionString"\s*value=")[^"]+(?="\s*/>)', $connString));
};