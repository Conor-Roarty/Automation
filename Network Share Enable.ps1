$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
$name = "NC_ShowSharedAccessUI";
$value = 1;

if (Test-Path -Path $registryPath) {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null;
    Write-Host "Registry Entry Updated.";
    Write-Host "Network Sharing Enabled.";
} else {
    Write-Host "Registry Entry not found.";
}