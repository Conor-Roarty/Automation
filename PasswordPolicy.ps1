$config = "C:\temp.cfg";

secedit /export /cfg $config;

$contents = Get-Content -Path $config;

$contents = $contents -replace "PasswordComplexity = 1", "PasswordComplexity = 0";
$contents = $contents -replace "MinimumPasswordLength = 10", "MinimumPasswordLength = 1";
$contents = $contents -replace "MaximumPasswordAge = 180", "MaximumPasswordAge = 1800000";

Set-Content -Path $config -Value $contents;

secedit /configure /db C:\Windows\security\new.sdb /cfg $config /areas SECURITYPOLICY

Remove-Item $config;