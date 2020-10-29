# THE SECTION GETS THIS POWERSHELL INSTANCE AND ENSURES IT IS 'RUN AS ADMINISTRATOR' AND CHANGES COLOUR TO NOTIFY OF THIS
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($myWindowsPrincipal.IsInRole($adminRole)){
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
	$Host.UI.RawUI.BackgroundColor = "DarkBlue"
	clear-host
}else{
	$newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
	$newProcess.Arguments = $myInvocation.MyCommand.Definition;
	$newProcess.Verb = "runas";
	[System.Diagnostics.Process]::Start($newProcess);
	exit
}

#THE OU DEFINES WHERE IN THE DOMAIN AND GROUP POLICY THIS SERVER SHOULD RESIDE
$OU = 'OU=WSUS_Servers_Evening,OU=Servers,OU=Derry,OU=.EMEA,DC=aveva,DC=com'
$NewComputerName = Read-Host "Enter your new server name"
$NewComputerName = $NewComputerName.ToUpper()
If ($env:COMPUTERNAME -eq $NewComputerName){Add-Computer -DomainName aveva.com -ComputerName $env:COMPUTERNAME -OUPath $OU -Restart}
Else{Add-Computer -DomainName aveva.com -ComputerName $env:COMPUTERNAME -newname $NewComputerName.ToUpper() -OUPath $OU -Restart}
