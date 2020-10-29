############################################################################################################
# This Cleans Up Unnessecary File.                                                                         #
# We do not use any Credentials for this so that secure and needed files cannot be deleted                 #
#                                                                                                          #
# Inputs:  The types of files to be deleted and directories.                                               #
# Outputs: Increased Space on Disk                                                                         #
############################################################################################################

# If Out Output log does not exist create it
if(!(Test-Path C:\PerfLogs\ClearUp.txt)){
    New-Item -ItemType File -Path C:\PerfLogs\ClearUp.txt
}
# Clear old content to make room for todays logs
Clear-Content C:\PerfLogs\ClearUp.txt

# Get status before clean up tasks
$Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName,  
@{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } }, 
@{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}}, 
@{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } }, 
@{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } | 
Format-Table -AutoSize | Out-File C:\PerfLogs\ClearUp.txt -Append

# Stop Windows Update Service as this interupts with cleanup in places
Get-Service -Name wuauserv | Stop-Service -Verbose -ErrorAction SilentlyContinue

# Clear Out Old Logs
Get-ChildItem C:\ -Recurse | Where-Object {$_.FullName -like "*.log" -and $_.FullName -notlike "C:\IMPORTANTDIRECTORY*" } -ErrorAction Ignore | Remove-Item -Recurse -Force

# Clear Out Old Txt Files
Get-ChildItem C:\ -Recurse | Where-Object {$_.FullName -like "*.txt" -and $_.FullName -notlike "C:\IMPORTANTDIRECTORY*" } -ErrorAction Ignore | Remove-Item -Recurse -Force -ErrorAction Ignore

# Clear Out Annoying BodyPart Files
Get-ChildItem C:\ -Recurse | Where-Object {$_.FullName -like "*BodyPart*" -and $_.FullName -notlike "C:\IMPORTANTDIRECTORY*" } -ErrorAction Ignore | Remove-Item -Recurse -Force

# Clear Out Cache Files
Get-ChildItem C:\Windows\ccmcache -Recurse -ErrorAction Ignore | Remove-Item -Force

# Clear Out SoftwareDistribution Files that are not needed
Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue 

# Clear Out Temp Files that are currently being used or arent needed
Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | 
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-2)) } | 
remove-item -Force -Verbose -Recurse -ErrorAction SilentlyContinue 

# Clear Out All Users Old App Data
Get-ChildItem "C:\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | 
Where-Object { ($_.CreationTime -lt $(Get-Date).AddDays(-2))} | 
remove-item -force -Verbose -Recurse -ErrorAction SilentlyContinue 

# Clear Out All Users Old Internet Files
Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | 
Where-Object {($_.CreationTime -le $(Get-Date).AddDays(-2))} | 
remove-item -force -Recurse -ErrorAction SilentlyContinue 

# Clear Out IIS Logs
Get-ChildItem "C:\inetpub\logs\LogFiles\*" -Recurse -Force -ErrorAction SilentlyContinue | 
Where-Object { ($_.CreationTime -le $(Get-Date).AddDays(-5)) } | 
Remove-Item -Force -Verbose -Recurse -ErrorAction SilentlyContinue

# Clear Out Recycle Bin
Get-ChildItem -Path 'C:\$Recycle.Bin' -Force -Recurse | Remove-Item -force -Recurse -ErrorAction SilentlyContinue

Get-Service -Name wuauserv | Start-Service -Verbose -ErrorAction SilentlyContinue

$After = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName, 
@{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } }, 
@{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}}, 
@{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } }, 
@{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } | 
Format-Table -AutoSize | Out-File C:\PerfLogs\ClearUp.txt -Append