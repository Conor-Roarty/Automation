########################################################################################
#   Funtion: Test-IsFileLocked                                                         #
#   Inputs:  Path To File                                                              #
#   Outputs: True if file is locked and cannot be accessed, false if it is free to use #
########################################################################################
Function Test-IsFileLocked {
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$True)]
        [string[]]$Path,
        [parameter(Mandatory=$False)]
        [string[]]$Processes
    )
    ####################################################################################################
    # Loop Through Paths and attempt to open and write to items just to test that they are not locked
    ####################################################################################################
    ForEach ($Item in $Path) {
        #Ensure this is a full path
        $Item = Convert-Path $Item
        #Verify that this is a file and not a directory
        If (Test-Path $Item) {
            Try {
                $FileStream = [System.IO.File]::Open($Item,'Open','Write')
                ##############################################################################
                # Ensure The Stream Is Close and Dispose Of, As To Not Create A Lock On Files
                ##############################################################################
                $FileStream.Close()
                $FileStream.Dispose()
                $IsLocked = "$False"
            } Catch [System.UnauthorizedAccessException] {
                $IsLocked += "AccessDenied on $Item"
            } Catch {
                ########################################################################################################
                # Stop all Usual processes that can cause locks on files such as unused DLLs, cmd.exe and text editors.
                ########################################################################################################
                Get-Process |
                Where-Object { ($_.Name.ToLower() -eq "notepad*") -or ($_.Name.ToLower() -eq "dllhost") -or ($_.Name.ToLower() -eq "dwm")`
                                -or ($_.Description.ToLower() -like "*excel*") -or ($_.Description.ToLower() -like "*word*") } |
                Stop-Process
                ##############################################################################################
                # Stop any process specifically stated by user in parameter $Processes, this can be left null
                ##############################################################################################
                if($Processes -ne $null){
                    foreach($Process in $Processes){
                        Get-Process |
                        Where-Object { ($_.Name.ToLower() -eq "$Process*") } |
                        Stop-Process
                    }
                }
                #########################################################################################
                # Stop All Control Panel Applet Tasks that are running in case they have locked the file
                #########################################################################################
                Get-ScheduledTask -TaskPath "*" | Where-Object {$_.State -eq 'Running'} | Stop-ScheduledTask -ErrorAction SilentlyContinue
                $IsLocked = "$True"
            }
            [pscustomobject]@{
                File = $Item
                IsLocked = $IsLocked
            }
        }
    }
    if($IsLocked){
        Write-Output "Lets Get Locked"
    }
}
