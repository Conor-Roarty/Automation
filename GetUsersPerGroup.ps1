$Servers = $Env:COMPUTERNAME
$Groups = Get-WMIObject win32_group -filter "LocalAccount='$true'" -computername $Env:COMPUTERNAME | select name

$Servers | ForEach-Object{ $Server=$_ 
            Get-WMIObject win32_group -filter 'LocalAccount=True' -computername $Env:COMPUTERNAME |
            ForEach-Object{
                $localgroup = $_.Name
                $Group = [ADSI]"WinNT://$Env:COMPUTERNAME/$LocalGroup,group"
                $Members = @($Group.psbase.Invoke("Members"))
                $Members | ForEach-Object{
                    $MemberNames= @($_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null))
                    
                    Foreach ($Member in $MemberNames) {
                        $props=[ordered]@{
                            Server = $Env:COMPUTERNAME
                            LocalGroup = $localgroup
                            Member = $Member
                        }
                        New-Object PsCustomObject -Property $props          
                }
            }
        }
    }