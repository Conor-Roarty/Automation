$sqlServer=$false
Write-Output "DSC Completed Settings"
    
    Write-Output "DisableUserAuth"
    if(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AutoAdminLogon -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AutoAdminLogon).AutoAdminLogon -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AutoAdminLogon -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AutoAdminLogon -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AutoAdminLogon -Value 0 -PropertyType DWORD
    }

    Write-Output "DisableIpSourceRoutingIPv6"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting).DisableIpSourceRouting -eq 2){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -Value 2
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -Value 2 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -Value 2 -PropertyType DWORD
    }
    Write-Output "DisableIpSourceRouting"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIpSourceRouting -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIpSourceRouting).DisableIpSourceRouting -eq 2){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIpSourceRouting -Value 2
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIpSourceRouting -Value 2 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIpSourceRouting -Value 2 -PropertyType DWORD
    }
    Write-Output "SafeDllSearchMode"
    if(Test-Path "HKLM:\System\CurrentControlSet\Control\Session Manager\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Name SafeDllSearchMode -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Name SafeDllSearchMode).SafeDllSearchMode -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Name SafeDllSearchMode -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Name SafeDllSearchMode -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\" -Name SafeDllSearchMode -Value 1 -PropertyType DWORD
    }

    Write-Output "NoGPOListChanges"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges).NoGPOListChanges -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" -Name NoGPOListChanges -Value 0 -PropertyType DWORD
    }

    Write-Output "DisallowExploitProtectionOverride"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Name DisallowExploitProtectionOverride -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Name DisallowExploitProtectionOverride).DisallowExploitProtectionOverride -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Name DisallowExploitProtectionOverride -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Name DisallowExploitProtectionOverride -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection\" -Name DisallowExploitProtectionOverride -Value 1 -PropertyType DWORD
    }

    Write-Output "DisableUserAuth"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Name DisableUserAuth -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Name DisableUserAuth).DisableUserAuth -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Name DisableUserAuth -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Name DisableUserAuth -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount\" -Name DisableUserAuth -Value 1 -PropertyType DWORD
    }

    Write-Output "MitigationOptions_FontBocking"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Name MitigationOptions_FontBocking -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Name MitigationOptions_FontBocking).MitigationOptions_FontBocking -eq "1000000000000"){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Name MitigationOptions_FontBocking -Value "1000000000000"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Name MitigationOptions_FontBocking -Value "1000000000000" -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\" -Name MitigationOptions_FontBocking -Value "1000000000000" -PropertyType DWORD
    }

    Write-Output "AllowInsecureGuestAuth"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth).AllowInsecureGuestAuth -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -Value 0 -PropertyType DWORD
    }

    Write-Output "DisableBehaviorMonitoring"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Name DisableBehaviorMonitoring -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Name DisableBehaviorMonitoring).DisableBehaviorMonitoring -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Name DisableBehaviorMonitoring -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Name DisableBehaviorMonitoring -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\" -Name DisableBehaviorMonitoring -Value 0 -PropertyType DWORD
    }

    Write-Output "NETBIOS P-Node NoNameReleaseOnDemand"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand).NoNameReleaseOnDemand -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NoNameReleaseOnDemand -Value 1 -PropertyType DWORD
    }
    Write-Output "NETBIOS P-Node NodeType"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NodeType -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NodeType).NodeType -eq 2){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NodeType -Value 2
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NodeType -Value 2 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -Name NodeType -Value 2 -PropertyType DWORD
    }
    Write-Output "SmbServerNameHardeningLevel"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SmbServerNameHardeningLevel -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SmbServerNameHardeningLevel).SmbServerNameHardeningLevel -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SmbServerNameHardeningLevel -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SmbServerNameHardeningLevel -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SmbServerNameHardeningLevel -Value 1 -PropertyType DWORD
    }
    Write-Output "mrxsmb10 SMBv1"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Name Start -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Name Start).Start -eq 4){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Name Start -Value 4
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Name Start -Value 4 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\" -Name Start -Value 4 -PropertyType DWORD
    }
    Write-Output "SmbServerDisable"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1 -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1).SMB1 -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1 -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1 -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1 -Value 0 -PropertyType DWORD
    }
    Write-Output 'DependOnService "Bowser", "MRxSmb20", "NSI"'
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\" -Name DependOnService).DependOnService[0] -eq "Bowser"){
                if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\" -Name DependOnService).DependOnService[1] -eq "MRxSmb20"){
                    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\" -Name DependOnService).DependOnService[2] -eq "NSI"){
			            Write-Output "Already Correct"
                    } else {
                        Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -Value "Bowser", "MRxSmb20", "NSI"
                    }
                }else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -Value "Bowser", "MRxSmb20", "NSI"
                }
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -Value "Bowser", "MRxSmb20", "NSI"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -PropertyType MultiString -Value "Bowser", "MRxSmb20", "NSI"
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -Name DependOnService -PropertyType MultiString -Value "Bowser", "MRxSmb20", "NSI"
    }

    Write-Output "AdmPwdEnabled"
    if(Test-Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name AdmPwdEnabled -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name AdmPwdEnabled).AdmPwdEnabled -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name AdmPwdEnabled -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name AdmPwdEnabled -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name AdmPwdEnabled -Value 1 -PropertyType DWORD
    }

    Write-Output "PasswordComplexity"
    if(Test-Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordComplexity -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordComplexity).PasswordComplexity -eq 4){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordComplexity -Value 4
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordComplexity -Value 4 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordComplexity -Value 4 -PropertyType DWORD
    }
    Write-Output "PasswordLength"
    if(Test-Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordLength -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordLength).PasswordLength -eq 15){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordLength -Value 15
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordLength -Value 15 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordLength -Value 15 -PropertyType DWORD
    }
    Write-Output "PasswordAgeDays"
    if(Test-Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordAgeDays -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordAgeDays).PasswordAgeDays -eq 30){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordAgeDays -Value 30
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordAgeDays -Value 30 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PasswordAgeDays -Value 30 -PropertyType DWORD
    }
    Write-Output "PwdExpirationProtectionEnabled"
   if(Test-Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PwdExpirationProtectionEnabled -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PwdExpirationProtectionEnabled).PwdExpirationProtectionEnabled -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PwdExpirationProtectionEnabled -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PwdExpirationProtectionEnabled -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -Name PwdExpirationProtectionEnabled -Value 1 -PropertyType DWORD
    }
    if (-not $sqlServer) {
        Write-Output "FilterAdministratorToken Null For Web Server"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -ErrorAction Ignore) -eq $null){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; 
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -Value $null
            }
        }
    } else {
        Write-Output "FilterAdministratorToken should be 1 For SQL Server"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken).FilterAdministratorToken -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -Value 1 -PropertyType DWORD
        }
    }

    Write-Output "EnableAuthEpResolution"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution).EnableAuthEpResolution -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1 -PropertyType DWORD
    }

    Write-Output "ManagePreviewBuildsPolicyValue"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue).ManagePreviewBuildsPolicyValue -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuildsPolicyValue -Value 0 -PropertyType DWORD
    }

    Write-Output "ManagePreviewBuilds"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuilds -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuilds).ManagePreviewBuilds -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuilds -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuilds -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name ManagePreviewBuilds -Value 1 -PropertyType DWORD
    }

    Write-Output "DisableAntiSpyware"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware).DisableAntiSpyware -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -Value 0 -PropertyType DWORD
    }

    Write-Output "MpEnablePus"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Name MpEnablePus -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Name MpEnablePus).MpEnablePus -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Name MpEnablePus -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Name MpEnablePus -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine\" -Name MpEnablePus -Value 1 -PropertyType DWORD
    }

    Write-Output "TcpMaxDataRetransmissionsIPv6"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name TcpMaxDataRetransmissions -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name TcpMaxDataRetransmissions).TcpMaxDataRetransmissions -eq 3){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name TcpMaxDataRetransmissions -Value 3
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name TcpMaxDataRetransmissions -Value 3 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -Name TcpMaxDataRetransmissions -Value 3 -PropertyType DWORD
    }
    Write-Output "TcpMaxDataRetransmissions"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name TcpMaxDataRetransmissions -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name TcpMaxDataRetransmissions).TcpMaxDataRetransmissions -eq 3){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name TcpMaxDataRetransmissions -Value 3
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name TcpMaxDataRetransmissions -Value 3 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name TcpMaxDataRetransmissions -Value 3 -PropertyType DWORD
    }

    Write-Output "PerformRouterDiscovery"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name PerformRouterDiscovery -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name PerformRouterDiscovery).PerformRouterDiscovery -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name PerformRouterDiscovery -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name PerformRouterDiscovery -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name PerformRouterDiscovery -Value 0 -PropertyType DWORD
    }

    Write-Output "DisableEnterpriseAuthProxy"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DisableEnterpriseAuthProxy -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DisableEnterpriseAuthProxy).DisableEnterpriseAuthProxy -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DisableEnterpriseAuthProxy -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DisableEnterpriseAuthProxy -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DisableEnterpriseAuthProxy -Value 1 -PropertyType DWORD
    }

    Write-Output "WarningLevel"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Name WarningLevel -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Name WarningLevel).WarningLevel -eq 90){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Name WarningLevel -Value 90
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Name WarningLevel -Value 90 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" -Name WarningLevel -Value 90 -PropertyType DWORD
    }

    Write-Output "Wdigest"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential).UseLogonCredential -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -Value 0 -PropertyType DWORD
    }

    Write-Output "NetworkProtection"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Name EnableNetworkProtection -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Name EnableNetworkProtection).EnableNetworkProtection -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Name EnableNetworkProtection -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Name EnableNetworkProtection -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\" -Name EnableNetworkProtection -Value 1 -PropertyType DWORD
    }

    Write-Output "PreXPSP2ShellProtocolBehavior"
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior).PreXPSP2ShellProtocolBehavior -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -Value 0 -PropertyType DWORD
    }

    Write-Output "LocalAccountTokenFilterPolicy"
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy).LocalAccountTokenFilterPolicy -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -Value 0 -PropertyType DWORD
    }
    
    Write-Output "AllowProtectedCreds"
	if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds).AllowProtectedCreds -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -Value 1 -PropertyType DWORD
    }	        

Write-Output "GPO Completed Settings"
#region GPO CIS Security Standards
    Write-Output "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name restrictremotesam -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name restrictremotesam).restrictremotesam -eq "O:BAG:BAD:(A;;RC;;;BA)"){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name restrictremotesam -Value "O:BAG:BAD:(A;;RC;;;BA)"
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name restrictremotesam -Value "O:BAG:BAD:(A;;RC;;;BA)" -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name restrictremotesam -Value "O:BAG:BAD:(A;;RC;;;BA)" -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' RestrictAnonymousSAM "
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM).RestrictAnonymousSAM  -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' RestrictAnonymous"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous).RestrictAnonymous -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec).NTLMMinServerSec -eq 537395200){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -Value 537395200
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -Value 537395200 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -Value 537395200 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId).UseMachineId -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name UseMachineId -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback).allownullsessionfallback -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name allownullsessionfallback -Value 0 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name SupportedEncryptionTypes -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters\" -Name supportedencryptiontypes).supportedencryptiontypes -eq 2147483640){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name supportedencryptiontypes -Value 2147483640
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name supportedencryptiontypes -Value 2147483640 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name supportedencryptiontypes -Value 2147483640 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM&NTLM'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel).LmCompatibilityLevel -eq 5){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -Value 5
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -Value 5 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -Value 5 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec).NTLMMinClientSec -eq 537395200){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -Value 537395200
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -Value 537395200 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -Value 537395200 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin -eq 2){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -Value 2
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -Value 2 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -Value 2 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser).ConsentPromptBehaviorUser -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser -Value 0 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
        if(Test-Path "HKLM:\System\CurrentControlSet\Control\Lsa\"){
	        if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy).SCENoApplyLegacyAuditPolicy -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Control\Lsa\" -Force
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWORD
        }
         
    Write-Output "Configure 'Interactive logon: Message text for users attempting to log on'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticetext -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticetext).legalnoticetext -like "This system is restricted to authorized users. Individuals who attempt unauthorized access will be prosecuted. If you are una*"){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticetext -Value "This system is restricted to authorized users. Individuals who attempt unauthorized access will be prosecuted. If you are unauthorized, terminate access now. Click OK to indicate your acceptance of this information."
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticetext -Value "This system is restricted to authorized users. Individuals who attempt unauthorized access will be prosecuted. If you are unauthorized, terminate access now. Click OK to indicate your acceptance of this information." -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticetext -Value "This system is restricted to authorized users. Individuals who attempt unauthorized access will be prosecuted. If you are unauthorized, terminate access now. Click OK to indicate your acceptance of this information." -PropertyType DWORD
        }
        
    Write-Output "Configure 'Interactive logon: Message title for users attempting to log on'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticecaption -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticecaption).legalnoticecaption -like "WARNING: This system is restricted to authorized users."){
			       Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticecaption -Value "WARNING: This system is restricted to authorized users."
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticecaption -Value "WARNING: This system is restricted to authorized users." -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name legalnoticecaption -Value "WARNING: This system is restricted to authorized users." -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature).RequireSecuritySignature -eq 1){
			       Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature).RequireSecuritySignature -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -Value 1 -PropertyType DWORD
    }
    Write-Output "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature).EnableSecuritySignature -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name EnableSecuritySignature -Value 1 -PropertyType DWORD
    }
        


    Write-Output "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name EnableFirewall -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name EnableFirewall).EnableFirewall -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name EnableFirewall -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultInboundAction -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultInboundAction).DefaultInboundAction -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultInboundAction -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFilePath -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFilePath).LogFilePath -like "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log"){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log" -PropertyType String
    }
        
    Write-Output "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFileSize -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFileSize).LogFileSize -ge 16384){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFileSize -Value 16384
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
    }
        

    Write-Output "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogSuccessfulConnections -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogSuccessfulConnections).LogSuccessfulConnections -eq 1){
			       Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogSuccessfulConnections -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
        }
        


    Write-Output "Private Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name EnableFirewall -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name EnableFirewall).EnableFirewall -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name EnableFirewall -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Private Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DefaultInboundAction -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DefaultInboundAction).DefaultInboundAction -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DefaultInboundAction -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Private Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFilePath -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFilePath).LogFilePath -like "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log"){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log" -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log" -PropertyType String
    }

    Write-Output "1. Private Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFileSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFileSize).LogFileSize -ge 16384){
			        Write-Output "Already Correct"
		        } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFileSize -Value 16384
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
    }    
    Write-Output "2. Private Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogFileSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogFileSize).LogFileSize -ge 16384){
			        Write-Output "Already Correct"
		        } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogFileSize -Value 16384
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
    }
    
    Write-Output "Private Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogSuccessfulConnections -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogSuccessfulConnections).LogSuccessfulConnections -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogSuccessfulConnections -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
        }
        


    Write-Output "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name EnableFirewall -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name EnableFirewall).EnableFirewall -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name EnableFirewall -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name EnableFirewall -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DefaultInboundAction -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DefaultInboundAction).DefaultInboundAction -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DefaultInboundAction -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DefaultInboundAction -Value 1 -PropertyType DWORD
        }
        
    Write-Output "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFilePath -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFilePath).LogFilePath -like "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log"){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log"
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" -PropertyType String
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFilePath -Value "%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" -PropertyType String
        }
        

    Write-Output "1. Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
        $PublicLogFileSize  = $false
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFileSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFileSize).LogFileSize -ge 16384){
			        $PublicLogFileSize = $true
                    Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFileSize -Value 16384
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
        }
        

    if($PublicLogFileSize -eq $false){
        Write-Output "2. Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
            if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\"){
	            if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogFileSize -ErrorAction Ignore) -ne $null){
		            if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogFileSize).LogFileSize -ge 16384){
			            Write-Output "Already Correct"
		            } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogFileSize -Value 16384
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogFileSize -Value 16384 -PropertyType DWORD
        }
    }
    Write-Output "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogSuccessfulConnections -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogSuccessfulConnections).LogSuccessfulConnections -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogSuccessfulConnections -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogSuccessfulConnections -Value 1 -PropertyType DWORD
        } 




    Write-Output "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge).MaximumPasswordAge -eq 30){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 30
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 30 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 30 -PropertyType DWORD
    }
        
    Write-Output "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_AllowNetBridge_NLA -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_AllowNetBridge_NLA).NC_AllowNetBridge_NLA -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_AllowNetBridge_NLA -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_AllowNetBridge_NLA -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_AllowNetBridge_NLA -Value 0 -PropertyType DWORD
    }
        

    Write-Output "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI).NC_ShowSharedAccessUI -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_StdDomainUserSetLocation -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_StdDomainUserSetLocation).NC_StdDomainUserSetLocation -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_StdDomainUserSetLocation -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_StdDomainUserSetLocation -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\" -Name NC_StdDomainUserSetLocation -Value 1 -PropertyType DWORD
        }
        


    Write-Output "Ensure 'Continue experiences on this device' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp).EnableCdp -eq 0){
			      Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload).DisableWebPnPDownload -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices).NoWebServices -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Force
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin).BlockUserFromShowingAccountDetailsOnSignin -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Do not display network selection UI' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI).DontDisplayNetworkSelectionUI -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers).EnumerateLocalUsers -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnumerateLocalUsers -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnumerateLocalUsers -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnumerateLocalUsers -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowUnsolicited -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowUnsolicited).fAllowUnsolicited -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowUnsolicited -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowUnsolicited -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowUnsolicited -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp).fAllowToGetHelp -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' EnableAuthEpResolution"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution).EnableAuthEpResolution -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name EnableAuthEpResolution -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' RestrictRemoteClients"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients).RestrictRemoteClients -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name EnhancedAntiSpoofing -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name EnhancedAntiSpoofing).EnhancedAntiSpoofing -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Name EnhancedAntiSpoofing -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Name EnhancedAntiSpoofing -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Name EnhancedAntiSpoofing -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures).DisableWindowsConsumerFeatures -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\" -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators).EnumerateAdministrators -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name EnableConfigFlighting -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name EnableConfigFlighting).EnableConfigFlighting -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name EnableConfigFlighting -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name EnableConfigFlighting -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name EnableConfigFlighting -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Tooggle user cntrol over Insider builds' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name AllowBuildPreview -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name AllowBuildPreview).AllowBuildPreview -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name AllowBuildPreview -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name AllowBuildPreview -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds\" -Name AllowBuildPreview -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name Retention -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name Retention).Retention -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name Retention -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name Retention -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\" -Name Retention -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name Retention -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name Retention).Retention -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name Retention -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name Retention -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" -Name Retention -Value 0 -PropertyType DWORD
    }
        

    Write-Output "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name Retention -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name Retention).Retention -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\" -Name Retention -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name Retention -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup" -Name Retention -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name Retention -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name Retention).Retention -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name Retention -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" -Name Retention -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\" -Name Retention -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize).MaxSize -ge 32768){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -Value 32768
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -Value 32768 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -Value 32768 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Name MaxSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Name MaxSize).MaxSize -ge 32768){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Name MaxSize -Value 32768
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Name MaxSize -Value 32768 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" -Name MaxSize -Value 32768 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize).MaxSize -ge 32768){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize -Value 32768
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize -Value 32768 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" -Name MaxSize -Value 32768 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention).NoDataExecutionPrevention -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption).NoHeapTerminationOnCorruption -eq 0){
			       Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoHeapTerminationOnCorruption -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Name DisableFileSyncNGSC -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Name DisableFileSyncNGSC).DisableFileSyncNGSC -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Name DisableFileSyncNGSC -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Name DisableFileSyncNGSC -Value 1 -PropertyType DWORD -ErrorAction Ignore
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Force -ErrorAction Ignore
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\" -Name DisableFileSyncNGSC -Value 1 -PropertyType DWORD -ErrorAction Ignore
        }
        

    Write-Output "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving).DisablePasswordSaving -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Remote Desktop Services must always prompt a client for passwords upon connection"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword).fPromptForPassword -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Require secure RPC communication' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic).fEncryptRPCTraffic -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel).MinEncryptionLevel -eq 3){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -Value 3
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -Value 3 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -Value 3 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems).AllowIndexingEncryptedStoresOrItems -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
        if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional).MSAOptional -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name MSAOptional -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Allow user control over installs' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl).EnableUserControl -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated).AlwaysInstallElevated -eq 0){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -Value 0
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging).EnableScriptBlockLogging -eq 0){
			        Write-Output "Already Correct"
		        }else {
                     Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -Value 0
                }
	        } else {
                 New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Allow Basic authentication' is set to 'Disabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic).AllowBasic -eq 0){
			        Write-Output "Already Correct"
		        }else {
                     Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -Value 0
                }
	        } else {
                 New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -Value 0 -PropertyType DWORD
        }
        
   Write-Output "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
        if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"){
	        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic).AllowUnencryptedTraffic -eq 0){
			        Write-Output "Already Correct"
		        }else {
                     Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -Value 0
                }
	        } else {
                 New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest).AllowDigest -eq 0){
			        Write-Output "Already Correct"
		        }else {
                     Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest -Value 0
                }
	        } else {
                 New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest -Value 0 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest -Value 0 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs).DisableRunAs -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -Value 1 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Force
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -Value 1 -PropertyType DWORD
        }
        

    Write-Output "Ensure 'Enforce password history' is set to '24 or more password(s)'"
        if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"){
	        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge).MaximumPasswordAge -ge 24){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 24
                }
	        } else {
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 24 -PropertyType DWORD
            }
        } else {
            Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Force
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name MaximumPasswordAge -Value 24 -PropertyType DWORD
        }
        
     
    Write-Output "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
        if(Test-Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"){
	        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -ErrorAction Ignore) -ne $null){
		        if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex).ACSettingIndex -eq 1){
			        Write-Output "Already Correct"
		        } else {
                    Write-Warning "Attempting to set setting"
                    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -Value 1
                }
	        } else {
                New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -PropertyType DWORD -Value 1
            }
        } else {
				Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Force
				New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -PropertyType DWORD -Value 1
        }
        
    


    # SWITCH ALL THESE AROUND
    Write-Output "Ensure 'Minimum password age' is set to '1 or more day(s)'"
    if((net accounts)[1] -ne 'Minimum password age (days):                          1'){
        Write-Warning "Attempting to set setting"
        net accounts /MAXPWAGE:1
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Lockout Threshold' is set to '10 or less attempts'"
    if((net accounts)[5] -ne 'Lockout threshold:                                    10'){
        Write-Warning "Attempting to set setting"
        net accounts /lockoutthreshold:10
    }else{
        Write-Output "Already Correct"
    }
    
    
    Write-Output "Ensure 'Audit Computer Account Management' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[4] -ne '  Computer Account Management             Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"Computer Account Management" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Security Group Management' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[6] -ne '  Security Group Management               Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"Security Group Management" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[10] -ne '  Application Group Management            Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"Application Group Management" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[12] -ne '  Other Account Management Events         Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"Other Account Management Events" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[14] -ne '  User Account Management                 Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"User Account Management" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    

    Write-Output "Ensure 'Audit PNP Activity' is set to 'Success'"
    if((auditpol /get /category:"Detailed Tracking")[10] -ne '  Plug and Play Events                    Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Detailed Tracking" /subcategory:"Plug and Play Events" /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Process Creation' is set to 'Success'"
    if((auditpol /get /category:"Detailed Tracking")[14] -ne '  Process Creation                        Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }
    

    Write-Output "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
    if((auditpol /get /category:"Object Access")[24] -ne '  Other Object Access Events              Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Object Access" /subcategory:"Other Object Access Events" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
    if((auditpol /get /category:"Object Access")[28] -ne '  Removable Storage                       Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Object Access" /subcategory:"Removable Storage" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    

    Write-Output "Ensure 'Audit Authorization Policy Change' is set to 'Success'"
    if((auditpol /get /category:"Policy Change")[6] -ne '  Authorization Policy Change             Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Policy Change" /subcategory:"Authorization Policy Change" /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'"
    if((auditpol /get /category:"Policy Change")[14] -ne '  Audit Policy Change                     Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Policy Change" /subcategory:"Audit Policy Change" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
    if((auditpol /get /category:"Privilege Use")[8] -ne '  Sensitive Privilege Use                 Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Privilege Use" /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Account Lockout' is set to 'Success and Failure'"
    if((auditpol /get /category:Logon/Logoff)[8] -ne '  Account Lockout                         Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
    if((auditpol /get /category:Logon/Logoff)[18] -ne '  Other Logon/Logoff Events               Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Logon/Logoff" /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Group Membership' is set to 'Success'"
    if((auditpol /get /category:Logon/Logoff )[24] -ne '  Group Membership                        Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Logon/Logoff" /subcategory:"Group Membership" /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Logon")[10] -ne '  Credential Validation                   Success and Failure'){
         Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Logon" /subcategory:"Credential Validation" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit Security System Extension' is set to 'Success and Failure'"
    if((auditpol /get /category:System)[4] -ne '  Security System Extension               Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:System /subcategory:"Security System Extension" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }
    
    Write-Output "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
    if((auditpol /get /category:System)[8] -ne '  IPsec Driver                            Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:System /subcategory:"IPsec Driver" /success:enable /failure:enable
    } else{
        Write-Output "Already Correct"
    }
      

    <#Write-Output "UNC Hardened Path 1"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\windows\NetworkProvider\HardenedPaths"){
        if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\windows\NetworkProvider\HardenedPaths" -ErrorAction Ignore) -ne $null){
	        if(([string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\windows\NetworkProvider\HardenedPaths")).IndexOf("SYSVOL=RequireMutualAuthentication=1, RequireIntegrity=1;") -ne -1){
		        $SYSVOL = $true
	        }
        }
    }
        
    Write-Output "UNC Hardened Path 2"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\windows\NetworkProvider\HardenedPaths"){
        if(([string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\windows\NetworkProvider\HardenedPaths")).IndexOf("NETLOGON=RequireMutualAuthentication=1, RequireIntegrity=1;") -ne -1){
			$NETLOGON = $true
		}
    }#>
    
    
#endregion GPO CIS Security Standards

#region Low CIS Security Standards
Write-Output "Low Impact CIS Issues"
    # LOW IMPACT ISSUES
	# Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes	
    Write-Output "MSSKeepAliveTime"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime -ErrorAction Ignore) -ne $null){
		    if(((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime).KeepAliveTime -le 300000) -and ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime).KeepAliveTime -gt 0)){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime -Value 300000
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime -Value 300000 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -Name KeepAliveTime -Value 300000 -PropertyType DWORD
    }
	
# Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0) recommended is set to 'Enabled: 5 or fewer seconds'
    Write-Output "ScreenSaverGracePeriod"
    if(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ScreenSaverGracePeriod -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ScreenSaverGracePeriod).ScreenSaverGracePeriod -eq "5"){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ScreenSaverGracePeriod -Value "5"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ScreenSaverGracePeriod -Value "5" -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ScreenSaverGracePeriod -Value "5" -PropertyType String
    }
		
	# Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'
    Write-Output "disabledComponentsIPv6"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Name DisabledComponents -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Name DisabledComponents).DisabledComponents -eq "255"){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Name DisabledComponents -Value "255"
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Name DisabledComponents -Value "255" -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters\" -Name DisabledComponents -Value "255" -PropertyType DWORD
    }
	
    # Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)
    Write-Output "EnableVirtualizationBasedSecurity"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity).EnableVirtualizationBasedSecurity -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 -PropertyType DWORD
    }
    Write-Output "HVCIMATRequired"
    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\"){
	    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HVCIMATRequired -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HVCIMATRequired).HVCIMATRequired -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HVCIMATRequired -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HVCIMATRequired -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name HVCIMATRequired -Value 1 -PropertyType DWORD
    }
	# Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
    Write-Output "HVCIMATRequired"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Name AllowMessageSync -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Name AllowMessageSync).AllowMessageSync -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Name AllowMessageSync -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Name AllowMessageSync -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging\" -Name AllowMessageSync -Value 0 -PropertyType DWORD
    }
	# Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'
    Write-Output "ConfigureAttackSurfaceReductionRules"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Name ExploitGuard_ASR_Rules -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Name ExploitGuard_ASR_Rules).ExploitGuard_ASR_Rules -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Name ExploitGuard_ASR_Rules -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Name ExploitGuard_ASR_Rules -Value 1 -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\" -Name ExploitGuard_ASR_Rules -Value 1 -PropertyType String
    }
	# Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
    Write-Output "ConfigureAttackSurfaceReductionASRRule"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550).'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -Value 1 -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -Value 1 -PropertyType String
    }


    #  Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled' (next 5)
    Write-Output "DisableFlashConfigRegistrar"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableFlashConfigRegistrar -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableFlashConfigRegistrar).DisableFlashConfigRegistrar -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableFlashConfigRegistrar -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableFlashConfigRegistrar -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableFlashConfigRegistrar -Value 0 -PropertyType DWORD
    }
    Write-Output "DisableInBand802DOT11Registrar"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableInBand802DOT11Registrar -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableInBand802DOT11Registrar).DisableInBand802DOT11Registrar -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableInBand802DOT11Registrar -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableInBand802DOT11Registrar -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableInBand802DOT11Registrar -Value 0 -PropertyType DWORD
    }
    Write-Output "DisableUPnPRegistrar"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableUPnPRegistrar -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableUPnPRegistrar).DisableUPnPRegistrar -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableUPnPRegistrar -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableUPnPRegistrar -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableUPnPRegistrar -Value 0 -PropertyType DWORD
    }
    Write-Output "DisableWPDRegistrar"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableWPDRegistrar -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableWPDRegistrar).DisableWPDRegistrar -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableWPDRegistrar -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableWPDRegistrar -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name DisableWPDRegistrar -Value 0 -PropertyType DWORD
    }
    Write-Output "EnableRegistrars"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name EnableRegistrars -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name EnableRegistrars).EnableRegistrars -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name EnableRegistrars -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name EnableRegistrars -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\" -Name EnableRegistrars -Value 0 -PropertyType DWORD
    }

    # Ensure 'Enable Font Providers' is set to 'Disabled'
    Write-Output "EnableFontProviders"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnableFontProviders -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnableFontProviders).EnableFontProviders -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnableFontProviders -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnableFontProviders -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name EnableFontProviders -Value 0 -PropertyType DWORD
    }

    # Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
    Write-Output "CEIP"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Client\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Name CEIP -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Name CEIP).CEIP -eq 2){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Name CEIP -Value 2
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Name CEIP -Value 2 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Client\" -Name CEIP -Value 2 -PropertyType DWORD
    }

    # Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
    Write-Output "NoRegistration"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Name NoRegistration -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Name NoRegistration).NoRegistration -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Name NoRegistration -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Name NoRegistration -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control\" -Name NoRegistration -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
    Write-Output "DisableContentFileUpdates"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\" -Name DisableContentFileUpdates -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\" -Name DisableContentFileUpdates).DisableContentFileUpdates -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\" -Name DisableContentFileUpdates -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\" -Name DisableContentFileUpdates -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\SearchCompanion" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SearchCompanion\" -Name DisableContentFileUpdates -Value 1 -PropertyType DWORD
    }
     
    # Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
    Write-Output "NoOnlinePrintsWizard"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoOnlinePrintsWizard -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoOnlinePrintsWizard).NoOnlinePrintsWizard -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoOnlinePrintsWizard -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoOnlinePrintsWizard -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoOnlinePrintsWizard -Value 1 -PropertyType DWORD
    } 
    
    # Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
    Write-Output "DevicePKInitEnabled"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled).DevicePKInitEnabled -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -Value 1 -PropertyType DWORD
    } 
    # Set Above enabled to automatic
    Write-Output "DevicePKInitBehavior"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitBehavior -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitBehavior).DevicePKInitBehavior -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitBehavior -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitBehavior -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitBehavior -Value 0 -PropertyType DWORD
    }

    # Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
    Write-Output "DontEnumerateConnectedUsers"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DontEnumerateConnectedUsers -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DontEnumerateConnectedUsers).DontEnumerateConnectedUsers -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DontEnumerateConnectedUsers -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DontEnumerateConnectedUsers -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DontEnumerateConnectedUsers -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
    Write-Output "DisableLockScreenAppNotifications"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DisableLockScreenAppNotifications -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DisableLockScreenAppNotifications).DisableLockScreenAppNotifications -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DisableLockScreenAppNotifications -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DisableLockScreenAppNotifications -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name DisableLockScreenAppNotifications -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn off picture password sign-in' is set to 'Enabled'
    Write-Output "BlockDomainPicturePassword"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name BlockDomainPicturePassword -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name BlockDomainPicturePassword).BlockDomainPicturePassword -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name BlockDomainPicturePassword -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name BlockDomainPicturePassword -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" -Name BlockDomainPicturePassword -Value 1 -PropertyType DWORD
    }

    # Allow network connectivity during connected-standby (on battery)' is disabled
    Write-Output "DCSettingIndex"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Name DCSettingIndex -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Name DCSettingIndex).DCSettingIndex -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Name DCSettingIndex -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Name DCSettingIndex -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\" -Name DCSettingIndex -Value 0 -PropertyType DWORD
    }

    # Ensure 'enable/disable perftrack' is set to 'disabled'
    Write-Output "ScenarioExecutionEnabled"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Name ScenarioExecutionEnabled -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Name ScenarioExecutionEnabled).ScenarioExecutionEnabled -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Name ScenarioExecutionEnabled -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Name ScenarioExecutionEnabled -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" -Name ScenarioExecutionEnabled -Value 0 -PropertyType DWORD
    }

    # Ensure 'Turn off the advertising ID' is set to 'Enabled'
    Write-Output "DisabledByGroupPolicy"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Name DisabledByGroupPolicy -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Name DisabledByGroupPolicy).DisabledByGroupPolicy -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Name DisabledByGroupPolicy -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Name DisabledByGroupPolicy -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo\" -Name DisabledByGroupPolicy -Value 1 -PropertyType DWORD
    }

    #  Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Next 3)
    Write-Output "EnableVirtualizationBasedSecurity"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity).EnableVirtualizationBasedSecurity -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 -PropertyType DWORD
    }
    Write-Output "RequirePlatformSecurityFeatures"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures).RequirePlatformSecurityFeatures -eq 3){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -Value 3
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -Value 3 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name RequirePlatformSecurityFeatures -Value 3 -PropertyType DWORD
    }
    Write-Output "HypervisorEnforcedCodeIntegrity"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity).HypervisorEnforcedCodeIntegrity -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\" -Name HypervisorEnforcedCodeIntegrity -Value 1 -PropertyType DWORD
    }

    # Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
    Write-Output "DeferQualityUpdates"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdates -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdates).DeferQualityUpdates -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdates -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdates -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdates -Value 1 -PropertyType DWORD
    }
    # Check this one
    Write-Output "DeferQualityUpdatesPeriodInDays"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdatesPeriodInDays -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdatesPeriodInDays).DeferQualityUpdatesPeriodInDays -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdatesPeriodInDays -Value 0 
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdatesPeriodInDays -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name DeferQualityUpdatesPeriodInDays -Value 0 -PropertyType DWORD
    }

    # Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
    Write-Output "NoAutoRebootWithLoggedOnUsers"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers).NoAutoRebootWithLoggedOnUsers -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -Value 0 
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -Value 0 -PropertyType DWORD
    }

    # Ensure 'Allow Use of Camera' is set to 'Disabled'
    Write-Output "AllowCamera"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Camera"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Camera" -Name AllowCamera -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Camera" -Name AllowCamera).AllowCamera -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Camera" -Name AllowCamera -Value 0 
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Camera" -Name AllowCamera -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Camera" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Camera" -Name AllowCamera -Value 0 -PropertyType DWORD
    }

    # Ensure 'Require pin for pairing' is set to 'Enabled'
    Write-Output "RequirePinForPairing"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Name RequirePinForPairing -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Name RequirePinForPairing).RequirePinForPairing -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Name RequirePinForPairing -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Name RequirePinForPairing -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect\" -Name RequirePinForPairing -Value 1 -PropertyType DWORD
    }

    # Ensure 'Do not show feedback notifications' is set to 'Enabled' (Next 2)
    Write-Output "DoNotShowFeedbackNotifications"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DoNotShowFeedbackNotifications -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DoNotShowFeedbackNotifications).DoNotShowFeedbackNotifications -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DoNotShowFeedbackNotifications -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DoNotShowFeedbackNotifications -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\" -Name DoNotShowFeedbackNotifications -Value 1 -PropertyType DWORD
    }
    Write-Output "NoExplicitFeedback"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback).NoExplicitFeedback -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\" -Name NoExplicitFeedback -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn off location' is set to 'Enabled'
    Write-Output "DisableLocation"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableLocation -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableLocation).DisableLocation -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableLocation -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableLocation -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableLocation -Value 1 -PropertyType DWORD
    }
    Write-Output "DisableWindowsLocationProvider"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableWindowsLocationProvider -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableWindowsLocationProvider).DisableWindowsLocationProvider -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableWindowsLocationProvider -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableWindowsLocationProvider -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\" -Name DisableWindowsLocationProvider -Value 1 -PropertyType DWORD
    }

    # Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled' 
    Write-Output "AllowSharedLocalAppData"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Name AllowSharedLocalAppData -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Name AllowSharedLocalAppData).AllowSharedLocalAppData -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Name AllowSharedLocalAppData -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Name AllowSharedLocalAppData -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager\" -Name AllowSharedLocalAppData -Value 0 -PropertyType DWORD
    }

    # Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
    Write-Output "MaxDisconnectionTime"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime).MaxDisconnectionTime -eq 60000){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -Value 60000
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -Value 60000 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name MaxDisconnectionTime -Value 60000 -PropertyType DWORD
    }

    # Ensure 'Do not allow COM port redirection' is set to 'Enabled'
    Write-Output "fDisableCcm"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCcm -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCcm).fDisableCcm -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCcm -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCcm -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCcm -Value 1 -PropertyType DWORD
    }

    # Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
    Write-Output "fDisableLPT"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableLPT -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableLPT).fDisableLPT -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableLPT -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableLPT -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableLPT -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
    Write-Output "NoGenTicket"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Name NoGenTicket -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Name NoGenTicket).NoGenTicket -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Name NoGenTicket -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Name NoGenTicket -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform\" -Name NoGenTicket -Value 1 -PropertyType DWORD
    }

    # Ensure 'Turn on e-mail scanning' is set to 'Enabled'
    Write-Output "DisableEmailScanning"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Name DisableEmailScanning -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Name DisableEmailScanning).DisableEmailScanning -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Name DisableEmailScanning -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Name DisableEmailScanning -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\" -Name DisableEmailScanning -Value 0 -PropertyType DWORD
    }

    # Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
    Write-Output "AllowSuggestedAppsInWindowsInkWorkspace"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name AllowSuggestedAppsInWindowsInkWorkspace -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name AllowSuggestedAppsInWindowsInkWorkspace).AllowSuggestedAppsInWindowsInkWorkspace -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name AllowSuggestedAppsInWindowsInkWorkspace -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name AllowSuggestedAppsInWindowsInkWorkspace -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name AllowSuggestedAppsInWindowsInkWorkspace -Value 0 -PropertyType DWORD
    }

    #  Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
    Write-Output "AllowOnlineID"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID).AllowOnlineID -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -Value 0 -PropertyType DWORD
    }

    # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
    Write-Output "ShutdownWithoutLogon"
    if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ShutdownWithoutLogon -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ShutdownWithoutLogon).ShutdownWithoutLogon -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ShutdownWithoutLogon -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ShutdownWithoutLogon -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ShutdownWithoutLogon -Value 0 -PropertyType DWORD
    }

    # Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
    # Possibly change value to 
    Write-Output "AllocateDASD"
    if(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD).AllocateDASD -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD -Value 0 -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD -Value 0 -PropertyType String
    }

    # Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only
    Write-Output "SubmitControl"
    if(Test-Path "HKLM:\System\CurrentControlSet\Control\LSA\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\" -Name SubmitControl -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\" -Name SubmitControl).SubmitControl -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\" -Name SubmitControl -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\" -Name SubmitControl -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Control\LSA\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\" -Name SubmitControl -Value 0 -PropertyType DWORD
    }

    # Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only
    Write-Output "LDAPServerIntegrity"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Name LDAPServerIntegrity -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Name LDAPServerIntegrity).LDAPServerIntegrity -eq 2){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Name LDAPServerIntegrity -Value 2
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Name LDAPServerIntegrity -Value 2 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" -Name LDAPServerIntegrity -Value 2 -PropertyType DWORD
    }

    # Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only
    Write-Output "RefusePasswordChange"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RefusePasswordChange -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RefusePasswordChange).RefusePasswordChange -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RefusePasswordChange -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RefusePasswordChange -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RefusePasswordChange -Value 0 -PropertyType DWORD
    }

    #  Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
    Write-Output "SignSecureChannel"
    if(Test-Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"){
	    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel).SignSecureChannel -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Force
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -Value 1 -PropertyType DWORD
    }
    
    # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
    Write-Output "DontDisplayLastUserName"
    if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DontDisplayLastUserName -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DontDisplayLastUserName).DontDisplayLastUserName -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DontDisplayLastUserName -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DontDisplayLastUserName -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DontDisplayLastUserName -Value 1 -PropertyType DWORD
    }

    # Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
    Write-Output "InactivityTimeoutSecs"
    if(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs).InactivityTimeoutSecs -eq 900){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -Value 900
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -Value 900 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -Value 900 -PropertyType DWORD
    }

    # Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only
    Write-Output "ForceUnlockLogon"
    if(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ForceUnlockLogon -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ForceUnlockLogon).ForceUnlockLogon -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ForceUnlockLogon -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ForceUnlockLogon -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name ForceUnlockLogon -Value 0 -PropertyType DWORD
    }

    # Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
    Write-Output "ForceUnlockLogon"
    if(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption).SCRemoveOption -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -Value 1 -PropertyType String
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -Value 1 -PropertyType String
    }

    # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default
    Write-Output "ForceUnlockLogon"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultOutboundAction -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultOutboundAction).DefaultOutboundAction -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultOutboundAction -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultOutboundAction -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\" -Name DefaultOutboundAction -Value 0 -PropertyType DWORD
    }

    # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
    Write-Output "Domain Private Profile FW Disable Notifications"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DisableNotifications -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DisableNotifications).DisableNotifications -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DisableNotifications -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DisableNotifications -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\" -Name DisableNotifications -Value 0 -PropertyType DWORD
    }
    # Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
    Write-Output "Private LogDroppedPackets"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogDroppedPackets -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogDroppedPackets).LogDroppedPackets -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
    }
    Write-Output "Private LogDroppedPackets"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogDroppedPackets -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogDroppedPackets).LogDroppedPackets -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
    }

    # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
    Write-Output "Domain PublicProfile FW Disable Notifications"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DisableNotifications -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DisableNotifications).DisableNotifications -eq 0){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DisableNotifications -Value 0
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DisableNotifications -Value 0 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\" -Name DisableNotifications -Value 0 -PropertyType DWORD
    }
    # Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
    Write-Output "PublicProfile LogDroppedPackets"
    if(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogDroppedPackets -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogDroppedPackets).LogDroppedPackets -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
    }
    Write-Output "PublicProfile LogDroppedPackets"
    if(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\"){
	    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogDroppedPackets -ErrorAction Ignore) -ne $null){
		    if((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogDroppedPackets).LogDroppedPackets -eq 1){
			    Write-Output "Already Correct"
		    } else {
                Write-Warning "Attempting to set setting"; Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1
            }
	    } else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
        }
    } else {
        Write-Warning "Creating Registry Value"; New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\" -Name LogDroppedPackets -Value 1 -PropertyType DWORD
    }



    # THE BELOW CARBON ONES MAY NEED TO HAVE REVOKE-PRIVILEGE FOR OTHER ACCOUNTS, DONT SEEM TO BE NEEDED AS NOT SET BY DEFAULT BUT INVESTIGATE ON SERVER
    if (-not (Get-Module -ListAvailable -Name Carbon)) {
        Write-Output "Installing Carbon Module and updating hosts file..."
        Install-Module -Name 'Carbon' -force | Out-Null
    }
    $latest_carbon = (get-childitem 'C:\Program Files\WindowsPowerShell\Modules\Carbon' | Select-Object FullName)[0].Fullname
    Import-Module "$latest_carbon\Carbon.psd1"

    $Privileges = "SeEnableDelegationPrivilege", "SeMachineAccountPrivilege", "SeIncreaseQuotaPrivilege", "SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight"
    $Accounts = "Guest", "DefaultAccount", "Users", "IIS_IUSRS", "NETWORK SERVICE", "LOCAL SERVICE"
    foreach($Privilege in $Privileges){
        foreach($Account in $Accounts){
            if(Test-Privilege -Identity "$Account" -Privilege $Privilege){
                Write-Warning "Removing $Account from $Privilege"
                Revoke-Privilege -Identity "$Account" -Privilege $Privilege
            }
        }
        Write-Output "Adding $Account to $Privilege"
        Grant-Privilege -Identity "Administrators" -Privilege $Privilege
        if($Privilege -eq "SeIncreaseQuotaPrivilege"){
            Grant-Privilege -Identity "LOCAL SERVICE" -Privilege $Privilege
            Grant-Privilege -Identity "NETWORK SERVICE" -Privilege $Privilege
        }
    }
    <# Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only
    Grant-Privilege -Identity "Administrators" -Privilege SeEnableDelegationPrivilege

    # Ensure 'Add workstations to domain' is set to 'Administrators' (DC only
    Grant-Privilege -Identity "Administrators" -Privilege SeMachineAccountPrivilege

    # Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
    Grant-Privilege -Identity "Administrators" -Privilege SeIncreaseQuotaPrivilege
    Grant-Privilege -Identity "LOCAL SERVICE" -Privilege SeIncreaseQuotaPrivilege
    Grant-Privilege -Identity "NETWORK SERVICE" -Privilege SeIncreaseQuotaPrivilege


    # Ensure 'Allow log on locally' is set to 'Administrators'
    Grant-Privilege -Identity "Administrators" -Privilege SeInteractiveLogonRight

    # Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
    Grant-Privilege -Identity "Administrators" -Privilege SeRemoteInteractiveLogonRight
    #>
    # Configure 'Accounts: Rename guest account'
    Rename-LocalUser -Name "Guest" -NewName "CRMGuest"

    # Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'
    Write-Output "Ensure 'Audit Distribution Group Management' is set to 'Success and Failure'"
    if((auditpol /get /category:"Account Management")[8] -ne '  Distribution Group Management           Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Account Management" /subcategory:"Distribution Group Management" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }

    # Ensure 'Audit Directory Service Access' is set to 'Success and Failure'
    Write-Output "Ensure 'Audit Directory Service Access' is set to 'Success and Failure'"
    if((auditpol /get /category:"DS Access")[10] -ne '  Directory Service Access                Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"DS Access" /subcategory:"Directory Service Access" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }

    # Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'
    Write-Output "Ensure 'Audit Directory Service Changes' is set to 'Success and Failure'"
    if((auditpol /get /category:"DS Access")[4] -ne '  Directory Service Changes               Success and Failure'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"DS Access" /subcategory:"Directory Service Changes" /success:enable /failure:enable
    }else{
        Write-Output "Already Correct"
    }

    # Ensure 'Audit Logoff' is set to 'Success'
    Write-Output "Ensure 'Audit Logoff' is set to 'Success'"
    if((auditpol /get /category:Logon/Logoff)[6] -ne '  Logoff                                  Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:Logon/Logoff /subcategory:Logoff /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }

    # Ensure 'Audit Authentication Policy Change' is set to 'Success'
    Write-Output "Ensure 'Audit Authentication Policy Change' is set to 'Success'"
    if((auditpol /get /category:"Policy Change")[4] -ne '  Authentication Policy Change            Success'){
        Write-Warning "Attempting to set setting"
        auditpol /set /category:"Policy Change" /subcategory:"Authentication Policy Change" /success:enable /failure:disable
    }else{
        Write-Output "Already Correct"
    }
#endregion