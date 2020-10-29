Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName
)
$credential = Get-Credential

Invoke-Command -ComputerName $(GetName $ComputerName) -Credential $credential -ScriptBlock {
    if ((gwmi win32_operatingsystem | select osarchitecture).osarchitecture -eq "64-bit"){
        #64 bit logic here
        Write-Host "64-bit OS"
    }
    else{
        #32 bit logic here
        Write-Host "32-bit OS"
    }
};