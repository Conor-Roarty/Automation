Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@;

[Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

#####################################################################################################################################################
# Variables to modify before running                                                                                                                #
$data = Import-Csv "C:\310807\Control Account RTIO Project.csv"; # The full file path of the CSV to upload                                          #
$server = "localhost"; # The server to run against (update this)                                                                                    #
$projectDeptRef = "DefDept"; # The reference of the project dept the control accounts are to be uploaded to                                  #
$logFileDirectory = "C:\"; # The folder location of where the log file should be written to - leave as C:\ to write to the root of the C drive      #
$username = "unittestuser"; # The username                                                                                                   #
$password = "password"; # The password                                                                                                       #
# End of variables                                                                                                                                  #
#####################################################################################################################################################

$controlAccountsUrl = "https://$server/RestApi/procon/v1/project-depts/control-accounts?tier3Reference=$projectDeptRef";

$basicAuth = @{
    Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($username + ":" + $password));
};

if (!$data) {
    Pause;
    Exit;
}

$logFile = "Upload Log $([DateTime]::Now.ToString("dd-MM-yyyy-HHmmss")).txt";
$logFile = [System.IO.Path]::Combine($logFileDirectory, $logFile);

New-Item $logFile -ItemType file | Out-Null;

$progress = 0;

$data | ForEach-Object {
    $progress++;
    Write-Progress -Activity "Inserting Control Accounts" -Status "$progress of $($data.length)" -PercentComplete (($progress / $data.length) * 100);
    $controlAccount = $_;
    $json = @{
        AccountCode = $controlAccount.'Control Account Code';
        Description = $controlAccount.'Control Account Name';
    } | ConvertTo-Json;

    Try {
        Invoke-RestMethod -Method Post -Uri $controlAccountsUrl -ContentType "application/json" -Headers $basicAuth -Body $json | Out-Null;
        $logText = "SUCCESS - Control Account with Code: $($controlAccount.'Control Account Code') & Name: $($controlAccount.'Control Account Name') successfully added."
    } Catch {
        $message = (ConvertFrom-Json $_.ErrorDetails.Message).message;
        $logText = "FAILURE - Control Account with Code: $($controlAccount.'Control Account Code') & Name: $($controlAccount.'Control Account Name') failed to insert with error $message";
    }

    Add-Content -Path $logFile -Value $logText;
}

Write-Output "Processing complete - check log file for details."
Start-Process $logFile;
Pause;
