param(
    [Parameter(Mandatory=$true)]
    [Alias("Name","CN","Computer")]
    [string]$ComputerName
) # add param for what value to do for this

function GetName([string]$Name) {
    if ($Name.StartsWith("VM", [StringComparison]::CurrentCultureIgnoreCase) -or $Name.StartsWith("SERVER", [StringComparison]::CurrentCultureIgnoreCase)) { #Based on random naming conventions
        return $Name;
    }

    return "$Name";
}

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "<DOMAIN>\QA", $(ConvertTo-SecureString "password" -AsPlainText -Force);

Invoke-Command -ComputerName $(GetName $ComputerName) -Credential $credential -ScriptBlock {
    $restApiFolder = gci (Get-Item $env:PROCON_HOME).Root -Recurse -ErrorAction Ignore | ? { $_.PSIsContainer -eq $true -and $_.Name -like "*RestAPI" } | select -First 1 -ExpandProperty FullName;

    @("$env:PROCON_HOME\Web\Web.Config", "$restApiFolder\Web.Config") | % {
        sp $_ IsReadOnly $false;
        [xml]$config = Get-Content $_;

        $modules = $config.SelectSingleNode("//system.webServer/modules");
        $i18n = $modules.SelectSingleNode("add[@name='I18N']");
        $lastComment = $modules.SelectSingleNode("comment()[last()]");

        if ($i18n -ne $null) {
            $comment = $config.CreateComment($i18n.OuterXml);
            $modules.InsertAfter($comment, $lastComment) | Out-Null;
            $modules.RemoveChild($i18n) | Out-Null;
        } else {
            $nameAttr = $config.CreateAttribute("name");
            $nameAttr.Value = "I18N";
            $typeAttr = $config.CreateAttribute("type");
            $typeAttr.Value = "COMPANY.Presentation.InternationalModule.I18N"; #sample 
    
            $node = $config.CreateElement("add");
            $node.Attributes.Append($typeAttr) | Out-Null;
            $node.Attributes.Append($nameAttr) | Out-Null;

            if ($lastComment -ne $null) {
                $modules.InsertAfter($node, $lastComment) | Out-Null;
                $modules.RemoveChild($lastComment) | Out-Null;    
            } else {
                $modules.PrependChild($node);
            } 
        }

        $config.Save($_);
    }
 };