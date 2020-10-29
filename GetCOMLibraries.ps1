$comAdmin = New-Object -ComObject ("COMAdmin.COMAdminCatalog.1")
$applications = $comAdmin.GetCollection("Applications") 
$applications.Populate() 

foreach($application in $applications){
	if($application.Name -eq "Server Application"){

		$application.Value("Identity") = "Network Service"
		$application.SaveChanges();

		$identity = $application.Value("Identity")
		"Identity: $identity`n"

	}

    $components = $applications.GetCollection("Components",$application.key)
    $components.Populate()
    foreach ($component in $components)
    {
		
        $dllName = $component.Value("DLL")
        $componentName = $component.Name

        "Component Name:$componentName"
        "DllName: $dllName`n"
    }
}