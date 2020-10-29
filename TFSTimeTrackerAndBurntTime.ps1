# Specify the time of day to track between
# Hours, Minutes, Seconds
$TrackingTime = New-Object System.TimeSpan(08, 00, 0);
$TFSConnectionString = "http://tfs2013:8080/tfs";
$TFSProjectName = "PROJECT";
$CurrentName = "";
$Names = "Conor Roarty"
$Script:StartDate = Get-Date "03/04/2017";
$Script:StartDate += $TrackingTime;
$Script:EndDate = Get-Date "10/04/2017";
$Script:EndDate += $TrackingTime;
$Loop = $False;
$Global:ItemTable= @{};
$Global:TotalTimeSpent = @{};
$Global:TotalTimeBurnt = @{};

$Global:WeeklyItemTable= @{};
$Global:WeeklyTotals = @{};
Clear-Content  C:\BuildLocation\DevOpsTimeTracker\TimeTracker.htm;

# Do not edit below this line, connects to TFS Assemblies to give us all the information we are working with
foreach ($Assembly in @("Microsoft.TeamFoundation.Client", "Microsoft.TeamFoundation.WorkItemTracking.Client")) {
    try {
		Add-Type -Path "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\$Assembly.dll" -ErrorAction SilentlyContinue
    } catch {
	    try {
	        Add-Type -AssemblyName "$Assembly, Version=12.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" -ErrorAction SilentlyContinue
	    } catch {
		    Write-Output "Error loading TFS assemblies";
		    pause;
		    exit;
	    }
    }
}

# Getting the TFS Work Item Store as a script level variable
$WorkItemStore = [Microsoft.TeamFoundation.Client.TfsTeamProjectCollectionFactory]::GetTeamProjectCollection($TFSConnectionString).
																					GetService([Microsoft.TeamFoundation.WorkItemTracking.Client.WorkItemStore]);
$WeeklyWorkItemStore = [Microsoft.TeamFoundation.Client.TfsTeamProjectCollectionFactory]::GetTeamProjectCollection($TFSConnectionString).
																					GetService([Microsoft.TeamFoundation.WorkItemTracking.Client.WorkItemStore]);

# Gets the from and to dates for filtering on based on the current time of day
# and the tracking time configured at the start of the script
function Get-Dates() {
    $TrackingDate = [DateTime]::Now.Date + $TrackingTime;
    if ([DateTime]::Now.TimeOfDay -lt $TrackingTime) {
        $Script:FromDate = $TrackingDate.AddDays(-1);

        # Ensuring that if it's run on a Monday then the previous day to search is the Friday
        while ($Script:FromDate.DayOfWeek -in ([System.DayOfWeek]::Saturday, [System.DayOfWeek]::Sunday)) {
            $Script:FromDate = $Script:FromDate.AddDays(-1);
        }
        $Script:ToDate = $TrackingDate;
    } else {
        $Script:FromDate = $TrackingDate.AddDays(0);
        $Script:ToDate = $TrackingDate.AddDays(1);
    }
}

# Gets the collection of task work items assigned to the current user that have changed within the time period
function Get-WorkItemCollection() {
    $Context = @{ "project" = $TFSProjectName };
    $QueryText = @"
        SELECT [System.Id]
        FROM WorkItems
        WHERE [System.TeamProject] = @project
            AND [System.WorkItemType] = 'Task'
            AND [System.AssignedTo] = '$CurrentName'
            AND [System.ChangedDate] >= '$($Script:FromDate.ToString("yyyy-MM-dd"))'
            AND [System.ChangedDate] <= '$($Script:ToDate.AddDays(1).ToString("yyyy-MM-dd"))'
"@;
    return $WorkItemStore.Query($QueryText, $Context);
}
function Get-WeeklyWorkItemCollection() {
    $Context = @{ "project" = $TFSProjectName };
    $QueryText = @"
        SELECT [System.Id]
        FROM WorkItems
        WHERE [System.TeamProject] = @project
            AND [System.WorkItemType] = 'Task'
            AND [System.AssignedTo] = '$CurrentName'
            AND [System.ChangedDate] >= '$($Script:FromDate.AddDays(-4).ToString("yyyy-MM-dd"))'
            AND [System.ChangedDate] <= '$($Script:ToDate.AddDays(1).ToString("yyyy-MM-dd"))'
"@;
    return $WeeklyWorkItemStore.Query($QueryText, $Context);
}

# Loops through the work items passed in and calculates the time spent in the time period
function Set-WorkHours($WorkItems) {
    $Data = @();
    foreach ($WorkItem in $WorkItems) {
        
        # Gets all the revisions of the work item, sorted by the Changed Date descending
        $Revisions = $WorkItem.Revisions | sort @{ Expression = { $_.Fields["Changed Date"].Value };
                                                   Ascending = $false };

        $LastRevisionInPeriod = Get-LastRevisionInPeriod -Revisions $Revisions;
        $LastRevisionBeforePeriod = Get-LastRevisionBeforePeriod -Revisions $Revisions;

        $CompletedWork = 0;
        $BurntWork = 0;
        if ($LastRevisionInPeriod -ne $null) {
            # If there was a change to the work item in the time period
            # calculate the time spent by subtracting the Completed Time before the period from the Completed Time in the latest revision in the period
            $CompletedWork = $LastRevisionInPeriod.Fields["Completed Work"].Value;
			$BurntWork = $LastRevisionInPeriod.Fields["Remaining Work"].Value;
			if ($LastRevisionBeforePeriod -ne $null) { 
				$CompletedWork -= $LastRevisionBeforePeriod.Fields["Completed Work"].Value;
				$BurntWork -= $LastRevisionBeforePeriod.Fields["Remaining Work"].Value;
			}
        }

        # Only add the work item to the list if time has been spent
        if (($CompletedWork -ne 0) -or ($BurntWork -ne 0)) {
            $Data += New-Object PSObject -Property @{
				"Title" = (Get-ParentTitle -WorkItem $WorkItem);
				"Task" = $WorkItem.Title;
				"Time Spent" = $CompletedWork;
				"Time Burnt" = -$BurntWork;
				"Total Time Spent" = 0;
				"Total Time Burnt" = 0;
				"Date" = ($Script:FromDate).ToShortDateString();
				"Name" = $CurrentName;
				"Delimiter" = "|"}
        }
    }
    return $Data;
}
# Loops through the work items passed in and calculates the time spent in the time period
function Set-WeeklyWorkHours($WeeklyWorkItems) {
    $Data = @();
    foreach ($WorkItem in $WeeklyWorkItems) {
        
        # Gets all the revisions of the work item, sorted by the Changed Date descending
        $Revisions = $WorkItem.Revisions | sort @{ Expression = { $_.Fields["Changed Date"].Value };
                                                   Ascending = $false };

        $LastRevisionInWeek = Get-LastRevisionInWeek -Revisions $Revisions;
        $LastRevisionBeforeWeek = Get-LastRevisionBeforeWeek -Revisions $Revisions;

        $CompletedWork = 0;
        $BurntWork = 0;
        if ($LastRevisionInWeek -ne $null) {
            # If there was a change to the work item in the time period
            # calculate the time spent by subtracting the Completed Time before the period from the Completed Time in the latest revision in the period
            $CompletedWork = $LastRevisionInWeek.Fields["Completed Work"].Value;
			$BurntWork = $LastRevisionInWeek.Fields["Remaining Work"].Value;
			if ($LastRevisionBeforeWeek -ne $null) { 
				$CompletedWork -= $LastRevisionBeforeWeek.Fields["Completed Work"].Value;
				$BurntWork -= $LastRevisionBeforeWeek.Fields["Remaining Work"].Value;
			}
        }

        # Only add the work item to the list if time has been spent
        if (($CompletedWork -ne 0) -or ($BurntWork -ne 0)) {
            $Data += New-Object PSObject -Property @{
				"Title" = (Get-ParentTitle -WorkItem $WorkItem);
				"Task" = $WorkItem.Title;
				"Time Spent" = $CompletedWork;
				"Time Burnt" = -$BurntWork;
				"Total Time Spent" = 0;
				"Total Time Burnt" = 0;
				#"Date" = ($WeeklyWorkItems.Date).ToShortDateString();
				"Name" = $CurrentName;
				"Delimiter" = "|"}
        }
    }
    return $Data;
}
# Find the task's parent to get the name of the bug or user story
function Get-ParentTitle($WorkItem) {
    $ParentId = $WorkItem.Links | ? { $_.LinkTypeEnd.Name -eq "Parent" } | select -ExpandProperty RelatedWorkItemId;
	if (-not $ParentId) {
		return "<Orphaned Task>";
	}

    return $WorkItemStore.GetWorkItem($ParentId).Title;
}
# Gets the latest revision in the time period
function Get-LastRevisionInPeriod($Revisions) {
    foreach ($Revision in $Revisions) {
        $ChangedDate = [DateTime]($Revision.Fields["Changed Date"].Value);
        if ($ChangedDate -le $Script:ToDate -and $ChangedDate -ge $Script:FromDate) {
            return $Revision;
        }#probably nothing
        #elseif ([DateTime]::Now.Date.DayOfWeek -in [System.DayOfWeek]::Thursday){
          #  return $Revision
      #  }
    }
}
# Gets the latest revision in the time period
function Get-LastRevisionInWeek($Revisions) {
    foreach ($Revision in $Revisions) {
        $ChangedDate = [DateTime]($Revision.Fields["Changed Date"].Value);
        if ($ChangedDate -le $Script:ToDate -and $ChangedDate -ge $Script:FromDate.AddDays(-4)) {
            return $Revision;
        }
    }
}

# Gets the latest revision before the time period
function Get-LastRevisionBeforePeriod($Revisions) {
    foreach ($Revision in $Revisions) {
        $ChangedDate = [DateTime]($Revision.Fields["Changed Date"].Value);
        if ($ChangedDate -lt $Script:FromDate) {
            return $Revision;
        }
    }
}
# Gets the latest revision before the Week started
function Get-LastRevisionBeforeWeek($Revisions) {
    foreach ($Revision in $Revisions) {
        $ChangedDate = [DateTime]($Revision.Fields["Changed Date"].Value);
        if ($ChangedDate -lt $Script:FromDate.AddDays(-4)) {
            return $Revision;
        }
    }
}

#Works Out How Many Hours Each Person In The Team Has Done On Each Task and Totals
function Set-UsersWorkItems() {
foreach ($Name in $Names) {
		$CurrentName = $Name;
		$WorkItems = Set-WorkHours -WorkItems (Get-WorkItemCollection);
		$TimeSpent = $WorkItems | Measure-Object -Property "Time Spent" -Sum;
		$TimeBurnt = $WorkItems | Measure-Object -Property "Time Burnt" -Sum;
		$Global:TotalTimeSpent += @{$Name = $(if ($TimeSpent) { $TimeSpent.Sum } else { 0 })};
		$Global:TotalTimeBurnt += @{$Name = $(if ($TimeBurnt) { $TimeBurnt.Sum } else { 0 })};

        $WorkItems| Select-Object "Title", "Task", "Time Spent", "Time Burnt","Date"         
        $Global:ItemTable += @{$Name = $WorkItems};
	}
}
function Set-UsersWeeklyWorkItems() {
foreach ($Name in $Names) {
		$CurrentName = $Name;
		$WeeklyWorkItems = Set-WeeklyWorkHours -WeeklyWorkItems (Get-WeeklyWorkItemCollection);
		$TimeSpent = $WeeklyWorkItems | Measure-Object -Property "Time Spent" -Sum;
		$TimeBurnt = $WeeklyWorkItems | Measure-Object -Property "Time Burnt" -Sum;
		$Global:WeeklyTotals += @{$Name = $Name+"'s Total worked for the week: " + $(if ($TimeSpent) { $TimeSpent.Sum } else { 0 })};
		
        $WeeklyWorkItems| Select-Object "Title", "Task", "Time Spent", "Time Burnt","Date"   
        $Global:WeeklyItemTable += @{$Name = $WeeklyWorkItems};      
	}
}
#The Header is used in the HTML to format our tables and text presentably
$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

# Check The Day, If It Is Monday Before 8am it Should Show Fridays Details
if ($Loop) {
	$Script:FromDate = $Script:StartDate;
	$Script:ToDate = $Script:StartDate.AddDays(1);
	while ($Script:FromDate -lt $Script:EndDate) {
		Write-Output "Tracking from $Script:FromDate to $Script:ToDate";
		Set-UsersWorkItems;
		$Script:FromDate = $Script:FromDate.AddDays(1);
		$Script:ToDate = $Script:ToDate.AddDays(1);
	}
} else {
	Get-Dates;
	Write-Output "Tracking from $Script:FromDate to $Script:ToDate";
	Set-UsersWorkItems;

    if([DateTime]::Now.Date.DayOfWeek -in [System.DayOfWeek]::Friday){
        Set-UsersWeeklyWorkItems;
    }

    #Loop for each person and creating a html page with a table for each person and totals
    foreach($Name in $Names){
        if($Global:ItemTable.ContainsKey($Name)){
            $Global:ItemTable.Item($Name) |
            ConvertTo-Html -Property Title, Task, 'Time Spent', 'Time Burnt', 'Date' -Head $Header -PreContent "<h1>$Name</h1><h2>`nTime Tracking from $Script:FromDate to $Script:ToDate</h2>" -PostContent "</br> $(if($Global:TotalTimeSpent.ContainsKey($Name) -and $Global:TotalTimeBurnt.ContainsKey($Name)){"</br>" + "$Name's Total Time Spent: " + $Global:TotalTimeSpent.Item($Name).ToString() + "</br>" + "$Name's Total Time Burnt: " + $Global:TotalTimeBurnt.Item($Name).ToString()+ "</br>" + $(if($Global:WeeklyTotals.ContainsKey($Name)) {$Global:WeeklyTotals.Item($Name).ToString()}) } else { "No Totals To Show" })"|
            Out-File  C:\BuildLocation\DevOpsTimeTracker\TimeTracker.htm -Append
        }
    }
    #$Body Gets The Content of The WebPage We Created and Makes It Readable In An Email
    $Body = Get-Content  C:\BuildLocation\DevOpsTimeTracker\TimeTracker.htm -Raw
    $Today = ([DateTime]::Now.Date).ToShortDateString()
    Send-MailMessage -To "Conor Roarty <conor.roarty@aveva.com>" -From "Conor Roarty <conor.roarty@aveva.com>" -BodyAsHtml -SmtpServer "smtp.aveva.com" -Attachments  C:\BuildLocation\DevOpsTimeTracker\TimeTracker.htm -Subject "$Today Time Tracker" -Body $Body
}