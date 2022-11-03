# Configure CAP to require MFA for users in the "MFA Rerquired" security group.

$RequireMFAGroupName = "MFA Required"
$RequireMFAGroup = Get-AzureADGroup | Where-Object DisplayName -Contains $RequireMFAGroupName

# CAP conditions and controls

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeGroups = $RequireMFAGroup.ObjectID
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = "All"
$conditions.Locations.ExcludeLocations = "AllTrusted"
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "block"

New-AzureADMSConditionalAccessPolicy -DisplayName "Block External Access" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls