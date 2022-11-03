# CAP conditions and controls

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = 'All'
$conditions.ClientAppTypes = 'exchangeActiveSync', 'other'
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "block"

New-AzureADMSConditionalAccessPolicy -DisplayName "Block Legacy Authentication" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls