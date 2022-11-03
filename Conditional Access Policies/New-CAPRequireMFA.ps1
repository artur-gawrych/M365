# Configure CAP to require MFA for users in the "MFA Rerquired" security group.

$RequireMFAGroupName = "MFA Required"

if (!(Get-AzureADGroup | Where-Object DisplayName -Contains $RequireMFAGroupName)){
    $RequireMFAGroup = New-AzureADGroup -DisplayName $RequireMFAGroupName -SecurityEnabled $true -MailEnabled $false -MailNickName "mfarequired"
} else {
    $RequireMFAGroup = Get-AzureADGroup | Where-Object DisplayName -Contains $RequireMFAGroupName
}

<##

#Add IP address and mark it as a trusted location

$IPAddress = '185.21.86.11/32'
$HeadOfficeIP = New-Object -TypeName Microsoft.Open.MSGraph.Model.IpRange
$HeadOfficeIP.CidrAddress = $IPAddress
New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.ipNamedLocation" -DisplayName 'Head Office Public IP' -IsTrusted $True -IpRanges $IPAddress | Out-Null

$IPAddress = '185.21.86.21/32'
$HeadOfficeIP2 = New-Object -TypeName Microsoft.Open.MSGraph.Model.IpRange
$HeadOfficeIP2.CidrAddress = $IPAddress
New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.ipNamedLocation" -DisplayName 'Head Office 2 Public IP' -IsTrusted $True -IpRanges $IPAddress | Out-Null

##>

# CAP conditions and controls

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeGroups = $RequireMFAGroup.ObjectID
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = "All"
# $conditions.Locations.ExcludeLocations = "AllTrusted"
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "mfa"

New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA" -State "enabledForReportingButNotEnforced" -Conditions $conditions -GrantControls $controls