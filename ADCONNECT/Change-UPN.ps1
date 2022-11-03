param (
    [Parameter(Mandatory)]
    [string]$NewSuffix
)

# Check if the new suffix is added to the AD Forest

$UPNSuffixList = Get-ADForest | Select-Object UPNSuffixes -ExpandProperty UPNSuffixes

if ($($UPNSuffixList.Length) -ne 0) {
    Write-Output "Checking if $NewSuffix suffix exists in AD Forest"
    foreach ($Suffix in $UPNSuffixList) {
        if ($Suffix -eq $NewSuffix) {
            Write-Output "$NewSuffix suffix found!"
        } else {
            Write-Output "$NewSuffix suffix not found in AD Forest. Attempting to add it."
            Get-ADForest | Set-ADForest -UPNSuffixes @{add = $NewSuffix }
            Write-Output "$NewSuffix suffix was added successfully"
        }
    }
} else {
    Write-Output "$NewSuffix suffix not found in AD Forest. Attempting to add it."
    Get-ADForest | Set-ADForest -UPNSuffixes @{add = $NewSuffix }
    Write-Output "$NewSuffix suffix was added successfully"
}

# Change the UPNsuffix for all users.

$users = Get-ADUser -Filter * -Properties *

foreach ($user in $users) {
    Write-Output "Changing UPN for $($user.Name) - $($user.SamAccountName)"
    Set-ADUser -Identity $user.SamAccountName -UserPrincipalName $($user.SamAccountName + "@" + $NewSuffix)
}