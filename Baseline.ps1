

#region Enable mailbox auditing

if ((Get-OrganizationConfig).AuditDisabled -eq $True) {
    Set-OrganizationConfig -AuditDisabled $False
    Write-Output 'Enabled Auditing in Organization Configuration'
} else {
    Write-Output 'Auditing is already enabled in Organization Configuration'
}

if ((Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled -eq $False) {
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $True
}

$AuditingParameters = @{
    AuditEnabled     = $true
    AuditLogAgeLimit = 365
    AuditAdmin       = 'Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'SendAs', 'SendOnBehalf', 'Create', 'UpdateFolderPermission'
    AuditDelegate    = 'Update', 'SoftDelete', 'HardDelete', 'SendAs', 'Create', 'UpdateFolderPermissions', 'MoveToDeletedItems', 'SendOnBehalf'
    AuditOwner       = 'UpdateFolderPermission', 'MailboxLogin', 'Create', 'SoftDelete', 'HardDelete', 'Update', 'MoveToDeletedItems'
}

foreach ($mailbox in (Get-Mailbox -ResultSize Unlimited)) {
    Set-Mailbox -Identity $mailbox.Identity @AuditingParameters
    Write-Output "Enabling Auditing for $($mailbox.Displayname) - $($mailbox.UserPrincipalName)"
}

#endregion

#region Enable modern authentication

if ((Get-OrganizationConfig).OAuth2ClientProfileEnabled -eq $False) {
    Set-OrganizationConfig -OAuth2ClientProfileEnabled $True
}

#endregion

#region Disable mailbox forwarding to remote domains.

if ((Get-RemoteDomain).AutoForwardEnabled -eq $True) {
    Set-RemoteDomain -Identity Default -AutoForwardEnabled $False
    Write-Output 'Disabled forwarding to remote domains.'
}

#endregion

#region Configure a spam filter policy

$SpamPolicyParameters = @{
    Name                             = '[Custom] SPAM Filter Policy'
    BulkQuarantineTag                = 'DefaultFullAccessPolicy'
    BulkSpamAction                   = 'Quarantine'
    BulkThreshold                    = 7
    EnableEndUserSpamNotifications   = $True
    EndUserSpamNotificationFrequency = 1
    HighConfidencePhishAction        = 'Quarantine'
    HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'
    HighConfidenceSpamAction         = 'Quarantine'
    HighConfidenceSpamQuarantineTag  = 'AdminOnlyAccessPolicy'
    inlinesafetytipsenabled          = $True
    MarkAsSpamBulkMail               = 'On'
    PhishQuarantineTag               = 'DefaultFullAccessPolicy'
    PhishSpamAction                  = 'Quarantine'
    PhishZapEnabled                  = $True
    QuarantineRetentionPeriod        = 30
    SpamAction                       = 'Quarantine'
    SpamQuarantineTag                = 'DefaultFullAccessPolicy'
    SpamZapEnabled                   = $True
}

New-HostedContentFilterPolicy @SpamPolicyParameters

$domains = @()
foreach ($domain in Get-AcceptedDomain) {
    $domains += $($domain.Name)
}

$SpamRuleParameters = @{
    Name                        = '[Custom] SPAM Filter Rule'
    Enabled                     = $True
    HostedContentFilterPolicy   = '[Custom] SPAM Filter Policy'
    Priority                    = 0
    RecipientDomainIs           = $domains
}

New-HostedContentFilterRule @SpamRuleParameters

#endregion

#region Configure a malware filter policy

$MalwarePolicyParameters = @{
    Name                = '[Custom] Malware Filter Policy'
    EnableFileFilter    = $True
    FileTypes           = 'ace', 'ani', 'apk', 'app', 'appx', 'arj', 'bat', 'cmd', 'com', 'deb', 'dex', 'dll', 'docm', 'elf', 'exe', 'hta', 'img', 'jar', 'kext', 'lha', 'lib', 'library', 'lnk', 'lzh', 'macho', 'msc', 'msi', 'msix', 'msp', 'mst', 'pif', 'ppa', 'ppam', 'reg', 'rev', 'scf', 'scr', 'sct', 'sys', 'uif', 'vb', 'vbe', 'vbs', 'vxd', 'wsc', 'wsf', 'wsh', 'xll', 'xz', 'z'
    FileTypeAction      = 'Quarantine'
    QuarantineTag       = 'AdminOnlyAccessPolicy' 
[-RecommendedPolicyType <RecommendedPolicyType>]
[-WhatIf]
[-ZapEnabled <Boolean>]
[<CommonParameters>]

}

