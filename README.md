# 🔐 MFA Combined Report — Method Type & Registration Age
### Microsoft Entra ID | PowerShell | Microsoft Graph API

### Why Method Type AND Registration Age Both Matter

Most MFA audits answer one question — does this user have MFA?
This script goes two levels deeper:

**Level 1 — What method do they have?**
SMS and email OTP are weak — vulnerable to SIM swapping and phishing.
Authenticator app and FIDO2 are strong — phishing resistant.
A user with MFA is not automatically secure.

**Level 2 — When did they register it?**
A user who registered MFA 400 days ago may be using an outdated
method or a device they no longer have access to.
Registration age helps prioritize who needs an MFA review.

### What This Script Delivers
- Complete MFA inventory per user — method type and registration date
- Five tier risk classification combining strength and age
- Identifies users with no MFA, weak MFA, and aging strong MFA
- Timestamped CSV with full detail per user
- Recurring capability — run weekly to track MFA posture over time

## 📄 Executive Summary

**Problem:** Organizations know MFA is required but have no automated
way to audit what methods users actually registered or how long ago
they did it. A user with SMS-only MFA or MFA registered on a lost
device is still flagged as compliant in basic audits.

**Solution:** This script pulls every user's authentication methods,
identifies the type of each method, finds the earliest registration
date, and classifies the user based on both pieces of information
combined into one status.

**Result:** A complete MFA posture picture — not just who has it
but whether it is strong enough and recent enough to be trustworthy.

**Time to value:** Under 10 minutes from first run to full report.

---

## 🔍 Real Findings From Lab Tenant

| Metric | Result |
|---|---|
| Total enabled users scanned | 98 |
| No MFA registered | 94 |
| Has strong MFA | 4 |
| Has weak MFA only | 0 |
| Recently registered | 0 |
| Well secured | 4 |

**94 out of 98 enabled users had no MFA registered.**

---

## 🔍 Classification System

| Status | Criteria | Risk Level |
|---|---|---|
| Recently Secured | Strong MFA + registered within 30 days | ✅ Excellent |
| Well Secured | Strong MFA + registered within 180 days | ✅ Good |
| Review - Aging Strong MFA | Strong MFA + registered 180+ days ago | 🟡 Monitor |
| Weak MFA - Upgrade Needed | SMS or email OTP only | 🟠 High |
| No MFA - Critical | Password only | 🔴 Critical |

## Step by Step Breakdown

**Step 1 — Connected to Microsoft Graph**
```powershell
Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome
```
- `User.Read.All` — read all user accounts and their properties
- `UserAuthenticationMethod.Read.All` — read authentication methods per user
- Two scopes are all that is needed for this audit

---

**Step 2 — Pulled all users and filtered to enabled accounts**
```powershell
$users        = Get-MgUser -All -Property "Id,DisplayName,Department,UserPrincipalName,AccountEnabled"
$enabledUsers = $users | Where-Object AccountEnabled -eq $true
```
- `-All` ensures every user is returned not just the first page
- Filter to enabled accounts — no point auditing accounts that cannot sign in
- `$enabledUsers` used in the loop — not `$users`

---

**Step 3 — Got all authentication methods per user**
```powershell
$methods = Get-MgUserAuthenticationMethod -UserId $user.Id
$hasMFA  = $methods.Count -gt 1
```
- One API call per user returns all registered methods
- Every user always has at least one method — their password
- Count greater than 1 means at least one MFA method is registered

---

**Step 4 — Reset all flags before inner loop**
```powershell
$hasFIDO2         = $false
$hasAuthenticator = $false
$hasPhoneSMS      = $false
$hasEmail         = $false
$earliestRegDate  = $null
$earliestDaysAgo  = 999
```
- Six variables reset before checking this user's methods
- Must reset here — not inside the inner loop
- Resetting inside the inner loop would erase data from previous methods
- `$null` means no date found yet
- `999` is a sentinel value meaning never registered

---

**Step 5 — Looped through each method**
```powershell
foreach ($method in $methods) {
    if (-not $method.AdditionalProperties) { continue }
```
- Inner loop processes each method one at a time
- Null check on `AdditionalProperties` — some method objects come back empty
- `continue` skips empty objects without crashing

---

**Step 6 — Identified method type with switch**
```powershell
switch ($method.AdditionalProperties["@odata.type"]) {
    "#microsoft.graph.fido2AuthenticationMethod"                        { $hasFIDO2 = $true }
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"       { $hasAuthenticator = $true }
    "#microsoft.graph.phoneAuthenticationMethod"                        { $hasPhoneSMS = $true }
    "#microsoft.graph.emailAuthenticationMethod"                        { $hasEmail = $true }
}
```
- Method type lives in `AdditionalProperties["@odata.type"]` — not a direct property
- `switch` checks one value against multiple known strings — cleaner than if/elseif chain
- Sets boolean flags for each method type found
- Password method not listed — it is never counted as MFA

---

**Step 7 — Tracked the earliest registration date**
```powershell
$createdDateMFA   = $method.AdditionalProperties["createdDateTime"]
$registrationDate = if ($createdDateMFA) { [datetime]$createdDateMFA } else { $null }
$daysAgoMFA       = if ($registrationDate) { [int]($today - $registrationDate).TotalDays } else { 999 }

if ($registrationDate -and ($earliestRegDate -eq $null -or $registrationDate -lt $earliestRegDate)) {
    $earliestRegDate = $registrationDate
    $earliestDaysAgo = $daysAgoMFA
}
```
- `createdDateTime` comes from `AdditionalProperties` — not a direct property
- Graph returns it as a string — `[datetime]` converts it to a real date for math
- Null check before conversion — not all methods have a registration date
- The if condition tracks the earliest date across all methods:
- No date stored yet → take this one
- This date is earlier than current earliest → replace it
- This date is later → keep what we have

---

**Step 8 — Calculated MFA strength after inner loop**
```powershell
$strongMFA = $hasFIDO2 -or $hasAuthenticator
$weakMFA   = $hasPhoneSMS -or $hasEmail
```
- Calculated AFTER the inner loop — not inside it
- `$strongMFA` is true if either FIDO2 or Authenticator was found
- `$weakMFA` is true if phone or email was found
- A user can have both strong and weak — strong takes priority in classification

---

**Step 9 — Combined classification**
```powershell
$status = if (-not $hasMFA)                                    { "No MFA - Critical" }
          elseif ($strongMFA -and $earliestDaysAgo -le 30)     { "Recently Secured" }
          elseif ($strongMFA -and $earliestDaysAgo -le 180)    { "Well Secured" }
          elseif ($strongMFA -and $earliestDaysAgo -gt 180)    { "Review - Aging Strong MFA" }
          elseif ($weakMFA)                                     { "Weak MFA - Upgrade Needed" }
          else                                                  { "No MFA - Critical" }
```
- No MFA checked first — most critical condition
- Strong MFA classified by registration age — recent is better
- Weak MFA flagged regardless of age — method upgrade needed
- Both method strength AND registration age determine the final status

---

**Step 10 — Printed each user in color**
```powershell
Write-Host "User: $($user.DisplayName) | ... | Status: $status" -ForegroundColor $color
```
- One line per user showing all key details
- Color coded by status — green for secure, yellow for review, red for critical
- Inline if inside `$()` handles null dates cleanly

---

**Step 11 — Added to results list**
```powershell
$results.Add([PSCustomObject]@{
    DisplayName           = $user.DisplayName
    UPN                   = $user.UserPrincipalName
    Department            = $user.Department
    HasMFA                = if ($hasMFA) { "Yes" } else { "No" }
    HasFIDO2              = if ($hasFIDO2) { "Yes" } else { "No" }
    HasAuthenticator      = if ($hasAuthenticator) { "Yes" } else { "No" }
    HasPhoneSMS           = if ($hasPhoneSMS) { "Yes" } else { "No" }
    HasEmail              = if ($hasEmail) { "Yes" } else { "No" }
    MFAStrength           = if ($strongMFA) { "Strong" } elseif ($weakMFA) { "Weak" } else { "None" }
    EarliestRegDate       = if ($earliestRegDate) { $earliestRegDate.ToString("yyyy-MM-dd") } else { "Never" }
    DaysSinceRegistration = if ($earliestDaysAgo -eq 999) { "Never" } else { $earliestDaysAgo }
    Status                = $status
})
```
- Twelve properties per user covering all findings
- Boolean flags stored as Yes/No for readable CSV output
- Sentinel value 999 converted to "Never" for the report

---

**Step 12 — Exported report and printed summary**
```powershell
$results | Export-Csv -Path "$HOME/Desktop/MFACombined_Report.csv" -NoTypeInformation
```
- Full report exported to CSV on Desktop
- Summary counts calculated by filtering results by status
- Color coded summary showing full MFA posture at a glance

---

## 📋 Compliance Relevance

| Framework | Control |
|---|---|
| NIST 800-53 | IA-5 — Authenticator Management |
| SOC 2 Type II | CC6.1 — Logical Access Controls |
| ISO 27001 | A.9.4.2 — Secure Log-on Procedures |
| CIS Controls | Control 6 — Access Control Management |
| Microsoft Secure Score | Enable MFA for all users |

---

## 🚀 How to Run

```bash
git clone https://github.com/felipearborestrepo/MFA-Combined-Report.git
```

```powershell
.\MFACombinedReport.ps1
```

---

## 📋 CSV Report Columns

| Column | Description |
|---|---|
| DisplayName | User display name |
| UPN | User principal name |
| Department | User department |
| HasMFA | Yes or No |
| HasFIDO2 | Yes or No |
| HasAuthenticator | Yes or No |
| HasPhoneSMS | Yes or No |
| HasEmail | Yes or No |
| MFAStrength | Strong, Weak, or None |
| EarliestRegDate | Date of first MFA registration |
| DaysSinceRegistration | Days since first registration |
| Status | Risk classification |

# PowerShell Script 

```powershell
Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$today = Get-Date

$users = Get-MgUser -All -Property "Id,DisplayName,Department,UserPrincipalName,AccountEnabled"
$enabledUsers = $users | Where-Object AccountEnabled -eq $true

foreach ($user in $enabledUsers) {

$methods = Get-MgUserAuthenticationMethod -UserId $user.Id
$hasMFA = $methods.Count -gt 1

$hasFIDO2 = $false
$hasAuthenticator = $false
$hasPhoneSMS = $false
$hasEmail = $false

foreach ($method in $methods) {
if (-not $method.AdditionalProperties) { continue }
switch ($method.AdditionalProperties["@odata.type"]) {
	"#microsoft.graph.fido2AuthenticationMethod" { $hasFIDO2 = $true }
	"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { $hasAuthenticator = $true }
	"#microsoft.graph.phoneAuthenticationMethod" { $hasPhoneSMS = $true }
	"#microsoft.graph.emailAuthenticationMethod" { $hasEmail = $true }	
	}

$strongMFA = $hasFIDO2 -or $hasAuthenticator
$weakMFA = $hasPhoneSMS -or $hasEmail

$earliestRegDate = $null
$earliestDaysAgo = 999

$createdDateMFA = $method.AdditionalProperties["createdDateTime"]
$registrationDate = if ($createdDateMFA) { [datetime]$createdDateMFA } else { $null }
$daysAgoMFA = if ($registrationDate) { [int]($today - $registrationDate).TotalDays } else { 999 }

if ($registrationDate -and ($earliestRegDate -eq $null -or $registrationDate -lt $earliestRegDate)) {
$earliestRegDate = $registrationDate
$earliestDaysAgo = $daysAgoMFA
        }
}

$status = if ($strongMFA -and $earliestDaysAgo -le 30) { "Recently Secured" }
	elseif ($strongMFA -and $earliestDaysAgo -le 90) { "Well Secured" }
	elseif ($strongMFA -and $earliestDaysAgo -ge 180) { "Review - Aging Strong MFA" }
	elseif ($weakMFA) { "Weak MFA - Upgrade Needed" }
	else { "No MFA - Critical" }

$color = if ($status -eq "Recently Secured") { "Green" }
	elseif ($status -eq "Well Secured") { "Green" }
	elseif ($status -eq "Review - Aging Strong MFA") { "Cyan" }
	elseif ($status -eq "Weak MFA - Upgrade Needed") { "Yellow" }
	else { "Red"}

Write-Host "User: $($user.DisplayName) | UPN: $($user.UserPrincipalName) | Dept: $($user.Department) | Has MFA: $(if ($hasMFA) { 'Yes' } else { 'No' }) | Weak or Strong MFA: $(if ($strongMFA) { 'Strong' } elseif ($weakMFA) { 'Weak' } else { 'N/A' }) | Earliest Reg: $(if ($earliestRegDate) { $earliestRegDate.ToString('yyyy-MM-dd') } else { 'N/A' }) | Days: $(if ($earliestDaysAgo -eq 999) { 'Never' } else { $earliestDaysAgo }) | Status: $status" -ForegroundColor $color

$results.Add([PSCustomObject]@{
	 DisplayName = $user.DisplayName
        UPN = $user.UserPrincipalName
        Department = $user.Department
        HasMFA = if ($hasMFA) { "Yes" } else { "No" }
	HasFIDO2 = if ($hasFIDO2) { "Yes" } else { "No" }
	HasAuthenticator = if ($hasAuthenticator) { "Yes" } else { "No" }
	HasPhoneSMS = if ($hasPhoneSMS) { "Yes" } else { "No" }
	HasEmail = if ($hasEmail) { "Yes" } else { "No" }
        EarliestRegDate = if ($earliestRegDate) { $earliestRegDate.ToString("yyyy-MM-dd") } else { "Never" }
        DaysSinceRegistration = if ($earliestDaysAgo -eq 999) { "Never" } else { $earliestDaysAgo }
        Status = $status
})
}

$results | Export-Csv -Path "$HOME/Desktop/MFAStatus.csv" -NoTypeInformation

$recently = ($results | Where-Object Status -eq "Recently Secured").Count
$well = ($results | Where-Object Status -eq "Well Secured").Count
$review = ($results | Where-Object Status -eq "Review - Aging Strong MFA").Count	
$upgrade = ($results | Where-Object Status -eq "Weak MFA - Upgrade Needed").Count
$noMFA = ($results | Where-Object Status -eq "No MFA - Critical").Count	

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  MFA COMBINED REPORT SUMMARY" -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "  Total users scanned      : $($enabledUsers.Count)" -ForegroundColor White
Write-Host "  Recently Secured         : $recently" -ForegroundColor Green
Write-Host "  Well Secured             : $well" -ForegroundColor Cyan
Write-Host "  Review - Aging Strong    : $review" -ForegroundColor Yellow
Write-Host "  Weak MFA - Upgrade       : $upgrade" -ForegroundColor Yellow
Write-Host "  No MFA - Critical        : $noMFA" -ForegroundColor Red
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor DarkGray
```

# Results Printed in PowerShell

<img width="868" height="615" alt="Screenshot 2026-10-02 at 17 30 37" src="https://github.com/user-attachments/assets/55857e0f-33b5-4431-a73e-f1dd6e44ecf6" />

# Results in MFAStatus.csv

<img width="1242" height="558" alt="Screenshot 2026-10-02 at 17 35 37" src="https://github.com/user-attachments/assets/a8c9dfd8-7b3b-4ca3-93ea-b888a290da86" />

<img width="310" height="570" alt="Screenshot 2026-10-02 at 17 35 56" src="https://github.com/user-attachments/assets/e9d01329-92b2-476b-b12d-32f9020f40cf" />

