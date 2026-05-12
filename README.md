# Microsoft Sentinel SOC Lab

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SOC%20Lab-0078d4?style=flat-square&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Detection%20Logic-7b2d8b?style=flat-square)
![Incident Response](https://img.shields.io/badge/Incident%20Triage-Practiced-d83b01?style=flat-square)
![SOAR](https://img.shields.io/badge/SOAR-Logic%20App%20Playbook-107c10?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-black?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)

---

## What This Is

This is a personal SOC home lab I built to get actual hands-on experience with Microsoft Sentinel — not just reading about it, but working through it the way a real analyst would.

I've been passed my cybersecurity few days ago (CompTIA Security+ done, currently studying for SC-200 and working toward CySA+), and I kept feeling like my knowledge was very theoretical. I could explain what a SIEM does but I'd never actually sat inside one and investigated something. That's what pushed me to build this.

The lab covers the full SOC analyst workflow: getting data into Sentinel, writing KQL queries to detect suspicious authentication activity, triaging and documenting incidents, enriching investigations with watchlists, building a workbook to track SOC metrics, and designing a Logic App playbook for automated response with analyst approval. I spent about three weeks building and documenting this, with a lot of trial and error along the way.


---

## Why Sentinel Specifically

A few reasons. It's one of the most commonly mentioned tools in SOC job postings I've looked at, especially in Microsoft 365 and Azure environments. The SC-200 exam covers it heavily and I wanted the lab time to reinforce the study material. And Microsoft has a free trial tier that made it possible to actually spin this up without spending a lot of money.

I looked at Splunk and IBM QRadar as alternatives but decided to focus on one platform deeply rather than skim several of them.

---

## Lab Summary

| Area | What I Practiced |
|---|---|
| SIEM setup | Sentinel workspace, Log Analytics, data connectors, enabling the service |
| Log analysis | Sign-in logs, audit logs, Azure Activity logs, Security Events |
| KQL | Writing queries from scratch for failed logins, disabled accounts, privilege changes |
| Detection logic | Converting suspicious behavior into analytics rules with proper tuning |
| Incident triage | Reviewing severity, entities, ownership, investigation notes, escalation decisions |
| Threat hunting | Proactive searches beyond what alerts caught |
| Watchlists | Trusted IPs, high-risk IPs, privileged user enrichment |
| Workbooks | Building a SOC reporting view with charts and key metrics |
| SOAR | Logic App playbook with analyst approval before containment |
| Documentation | Writing up the reasoning behind every decision, not just the steps |

---

## Screenshots

### Sentinel Overview Dashboard

![Sentinel Overview Dashboard](assets/images/sentinel-overview.svg)

This is the main Sentinel workspace view. The top row shows open incidents (14), active alerts (38), anomalies (7), data ingested (2.4 GB), and active connectors (9 of 12). The bar chart below breaks out incident volume by severity over 7 days — High in red, Medium in orange, Low in blue. The MITRE ATT&CK heatmap in the lower left shows which tactic areas the current analytics rules cover; lighter cells showed me where I had little or no detection logic, which was useful for understanding coverage gaps. Connector health is on the lower right — the Office 365 connector showed a Warning during my lab window because a misconfigured OAuth permission caused a 38-minute gap in log delivery.

---

### Incident Queue

![Incident Queue](https://github.com/MartinAmofaBoadu/incident-queue/blob/main/README.md)

The incident queue filtered to Active and New status, sorted by last-updated time. The right panel shows the detail view for incident #SOC-2024-0047 (suspicious sign-in from unknown IP) — severity badge, MITRE tactic tag, affected entities with watchlist context, investigation tabs, and my analyst note at the bottom. One thing I learned: severity is set by the analytics rule that fired, not by the actual risk level of the activity. A High-severity alert still needs to be validated. Some of mine were false positives on early rule versions before I tuned the thresholds.

---

### Workbook / Reporting View

![Workbook View](assets/images/workbook-reporting.svg)

A custom workbook built to give a high-level SOC health view over 7 days. The KPI tiles show total incidents (58), mean time to respond (4.2h, down 18% week-over-week), failed sign-ins in the last 24 hours (342), disabled-account attempts over 7 days (27), and the incident closure rate (76%). The line chart shows failed sign-in trends across the week. The donut chart breaks down incidents by severity. The lower-left table shows the top source IPs by failed-login volume with watchlist enrichment inline — so you can immediately see whether a high-volume IP is a known threat, suspicious, or not listed anywhere.

---

### Logic App Playbook

![Logic App Playbook](assets/images/playbook-flow.svg)

The Logic App playbook triggered on Sentinel incident creation. The flow: parse incident entities → notify the SOC Teams channel → send an approval email to the on-call analyst → if approved, disable the Azure AD account and update the incident → if rejected or timed out (4 hours), add a comment and leave the incident open for manual review. The run history panel on the right shows recent executions including one marked "Failed" — that was me intentionally testing the 4-hour timeout to verify it handled the no-response case correctly (it added the timeout comment to the incident and left it open as expected).

---

## Phase 1 — Workspace Setup

Before anything else, I had to create a Log Analytics workspace and enable Sentinel on top of it. Sentinel doesn't store data itself — it sits on top of Log Analytics, which is what actually holds the logs and runs the queries.

### Steps I took

1. Searched for "Log Analytics workspaces" in the Azure portal and created a new workspace named `contoso-sentinel-ws` inside a resource group called `rg-sentinel-lab`.
2. Set the region to East US and kept the pricing tier at Pay-as-You-Go.
3. After the workspace was created, searched for "Microsoft Sentinel," clicked **Create Microsoft Sentinel**, and attached it to the new workspace.

**The mistake I made the first time:** I tried enabling Sentinel in a different region from the workspace and got an error I didn't immediately understand. The fix was making sure the Sentinel resource and the Log Analytics workspace are in the same region. After correcting that it enabled fine.

### Validation query

```kql
AzureActivity
| where TimeGenerated > ago(1h)
| take 5
```

If results come back, the workspace is live. If nothing returns, wait a few minutes — there's sometimes a short propagation delay after enabling.

**Things I confirmed before moving on:**
- Workspace ID and primary key were accessible (needed for some agent-based connectors)
- Resource group organized cleanly under `rg-sentinel-lab`
- No errors showing on the Sentinel overview page
- Pricing tier confirmed — I didn't want surprise charges from collecting logs I didn't need

---

## Phase 2 — Data Connectors and Telemetry

A SIEM is only as good as the data feeding into it. Before enabling any connector, I asked: what table does this populate, what scenarios does it support, what permissions do I need, and how much log volume will it generate? That last one matters because Log Analytics charges by GB ingested, and some log sources can generate a lot of data fast.

### Data sources I worked with

| Connector | Table | Purpose |
|---|---|---|
| Microsoft Entra ID | `SigninLogs`, `AuditLogs` | Core identity telemetry — every auth-based detection in this lab relies on this |
| Azure Activity | `AzureActivity` | Privilege changes, resource creation/deletion, role assignments |
| Security Events via AMA | `SecurityEvent` | Windows Event Logs from lab VMs |
| Microsoft Defender for Cloud | `SecurityAlert` | Pre-built Microsoft security alerts feeding into Sentinel |
| Threat Intelligence | `ThreatIntelligenceIndicator` | IOC matching against observed log activity |

### Connector setup notes

**Microsoft Entra ID** required Global Reader or Security Reader in Entra ID plus Log Analytics Contributor on the workspace. My first attempt failed because I forgot to grant the Sentinel app the correct Entra ID role — after assigning that, the connector connected within a few minutes.

**Azure Activity** enabled directly from the connector page without any agent. Needed Reader access at the subscription level.

**Security Events** required the Azure Monitor Agent installed on the Windows VM. I used the "Common" event collection preset rather than "All Events" — collecting everything would have generated far too much data for a lab.

**Office 365** required admin consent in the Microsoft 365 tenant. This one caused the Warning status visible in the dashboard screenshot because a misconfigured OAuth scope caused a 38-minute gap in log delivery. Fixing it required re-authorizing the connector with updated permissions.

### Connector health validation query

```kql
// Check when each table last received data
union withsource=TableName
    SigninLogs,
    AuditLogs,
    AzureActivity,
    SecurityEvent
| summarize LastRecord = max(TimeGenerated) by TableName
| extend MinutesSinceLastRecord = datetime_diff('minute', now(), LastRecord)
| order by MinutesSinceLastRecord asc
```

Anything over 60 minutes for a source that should be streaming is worth investigating. The portal's "Connected" status indicator tells you the configuration is valid; this query tells you whether data is actually flowing.

### A note on data quality over data quantity

One thing this phase taught me: having more data isn't automatically better. Turning on every connector creates a large volume that's expensive to store and harder to search. The better approach is to start with log sources that directly support your detection goals, validate them, build the detections, then add new sources as new scenarios demand them. I focused on identity and authentication logs first, which is where every core detection in this lab lives anyway.

---

## Phase 3 — KQL Detection Queries

KQL was the part I was most nervous about going in. I'd done the Microsoft Learn KQL module and watched several YouTube videos (John Savill's Azure content was particularly useful for understanding the underlying Azure context), but writing queries from a blank editor for actual detection scenarios felt different.

My process for each detection:

1. Define the suspicious behavior I'm trying to detect
2. Identify which table holds the relevant data
3. Start simple — get the table, scan the columns, understand what the data looks like
4. Build the query incrementally rather than writing it all at once
5. Think about false positives before finalizing
6. Think about what threshold and time window make sense
7. Convert to an analytics rule with entity mappings

---

### Query 1 — Failed Sign-ins by Source IP

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| where isnotempty(IPAddress)
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetedUsers = make_set(UserPrincipalName, 20),
    Applications = make_set(AppDisplayName, 20),
    Locations = make_set(Location, 20)
    by IPAddress
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

**What it does:** Aggregates failed sign-in attempts by source IP over 24 hours and filters for IPs hitting 10 or more failures. The `make_set` columns capture which users and apps were targeted — important for distinguishing brute force against one account from password spray across many.

**Why 10 as the threshold:** I started at 5 and got significant noise. Legitimate users fail 2–3 times before succeeding, and some misconfigured apps will fail repeatedly in the background. At 10 it becomes much harder to explain as accidental. In a production environment I'd baseline historical data rather than guess.

**False positives to consider:**
- Misconfigured applications with stale service account credentials
- Users locking themselves out while traveling
- Monitoring tools making test API calls
- VPN or proxy addresses shared by many legitimate users

The `make_set(TargetedUsers)` column is the best false-positive discriminator: one IP failing against 30 different usernames looks like a spray. The same IP failing 30 times against one username looks like a targeted lockout or a forgetful user. Very different scenarios, same failure count.

---

### Query 2 — Disabled Accounts Receiving Sign-in Attempts

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 50057
   or tostring(Status.failureReason) has "disabled"
| summarize
    Attempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Applications = make_set(AppDisplayName, 20),
    Locations = make_set(Location, 20)
    by UserPrincipalName, IPAddress
| order by Attempts desc
```

**What it does:** Finds sign-in attempts against disabled accounts. ResultType `50057` is the specific Azure AD error code for disabled accounts. I included the `failureReason` string search as a fallback in case the error code surfaces differently in certain configurations.

**Why this matters:** Disabled accounts shouldn't be active authentication targets from external sources. When they are, it means stale credentials being reused, an old automated process nobody updated, or an attacker testing account names from a list. Any of those is worth investigating.

**What I found in the lab:** The most interesting hit was a service account (`svc.backup@contoso.com`) disabled 8 months earlier that was still receiving attempts from an internal IP. Turned out to be a scheduled backup task nobody had updated when the account was deprovisioned. Benign — but exactly the kind of cleanup item you'd want to surface.

---

### Query 3 — New User Created Followed by Role Assignment

```kql
let NewUsers =
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "Add user"
| extend NewUser = tostring(TargetResources[0].userPrincipalName)
| project NewUser, UserCreatedTime = TimeGenerated, CreatedBy = tostring(InitiatedBy.user.userPrincipalName);

let RoleAssignments =
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
   or OperationName has "role assignment"
| project RoleAssignmentTime = TimeGenerated, Caller, OperationName, ResourceGroup, SubscriptionId;

NewUsers
| join kind=inner RoleAssignments on $left.CreatedBy == $right.Caller
| where RoleAssignmentTime between (UserCreatedTime .. UserCreatedTime + 1d)
| project UserCreatedTime, RoleAssignmentTime, NewUser, CreatedBy, OperationName, ResourceGroup, SubscriptionId
| order by RoleAssignmentTime desc
```

**What it does:** Finds cases where a new user account was created and the person who created it also performed a role assignment within a 24-hour window. The `let` statements build two temporary result sets joined on the `CreatedBy` / `Caller` identity — the person who performed both actions.

**Why this matters:** In normal IT operations, account creation and role assignment are typically handled by an identity management system, not a single person acting through the portal. When a human account creates a user *and* assigns them a privileged role in quick succession, it's worth reviewing — especially for high-privilege roles like Subscription Owner or Global Administrator.

**What was hard about this query:** The join condition took several attempts. I initially joined on the new user account rather than the creator, which returned no results. Had to step back and think about what field actually connects the two datasets — the identity of the person who performed both actions, not the account they created.

---

### Query 4 — Sign-ins from IPs Not on the Allow-list

```kql
let AllowedIPs =
    _GetWatchlist('trusted-ip-allowlist')
    | project AllowedIP = SearchKey;

SigninLogs
| where TimeGenerated > ago(24h)
| where isnotempty(IPAddress)
| join kind=leftanti AllowedIPs on $left.IPAddress == $right.AllowedIP
| summarize
    Events = count(),
    Users = make_set(UserPrincipalName, 20),
    Applications = make_set(AppDisplayName, 20)
    by IPAddress
| order by Events desc
```

**What it does:** Uses a watchlist of trusted IP addresses to filter out known-good sources, then surfaces sign-in activity from everything else. `leftanti` is the key operator here — it returns only rows from the left table with *no* match in the right table, giving you everything that is not on the allow-list.

**Why watchlists instead of hardcoded IPs:** Watchlists are far more maintainable. If you hardcode IP ranges in a query, every time the network team adds a new VPN exit node or office subnet, someone has to remember to update the query. With a watchlist, you update one central place and every query referencing that watchlist picks up the change automatically.

---

### Bonus — Threat Hunting Query: Distributed Sub-threshold Spray

This came from a threat hunting session rather than alert response. The question I was asking: what if an attacker was deliberately staying below my failed-login threshold by spreading attempts across many source IPs?

```kql
let LookbackPeriod = 7d;
let FailureThresholdLow = 3;
let FailureThresholdHigh = 9;
let MinTargetedUsers = 2;

SigninLogs
| where TimeGenerated > ago(LookbackPeriod)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedUsers = make_set(UserPrincipalName, 50),
    UniqueUserCount = dcount(UserPrincipalName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName, 10)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts between (FailureThresholdLow .. FailureThresholdHigh)
| where UniqueUserCount >= MinTargetedUsers
| project IPAddress, HourWindow = TimeGenerated, FailedAttempts, UniqueUserCount, TargetedUsers, FirstSeen, LastSeen, Apps
| order by HourWindow desc
```

**What I found:** One IP address (`103.86.99.12`) appeared across multiple 1-hour windows with 4–7 failures each time against a rotating set of usernames. No individual hour bucket would have triggered my alert rule (threshold was 10), but across 7 days it was clearly a coordinated pattern. I added it to the high-risk watchlist, saved a hunting bookmark in Sentinel, and noted it in the related incident.

---

## Phase 4 — Incident Triage

Once analytics rules were in place, incidents started appearing in the queue. This is where the lab started feeling most realistic.

### My triage workflow

For every incident I opened, I worked through this checklist before drawing any conclusions:

- **What rule fired?** What behavior was it designed to detect, and does this incident actually match that?
- **Is the severity calibrated correctly?** High/Medium/Low is assigned by the rule, not by actual risk — it needs to be validated.
- **Who are the affected entities?** User, IP, host, application.
- **What are the timestamps?** Isolated event or repeated activity over time?
- **Watchlist check.** Is this IP or user on the trusted list? The high-risk list? The privileged users list?
- **Cross-reference.** Does the same entity appear in other incidents?
- **Assessment.** True positive, false positive, benign positive, or undetermined?
- **Notes.** What did I look at, what did I find, why did I make the decision I made?

The investigation notes were something I underestimated early on. I re-opened an incident I'd reviewed two days earlier and couldn't reconstruct what I had checked. Good notes — specific about what you examined and why you drew a given conclusion — are what makes a case file useful to another analyst or for future reference.

### Incident classification

| Classification | When I used it |
|---|---|
| True Positive — Suspicious Activity | Real threat behavior, confirmed by investigation |
| Benign Positive — Suspicious but Expected | Real behavior matching the rule logic, but authorized or expected |
| False Positive — Incorrect Alert Logic | The rule fired but the activity doesn't match the detection intent |
| Undetermined | Not enough evidence to make a call; escalated |

The "Benign Positive" category came up more than I expected. The clearest example: the disabled-account rule fired on a service account that IT knew about — the account was disabled but an unupdated scheduled task was still sending credentials from an internal IP. Real behavior matching the rule exactly, but completely benign. Not a false positive (the rule worked correctly), just not malicious.

---

### Investigation Notes — Incident #SOC-2024-0045

**Analyst: J. Smith — May 12, 09:47 UTC**

IP 185.220.101.1 confirmed as a Tor exit node via the high-risk IP watchlist (entry added 2024-03-14). 247 failed sign-in attempts in 24 hours targeting 12 distinct user accounts across Exchange Online and SharePoint. Activity spans 01:00 to 23:00 UTC — spread consistently across the day is consistent with automated tooling, not manual attempts. No successful sign-ins from this IP. No VPN or proxy exception on file for this address.

**Assessment:** True positive — likely automated brute force or password spray via Tor infrastructure. All targeted accounts have MFA enabled (confirmed with identity team). Recommend confirming no active sessions or valid tokens exist for targeted accounts, blocking IP at Conditional Access, and flagging the ASN for broader monitoring.

**Follow-up — J. Smith, 14:22 UTC**

Confirmed with identity team: MFA enforced across all targeted accounts, zero successful authentications, no tokens to revoke. Closing as TP — suspicious activity confirmed, no breach. Conditional Access policy reviewed and in place.

---

### Investigation Notes — Incident #SOC-2024-0044

**Analyst: K. Patel — May 11, 10:15 UTC**

New account `m.johnson@contoso.com` created by `admin01@contoso.com`. Within 4 hours, same admin performed a Contributor role assignment on `rg-finance-prod`. No change request ticket found in ServiceNow or email trail. `admin01` is on the privileged users watchlist — activity from this account is expected to be infrequent and documented. Escalated to IT manager for confirmation.

**Follow-up — K. Patel, next shift**

IT manager confirmed this was a legitimate onboarding action for an incoming contractor. Fast-tracked onboarding, no ticket raised. Closing as Benign Positive. Recommended creating a pre-approved changes watchlist so future legitimate fast-tracks can be cross-referenced automatically rather than requiring manual escalation each time.

---

### Detection Engineering — Analytics Rule Configuration

There's a difference between having a query that finds suspicious results and having a detection that reliably produces useful alerts. For each rule I configured, I thought through:

| Setting | Value (failed sign-in rule) | Reasoning |
|---|---|---|
| Rule type | Scheduled | Runs on a defined cadence |
| Query frequency | Every 1 hour | Balances detection latency with cost |
| Query period | Last 2 hours | Overlap prevents gaps between runs |
| Alert threshold | Greater than 0 | The KQL `where FailedAttempts >= 10` handles the real threshold |
| Event grouping | Group all into one alert | Avoids one alert per IP per run |
| Entity mapping | IP Address → `IPAddress`, Account → `UserPrincipalName` | Enables entity timelines and cross-incident correlation |
| MITRE tactic | Credential Access — T1110 | Brute Force |

**What I got wrong initially:** My first version ran every 5 minutes with a 5-minute query period. This flooded the incident queue because every run was surfacing the same ongoing activity. Switching to 1-hour frequency / 2-hour query period fixed it — each alert now reflects a meaningful time block rather than a 5-minute snapshot.

---

## Phase 5 — Threat Hunting

Threat hunting is different from alert response. Instead of reacting to something the rules caught, you're proactively looking for things the rules might be missing.

The shift in mindset: you're not waiting for an alert, you're asking a question. "Is there behavior happening in my environment that my rules aren't set up to catch?" and then building a query to answer it.

### My hunting approach

- Start with an entity, a behavior pattern, or a specific gap in my alert coverage
- Extend the time window — 7 or 14 days instead of 24 hours
- Look for repetition — anything appearing consistently across time is worth noting
- Compare against expected behavior baselines
- Check whether the same entity appears across multiple log sources
- Document findings regardless of whether they produce incidents

### Detection rules vs. threat hunting

These two things are complementary, not alternatives. Rules catch obvious behavior efficiently at scale. Hunting catches behavior that was designed to evade rules, or patterns that are only visible when you look across a longer time window. Both are necessary for reasonable coverage.

---

## Phase 6 — Watchlists

Watchlists let you add context to detections and investigations without hardcoding values into queries. Every time a query needs to know whether an IP is trusted, risky, or associated with a privileged account, it references a watchlist rather than a static list in the query text.

### Watchlists I configured

**`trusted-ip-allowlist`** — Known-good IP ranges: corporate VPN exit nodes, office subnets, approved remote access addresses. Used in Query 4 to filter out known-good sources before surfacing unknowns.

**`high-risk-ip-addresses`** — IPs flagged as suspicious: Tor exit nodes, IPs from known malicious ASNs, addresses that appeared in high-volume failed-login activity before any rule fired.

**`privileged-users`** — Accounts with elevated Azure or Entra ID permissions: subscription owners, global admins, security team members. Sign-in events for these accounts warrant closer attention even when no alert fires.

### Sample watchlist data

**high-risk-ip-addresses.csv**

```csv
SearchKey,Description,Source,Priority,DateAdded
185.220.101.1,Tor exit node,ThreatIntel,High,2024-03-14
45.95.147.34,Suspicious auth source — brute force patterns observed,SOC,High,2024-04-02
103.86.99.12,Sub-threshold spray activity — hunting finding,SOC,Medium,2024-04-22
198.51.100.22,Unknown external — no VPN or proxy record,SOC,Low,2024-05-01
```

**privileged-users.csv**

```csv
SearchKey,DisplayName,Department,Role,Criticality
admin01@contoso.com,Domain Admin Account,Infrastructure,Global Administrator,High
secops.lead@contoso.com,Security Operations Lead,Security,Security Administrator,High
azure.owner@contoso.com,Azure Subscription Owner,Cloud,Owner,High
svc.sentinel@contoso.com,Sentinel Service Account,Security,Log Analytics Contributor,Medium
```

### Why context matters

A failed sign-in from a Tor exit node against a privileged account is a completely different situation from the same event from a corporate VPN. Watchlists let you embed that distinction into your queries so the enrichment happens automatically at query time — not as a separate lookup step during manual triage.

---

## Phase 7 — Workbook Reporting

The workbook was built to answer the questions a SOC lead would ask at a weekly standup: How many incidents this week? Are we resolving them faster or slower? What's generating the most volume? Are there recurring source IPs?

### Key metrics tracked during the lab period

| Metric | Value (7 days) | Trend |
|---|---|---|
| Total incidents | 58 | ↑ 14% from prior week |
| Mean time to respond | 4.2 hours | ↓ 18% — improving |
| Failed sign-ins (24h) | 342 | ↑ 41 from prior day |
| Disabled account attempts (7d) | 27 | ↑ 9 — worth monitoring |
| Incident closure rate | 76% | Stable |
| High-severity incidents | 16 (28%) | |
| Medium-severity incidents | 31 (53%) | |
| Low-severity incidents | 9 (16%) | |

### Workbook build notes

The workbook pulls from `SigninLogs`, `AuditLogs`, and `SecurityIncident` using KQL embedded in each tile. The time range filter at the top is a parameter that feeds every query — changing from "Last 7 days" to "Last 30 days" updates the whole workbook at once.

One tip: use `workspaceresource()` as the data source reference if you want the workbook portable across multiple workspaces without hardcoding resource IDs. I didn't do this at first and had to update several tiles manually when I tested on a second workspace.

---

## Phase 8 — Logic App Playbook Design

The playbook follows a human-in-the-loop model: automation handles the repetitive steps and routes information to the right people quickly, but a human must approve before any containment action runs.

### Why human approval?

The arguments for full automation are real — faster response, no dependence on analyst availability, consistent execution. But the arguments for human approval were stronger in my judgment: false positives can cause operational damage (an automated system disabling the wrong account at the wrong time is a serious incident in itself), and SOC teams should have visibility into what actions are being taken in their environment.

For lower-stakes actions like posting a Teams notification or adding an incident comment, full automation makes sense. For account disablement, I kept the human approval step. The speed cost is real but the risk cost of an automated false-positive containment is higher.

### Playbook flow

```
TRIGGER
└─ Microsoft Sentinel: When a Sentinel incident is created

ACTION — Entities: Get Accounts (Microsoft Sentinel)
└─ Parse affected accounts and IPs from the incident entity list

ACTION — Post message in a chat (Microsoft Teams)
└─ Notify #security-alerts: incident title, severity, entity summary, link

ACTION — Send approval email (Office 365 Outlook)
└─ On-call analyst receives Approve/Reject buttons
└─ Timeout: 4 hours

CONDITION — Response = 'Approve'?
│
├─ YES
│   ├─ Disable Azure AD user (Microsoft Entra ID)
│   ├─ Add incident comment: "Account disabled — approved by [analyst name]"
│   └─ Update incident: Status = Closed, Tag = "Contained"
│
└─ NO / Timeout
    ├─ Add incident comment: "Containment not approved / approval timeout"
    └─ Leave incident open for manual review
```

### The 4-hour timeout

Four hours was a deliberate choice. Long enough that an analyst dealing with another incident would still have time to respond. Short enough that an approval request isn't sitting unattended for an entire shift. When the timeout fires, the playbook closes gracefully without taking containment action and flags the incident for manual follow-up.

The "Failed" run in my run history was me intentionally testing this — I let the approval email expire without responding to verify the timeout path worked correctly. It did: the comment was added, the incident was left open, and the run logged the timeout as the reason.

### Error handling

Each step has a "Run After" configuration to handle upstream failures. If the Teams notification fails, the playbook still attempts the approval email. If the email step fails, the playbook logs the error and adds a comment to the incident noting that notification could not be sent. The containment logic and the notification logic are independent so a failure in one path doesn't kill the other.

---

## MITRE ATT&CK Mapping

| Detection | Tactic | Technique |
|---|---|---|
| Failed sign-ins by source IP | Credential Access | T1110 — Brute Force |
| Distributed sub-threshold hunt query | Credential Access | T1110.003 — Password Spraying |
| Disabled account sign-in attempts | Credential Access | T1078 — Valid Accounts |
| Sign-in from unknown IP (off allow-list) | Initial Access | T1078.004 — Cloud Accounts |
| New user + role assignment activity | Privilege Escalation | T1098 — Account Manipulation |
| Watchlist-based enrichment and filtering | Defense awareness | Evasion indicator detection |

---

## Coverage Gaps I Noticed

After building these detections I thought about what I was *not* detecting:

**Successful sign-in after a failure pattern** — my rule catches failed attempts but not the scenario where an attacker eventually succeeds after 9 tries (below the alert threshold). A useful additional detection: IP with 5+ failures followed by a success within the same hour.

**MFA bypass indicators** — not specifically watching for sign-ins where MFA was claimed satisfied but the location or device combination is unusual compared to the user's history.

**Impossible travel** — Sentinel has UEBA for this but I didn't configure it in this lab. A user signing in from two geographically distant locations within a short time window is a strong signal.

**Service principal abuse** — I focused on user sign-ins but service principals can also be compromised and used for unauthorized resource access. Adding detection logic for service principals making API calls outside their normal scope would strengthen coverage.

These are meaningful additions I plan to include when I extend this lab.

---

## Lessons Learned

**Tune before you deploy.** I set the failed-login threshold at 5 initially and got flooded with alerts immediately. In a production environment you'd baseline for several days to understand normal behavior before deciding what "abnormal" means.

**Investigation notes matter as much as the investigation.** I learned this when I re-opened an incident I'd reviewed two days earlier and couldn't reconstruct what I'd checked. Good notes — specific about what you examined and why you drew a conclusion — are what makes a case file useful to another analyst or future-you.

**"Connected" status is not the same as "data flowing correctly."** A connector can show green in the portal while silently losing events due to permission issues or network gaps. Running regular validation queries to check last-received timestamps per table is a more reliable health check than the status indicator alone.

**Context is what makes an alert actionable.** The watchlist integration was one of the most valuable parts of the lab. Knowing that 185.220.101.1 is a Tor exit node — right there in the query output, not as a separate lookup step — is the difference between efficient investigation and spending 15 minutes on a search engine for every IP.

**Automation needs guardrails.** The approval requirement in the playbook was the right call. In testing, the rule fired on a few borderline cases that would have been bad containment targets. Human review caught those. The speed cost of an approval step is real; the risk cost of a false-positive automated containment in production is higher.

---

## What I'd Do Differently

- Connect **Microsoft Defender for Endpoint** to add host-level telemetry alongside identity logs — the combination would make investigations significantly richer
- Document **false positives as I found them** in a formal tuning log rather than just noting them mentally
- Write a **decision runbook document** alongside the Logic App — describing the criteria for when to approve or reject containment, not just the automation steps
- **Baseline the environment first, set thresholds second** — measure what normal looks like before defining what abnormal means

---

## What I'm Working on Next

- SC-200 exam — aiming for summer
- Extending this lab with Microsoft Defender XDR integration
- Writing a formal detection-to-investigation case study for one of the incidents
- Building KQL detections for persistence and lateral movement scenarios (currently studying T1053, T1547)

---

## Repository Structure

```
microsoft-sentinel-soc-lab/
├── README.md
├── assets/
│   └── images/
│       ├── sentinel-overview.svg
│       ├── incident-queue.svg
│       ├── workbook-reporting.svg
│       └── playbook-flow.svg
├── kql/
│   ├── 01-failed-signins-by-source-ip.kql
│   ├── 02-disabled-account-signin-attempts.kql
│   ├── 03-new-user-followed-by-role-assignment.kql
│   ├── 04-watchlist-allowlist-example.kql
│   └── 05-threat-hunt-distributed-spray.kql
└── watchlists/
    ├── high-risk-ip-addresses.csv
    └── privileged-users.csv
```

---

## References

- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [KQL quick reference](https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference)
- [Azure Sentinel Training Lab on GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Training/Azure-Sentinel-Training-Lab)
- [SC-200 study guide on Microsoft Learn](https://learn.microsoft.com/en-us/credentials/certifications/security-operations-analyst/)
- John Savill's Azure Master Class — YouTube
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## Disclaimer

This is a personal learning project. All incidents, users, IP addresses, and security events are simulated or use placeholder data. The `contoso.com` domain is Microsoft's official example domain. No real employer, production environment, or client data is present in this repository.
