[Microsoft-Sentinel-Complete-README(2).md](https://github.com/user-attachments/files/27545720/Microsoft-Sentinel-Complete-README.2.md)
# Microsoft Sentinel SOC Lab Portfolio Project

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SOC%20Lab-blue)
![SIEM](https://img.shields.io/badge/Focus-SIEM%20%26%20SOC%20Operations-darkblue)
![KQL](https://img.shields.io/badge/Skill-KQL-purple)
![Incident Response](https://img.shields.io/badge/Skill-Incident%20Triage-red)
![SOAR](https://img.shields.io/badge/Skill-SOAR%20Playbooks-green)
![Status](https://img.shields.io/badge/Project-Portfolio%20Lab-success)

---

## Project Overview

This project is a hands-on Microsoft Sentinel SOC lab created to demonstrate practical security operations skills.

The goal of this lab was to work through the same type of workflow a junior SOC analyst would follow in a SIEM environment: reviewing telemetry, writing KQL queries, investigating suspicious activity, using watchlists for context, reviewing incidents, and designing a response playbook.

This project uses simulated and sanitized lab data. It does not contain real company, client, or production security data.

---

## Why I Built This Project

I built this project to strengthen my practical SOC analyst skills and show that I can do more than explain cybersecurity concepts in theory.

Microsoft Sentinel is a cloud-native SIEM and SOAR platform used for security monitoring, detection, investigation, and response. Through this lab, I practiced how a SOC analyst can use Sentinel to:

- collect and validate security logs,
- search and analyze activity using KQL,
- detect suspicious authentication behavior,
- investigate incidents,
- enrich detections with watchlists,
- review security trends with workbooks,
- and design basic response automation using playbooks.

This project helped me connect security monitoring, log analysis, identity security, incident response, and documentation into one practical SOC portfolio case study.

---

## Lab Focus

| Area | What I Practiced |
|---|---|
| SIEM Operations | Microsoft Sentinel workspace, incidents, alerts, data connectors, and dashboards |
| Log Analysis | Reviewing sign-in, audit, Azure Activity, and security event logs |
| KQL | Writing queries for failed sign-ins, disabled accounts, suspicious IPs, and watchlist filtering |
| Detection Engineering | Turning suspicious behavior into detection logic |
| Incident Triage | Reviewing severity, users, IPs, entities, ownership, and investigation notes |
| Threat Hunting | Searching for suspicious patterns before and beyond alerts |
| Watchlists | Using trusted IPs, privileged users, and suspicious IPs for enrichment |
| Workbooks | Creating visibility into SOC metrics and trends |
| SOAR | Designing a Logic App playbook for analyst notification and response actions |
| Documentation | Writing a clear GitHub case study that explains the full technical workflow |

---

## Tools and Technologies Used

- Microsoft Sentinel
- Azure Log Analytics Workspace
- Kusto Query Language
- Microsoft Entra ID sign-in logs
- Azure Activity logs
- Audit logs
- Security events
- Microsoft Sentinel analytics rules
- Microsoft Sentinel incidents
- Watchlists
- Workbooks
- Azure Logic Apps
- Microsoft Defender response concepts
- MITRE ATT&CK mapping

---

## Project Objectives

The objectives of this lab were to:

1. Set up and understand a Microsoft Sentinel lab environment.
2. Review how data connectors support SOC visibility.
3. Validate telemetry using KQL.
4. Write KQL queries for suspicious authentication activity.
5. Understand how analytics rules can generate incidents.
6. Practice an incident triage workflow.
7. Use watchlists to support detection tuning and enrichment.
8. Build a workbook-style reporting view.
9. Design a playbook workflow for response automation.
10. Document the project clearly for SOC analyst job applications.

---

# Lab Screenshots

The screenshots below represent the lab workflow using simulated or sanitized data.

---

## Microsoft Sentinel Overview Dashboard

![Microsoft Sentinel Overview Dashboard](assets/images/sentinel-overview.png)

This view gives a high-level overview of the Sentinel workspace, including open incidents, active alerts, impacted entities, connector health, analytics rules, recent incidents, and MITRE ATT&CK coverage.

---

## Incident Queue / Triage View

![Microsoft Sentinel Incident Queue](assets/images/incident-queue.png)

This view shows how incidents can be reviewed by severity, status, owner, product, tactic, last updated time, and incident number. The side panel supports investigation by showing the incident summary, affected entities, notes, and recommended next steps.

---

## Workbook / Reporting View

![Microsoft Sentinel Workbook](assets/images/workbook-reporting.png)

This workbook view shows SOC reporting metrics such as total incidents, active alerts, failed sign-ins, disabled account attempts, connector health, incident severity, MITRE ATT&CK coverage, and recent trends.

---

## Logic App Playbook Flow

![Microsoft Sentinel Playbook Flow](assets/images/playbook-flow.png)

This playbook represents a response workflow for suspicious sign-in activity. It includes incident trigger, entity parsing, analyst notification, approval, containment action, and incident update.

---

# End-to-End Lab Walkthrough

---

## Phase 1: Microsoft Sentinel Workspace Setup

The first step was to create or select a Log Analytics workspace and enable Microsoft Sentinel on top of it.

This is important because Sentinel depends on the workspace for log storage, query execution, analytics rules, investigations, and workbooks.

### What I learned

Microsoft Sentinel is not just a dashboard. It relies on Azure resources, proper configuration, and reliable data flow. Before building detections or investigating incidents, the workspace needs to be correctly set up and ready to receive logs.

### Evidence captured

- Sentinel workspace overview
- Resource group and workspace structure
- Microsoft Sentinel enabled on the workspace
- Portal screenshots showing the lab environment

---

## Phase 2: Data Connectors and Telemetry Ingestion

After enabling Sentinel, the next step was to review and understand data connectors.

A SIEM is only useful when it receives the right data. Without good telemetry, alerts and detections may either miss important activity or create too much noise.

### Data source mindset

When reviewing a data connector, I considered:

- what log table it populates,
- what security scenario it supports,
- what permissions are required,
- whether the data is useful for investigation,
- and whether it may create too many false positives.

### Example data sources reviewed

- Microsoft Entra ID sign-in logs
- Audit logs
- Azure Activity logs
- Windows security events
- Microsoft security alerts
- Threat intelligence indicators

### What I would validate after connecting data

- Connector status is healthy.
- Logs are arriving in the expected table.
- Events have recent timestamps.
- KQL queries return useful results.
- The data can support detection and investigation.

This phase showed me that data onboarding comes before detection engineering. A good detection depends on good data.

---

## Phase 3: KQL Detection Logic

KQL is one of the most important skills in Microsoft Sentinel. It allows analysts to search logs, investigate suspicious activity, and create detection logic.

In this phase, I wrote and reviewed KQL queries focused on authentication and identity-related activity.

### My detection workflow

1. Identify the suspicious behavior.
2. Select the correct log table.
3. Write the KQL query.
4. Test the query in Logs.
5. Review the output.
6. Think about possible false positives.
7. Convert useful logic into an analytics rule.
8. Tune the rule using thresholds, grouping, and watchlists.

### Detection scenarios covered

- repeated failed sign-ins from one source IP,
- disabled accounts still receiving sign-in attempts,
- new user creation followed by role assignment activity,
- suspicious sign-ins from IPs not found in an allow-list.

This helped me think more like a SOC analyst and not just someone clicking through built-in dashboards.

---

# KQL Queries Included

---

## 1. Failed Sign-ins by Source IP

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

### Why I included this query

This query helps identify repeated failed sign-ins from the same source IP. It can support investigation of brute force attempts, password spraying, misconfigured applications, or suspicious authentication behavior.

---

## 2. Disabled Accounts Receiving Sign-in Attempts

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

### Why I included this query

Disabled accounts should not normally be active authentication targets. Repeated attempts may indicate stale credentials, legacy automation, password spraying, or an attacker trying to reuse old account information.

---

## 3. New User Created Followed by Role Assignment Activity

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

### Why I included this query

This query looks for new account creation followed by role assignment activity within a short time window. This can help identify suspicious provisioning, risky privilege assignment, or possible privilege escalation activity.

---

## 4. Watchlist Allow-list Example

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

### Why I included this query

This query shows how a watchlist can be used to separate trusted IP addresses from unknown or suspicious sources. This is useful for reducing false positives while still keeping visibility into unusual activity.

---

# Phase 4: Incident Triage and Investigation

Once an alert becomes an incident, the work changes from detection to investigation.

In this phase, I focused on how a SOC analyst would review an incident and decide what should happen next.

### Questions I asked during triage

- What rule created the incident?
- Is the severity correct?
- Which user, IP address, host, or application is involved?
- Is the activity repeated or isolated?
- Is this likely a true positive, false positive, or unclear?
- Is there enough evidence to escalate?
- What notes should be left for the next analyst?

### Typical Sentinel incident actions

- assign an owner,
- update the incident status,
- review alerts and entities,
- add investigation comments,
- apply tags,
- classify the incident,
- escalate or close with clear notes.

### Why this matters

Incident documentation is a key part of SOC work. A good analyst should leave enough information for another team member to understand what was reviewed, what was found, and why a decision was made.

---

# Phase 5: Threat Hunting with KQL

Threat hunting means searching for suspicious activity before relying only on alerts.

In this phase, I used KQL to think through possible suspicious behavior and search across relevant logs.

### Hunting approach used

- Start with an entity such as a user, IP address, or host.
- Expand the time range.
- Look for repeated patterns.
- Compare the activity with expected behavior.
- Check whether the same source appears in other events.
- Document the findings clearly.

### Example hunting questions

- Is one IP address targeting many users?
- Are disabled accounts still receiving sign-in attempts?
- Was a new account created before privileged activity?
- Are sign-ins coming from unusual locations?
- Is the source IP trusted or unknown?
- Is the activity repeated over time?

Threat hunting helped me think beyond individual alerts and look for wider patterns.

---

# Phase 6: Watchlists for Enrichment and Tuning

Watchlists were included to show how SOC teams can add context to detections and investigations.

### Example watchlist use cases

- privileged users,
- trusted IP addresses,
- approved VPN egress IPs,
- sensitive systems,
- known suspicious IPs,
- service accounts.

### Why watchlists matter

Not every event should be treated the same way. Context matters.

For example, a failed sign-in from a known internal VPN address may be less suspicious than the same activity from an unknown external IP. Watchlists help reduce noise and improve investigation quality.

---

# Phase 7: Threat Intelligence Concepts

Threat intelligence can help enrich investigations when an IP address, domain, file hash, or other indicator is known to be suspicious.

In this project, I treated threat intelligence as supporting context, not automatic proof of compromise.

### My approach to threat intelligence

- Use indicators to support investigation.
- Confirm whether the activity matches the environment.
- Avoid assuming every indicator match is malicious.
- Combine threat intelligence with log evidence.
- Escalate when the activity is repeated, high-confidence, or linked to other suspicious behavior.

---

# Phase 8: Workbook Reporting

Workbooks are useful because SOC teams need visibility into security activity, not only individual alerts.

The workbook view in this project focused on:

- total incidents,
- active alerts,
- failed sign-ins,
- disabled account attempts,
- analytics rule status,
- connector health,
- incident severity,
- MITRE ATT&CK coverage,
- recent incident trends.

### Why this matters

SOC reporting helps analysts and managers understand workload, risk areas, noisy detections, and the overall health of monitoring.

---

# Phase 9: Logic App Playbook Design

The final part of the project was designing a Sentinel playbook workflow using Azure Logic Apps.

The playbook was designed for suspicious sign-in activity and includes analyst approval before containment actions. This is important because fully automated containment can create business risk if the alert is a false positive.

### Example playbook flow

1. A Sentinel incident is created or updated.
2. The playbook parses the incident entities.
3. A SOC analyst or Teams channel is notified.
4. Analyst approval is requested.
5. If approved:
   - disable the user account,
   - submit or block the suspicious IP where supported,
   - update the incident with response notes.
6. If not approved:
   - add a comment explaining that containment was not approved.
7. Update the incident status, comments, and tags.

### Why this matters

This demonstrates the connection between SIEM and SOAR. Automation should support analysts, reduce repetitive work, and leave a clear audit trail.

---

# Sample Watchlists

---

## High-Risk IP Watchlist

```csv
SearchKey,Description,Owner,Priority
185.220.101.1,Tor exit node sample,ThreatIntel,High
45.95.147.34,Suspicious authentication source sample,SOC,High
103.86.99.12,Unapproved external address sample,SOC,Medium
```

---

## Privileged Users Watchlist

```csv
SearchKey,DisplayName,Department,Criticality
admin01@contoso.com,Domain Admin Account,Infrastructure,High
secops.lead@contoso.com,Security Operations Lead,Security,High
azure.owner@contoso.com,Azure Subscription Owner,Cloud,High
```

---

# Sample Incident Summary

## Incident Title

Suspicious Sign-in Attempts Against Disabled Accounts

## Severity

Medium

## Summary

Multiple sign-in attempts were detected against disabled user accounts. This may indicate stale credentials, legacy automation, password spraying, or an attacker attempting to reuse old account information.

## Evidence Reviewed

- affected user accounts,
- source IP addresses,
- sign-in failure reason,
- time window of activity,
- applications involved,
- number of attempts,
- whether the source was trusted or unknown.

## Analyst Assessment

The activity is suspicious because disabled accounts should not normally receive active sign-in attempts. Repeated attempts from the same source require further review to confirm whether the activity is caused by a misconfigured internal process or external malicious behavior.

## Recommended Next Steps

1. Confirm whether the source IP is trusted.
2. Check if the affected accounts are linked to old services or automation.
3. Review additional sign-in activity from the same IP address.
4. Check whether other users were targeted.
5. Escalate if the source is external, repeated, or linked to other suspicious activity.

## Containment Considerations

- block or monitor the source IP if confirmed malicious,
- notify identity administrators if legacy automation is involved,
- review account lifecycle controls,
- tune the detection only after the root cause is understood.

## Closing Note Example

Incident reviewed and documented. Sign-in attempts were observed against disabled accounts. Further validation is required to confirm whether the source is malicious or linked to a legacy internal process.

---

# Detection Philosophy

The goal of this project was not to create many noisy alerts.

The goal was to show that I can:

- translate suspicious behavior into a query,
- understand why the behavior matters,
- review possible false positives,
- investigate the output,
- document the case,
- and think through the correct next action.

This is the type of thinking I would apply as a junior SOC analyst.

---

# Incident Handling Mindset

When reviewing an incident, I focus on:

- what triggered the alert,
- what evidence supports the severity,
- which entity matters most,
- whether the activity is normal or suspicious,
- whether the case should be escalated,
- and what should be written in the investigation notes.

Clear documentation is important because SOC work is team-based. Another analyst should be able to read the notes and understand the decision.

---

# MITRE ATT&CK Mapping

This project includes examples that can be mapped to attacker behavior.

| Activity | Possible MITRE ATT&CK Area |
|---|---|
| Repeated failed sign-ins | Credential Access |
| Password spraying patterns | Credential Access |
| Suspicious sign-in locations | Initial Access |
| New account followed by role activity | Privilege Escalation |
| Suspicious account creation | Persistence |
| Unusual access patterns | Discovery |
| Allow-list comparison | Detection tuning / defense awareness |

The purpose of this mapping is to think beyond raw logs and understand what the activity may mean from an attacker behavior perspective.

---

# What I Learned

This project helped me understand that Microsoft Sentinel is not only about viewing alerts. A SOC analyst needs to understand the full process:

- where the data comes from,
- how to query it,
- how to detect suspicious behavior,
- how to review incidents,
- how to reduce false positives,
- how to document findings,
- and how automation can support response.

The most valuable part of the lab was working with KQL and thinking through how a detection becomes an investigation.

---

# Recruiter Summary

This project demonstrates my practical understanding of Microsoft Sentinel and SOC workflows.

It shows that I can:

- explain how Microsoft Sentinel supports security operations,
- understand the role of data connectors,
- write KQL queries for investigation and detection,
- review and document incidents,
- use watchlists for context and tuning,
- understand workbook reporting,
- and design a basic playbook for response automation.

This project supports my interest in SOC Analyst, Cybersecurity Analyst, IT Security Specialist, and Security Operations roles.

---

# Resume Bullets

- Built and documented a Microsoft Sentinel SOC home lab covering workspace setup, data connectors, KQL detections, incident triage, watchlists, workbooks, and playbook design.
- Created KQL queries to investigate suspicious authentication activity, disabled-account sign-in attempts, failed sign-in patterns, and identity-related privilege activity.
- Practiced Microsoft Sentinel incident handling by reviewing severity, entities, ownership, evidence, status, classification, and analyst notes.
- Used watchlist concepts to enrich detections, separate trusted activity from suspicious sources, and reduce alert noise.
- Designed a Sentinel playbook workflow using Azure Logic Apps for SOC notification, analyst approval, containment steps, and incident updates.

---

# Interview Talking Points

## What did you build?

I built a Microsoft Sentinel SOC lab to practice how a security analyst works with alerts, incidents, KQL queries, watchlists, workbooks, and response playbooks.

## What was the most important part of the project?

The most valuable part was writing and understanding the KQL queries because it helped me think about suspicious behavior, false positives, and how alerts should be investigated.

## How did you practice incident handling?

I reviewed sample incidents by looking at severity, affected users, IP addresses, status, ownership, related entities, evidence, and the type of notes an analyst should leave before escalation or closure.

## Why did you include watchlists?

I included watchlists because real SOC teams need context. A watchlist can help separate trusted IPs, privileged users, or known systems from activity that needs more attention.

## Why did you include a playbook?

I included a playbook to show how Sentinel can support response automation. The design uses analyst approval before containment, which is safer than fully automatic action.

---

# Future Improvements

To improve this project further, I plan to:

- add exported analytics rule templates,
- include more KQL hunting queries,
- document one false positive and how it was tuned,
- add a short incident investigation report,
- include a screen recording of a rule generating an incident,
- expand the lab with Microsoft Defender XDR integration,
- and create a small detection-to-response case study.

---

# Repository Structure

```text
microsoft-sentinel-soc-lab/
├── README.md
├── assets/
│   └── images/
│       ├── sentinel-overview.png
│       ├── incident-queue.png
│       ├── workbook-reporting.png
│       └── playbook-flow.png
├── docs/
│   ├── 01-lab-walkthrough.md
│   ├── 02-detection-and-hunting.md
│   ├── 03-incident-response-and-playbooks.md
│   └── 04-recruiter-notes.md
├── kql/
│   ├── 01-failed-signins-by-source-ip.kql
│   ├── 02-disabled-account-signin-attempts.kql
│   ├── 03-new-user-followed-by-role-assignment.kql
│   └── 04-watchlist-allowlist-example.kql
├── reports/
│   └── sample-incident-summary.md
└── watchlists/
    ├── high-risk-ip-addresses.csv
    └── privileged-users.csv
```

---

# References

- Microsoft Sentinel documentation:  
  https://learn.microsoft.com/en-us/azure/sentinel/

- Microsoft Sentinel training lab:  
  https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Training/Azure-Sentinel-Training-Lab

- Kusto Query Language documentation:  
  https://learn.microsoft.com/en-us/kusto/query/

---

# Disclaimer

This is a personal home lab project created for learning and portfolio purposes. All screenshots, incidents, users, IP addresses, and security events are simulated, sanitized, or sample lab data. No real employer, client, or production security data is included.
