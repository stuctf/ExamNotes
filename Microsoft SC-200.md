# SC-200 Microsoft Security Operations Analyst - Study Notes

**Author:** Stuart Mackay
<!-- Author: Stuart Mackay -->

## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE4Myp3)
- [Official Microsoft Learning Path](https://docs.microsoft.com/en-us/certifications/exams/sc-200)

  
## Notes from Microsoft Learn & Microsoft Docs:

## Mitigate threats using Microsoft 365 Defender

### Introduction to Microsoft 365 threat protection
**Microsoft 365 Defender** is an integrated threat protection suite with solutions that detect malicious activity across email, endpoints, applications, and identity.

The graphic below shows which product provides visibility into which attack vector:
![Pasted image 20221121135959](https://user-images.githubusercontent.com/66924945/219874097-d0e2b990-79e1-461a-b400-f431d8bb0e4b.png)

  
How Microsoft 365 Defender and Microsoft Sentinel are integrated in a Modern Security Operations Center (SOC):
![Pasted image 20230203122305](https://user-images.githubusercontent.com/66924945/219874120-548a75ed-6ee6-45fe-bbdf-a7d46ecf01b1.png)

Teams involved:
![Pasted image 20230203122438](https://user-images.githubusercontent.com/66924945/219874157-e84ea5cb-9230-4912-aed3-84648090e503.png)


### Mitigate incidents using Microsoft 365 Defender
Incident Overview page, based on Cyber Kill Chain and MITRE ATT&CK:
![Pasted image 20230203135527](https://user-images.githubusercontent.com/66924945/219874168-73e716b4-943a-4a5b-9f18-b6a295b1d584.png)

  
Individual alerts can be accessed via left hand bar, Incidents & Alerts > Alerts
  
Automated investigations can be set in the portal, Microsoft recommends full automation, which includes automatic remediation
  
The **unified Action center** of the Microsoft 365 Defender portal lists pending and completed remediation actions for your devices, email & collaboration content, and identities in one location.
  
**Advanced hunting** is a query-based threat-hunting tool that lets you explore up to 30 days of raw data.

**Threat analytics** is a threat intelligence solution from expert Microsoft security researchers.
 - Includes a dashboard
 - Threat tags included in reports: -   Ransomware, Phishing, Vulnerability, Activity group

Incidents can be classed as "True Alerts"

### Protect your identities with Azure AD Identity Protection
**Identity Protection** is a solution built into Azure AD that's designed to protect your identities through a three-part process:
 - Detect
 - Investigate
 - Remediate

Types of risk:
 - User - When account or identity is compromised.  Detected by unusual behaviour and leaks
 - Sign-in risk - Is user authorized? - Location and IP based
Self & Administrator remediations available

  
### Remediate risks with Microsoft Defender for Office 365
**Automated Investigation and Response (AIR) workflow:**
1. Alert triggered, security playbook initiates
2. Depending on alert, automated investigation begins, manual optional
3. If more alerts triggered, the scope of automatic investigation increases
4. Details and results available throughout, also via API - Playbook log available
5. Remediation based on results and recommendations need approval from security operations team

![Pasted image 20220908132847](https://user-images.githubusercontent.com/66924945/219874198-cd6bbd3c-5c64-42a3-b119-ccfebc047c3a.png)


**Microsoft Defender for Office 365 Safe Attachments** - Scans email for malware using Microsoft servers

**Microsoft Defender for Office 365 Safe Links** Blocks malicious URLs

**Microsoft Defender for Office 365 anti-phishing** - Checks domain for legitimacy

**Simulating attacks:**
- **Threat trackers** - provides the latest intelligence on prevailing cybersecurity issues.
- **Threat Explorer** - Real-time report to identify and analyze recent threats
- **Attack Simulator** - Can run realistic attack scenarios to identify vulnerabilities

**Microsoft Defender for Office 365 is a cloud-based email filtering service that helps protect your organization. No agents are deployed.**
  
  
### Safeguard your environment with Microsoft Defender for Identity
**Microsoft Defender for Identity** is a cloud-based security solution that leverages your on-premises Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

![Pasted image 20230203142403](https://user-images.githubusercontent.com/66924945/219874217-ec42516a-d6b1-475d-994e-3702e176be8c.png)

Microsoft Defender for Identity provides the following benefits:

-   Monitor users, entity behavior, and activities with learning-based analytics
-   Protect user identities and credentials stored in Active Directory
-   Identify and investigate suspicious user activities and advanced attacks throughout the kill chain
-   Provide clear incident information on a simple timeline for fast triage

Provides suggestions on improving security posture and attack surface


Identifies suspicious activities and advanced attacks across the cyber-attack kill-chain:
![Pasted image 20230203142608](https://user-images.githubusercontent.com/66924945/219874230-9452b38a-ffa7-4cc1-980d-c9c00598a2db.png)

From Microsoft:
*"For example, in the reconnaissance stage, LDAP reconnaissance is used by attackers to gain critical information about the domain environment. Information that helps attackers map the domain structure, and identify privileged accounts for use later. This detection is triggered based on computers performing suspicious LDAP enumeration queries or queries targeting sensitive groups.*

*Brute force attacks are a common way to compromise credentials. This is when an attacker attempts to authenticate with multiple passwords on different accounts until a correct password is found or by using one password in a large-scale password spray that works for at least one account. Once found, the attacker logs in using the authenticated account. Microsoft Defender for Identity can detect this when it notices multiple authentication failures occurring using Kerberos, NTLM, or use of a password spray.*

*The next stage is when attackers attempt to move laterally through your environment, using pass-the-ticket, for example. Pass-the-ticket is a lateral movement technique in which attackers steal a Kerberos ticket from one computer and use it to gain access to another computer by reusing the stolen ticket. In this detection, a Kerberos ticket is being used on two (or more) different computers.*

*Ultimately, attackers want to establish domain dominance. One method, for example is the DCShadow attack. This attack is designed to change directory objects using malicious replication. This attack can be performed from any machine by creating a rogue domain controller using a replication process. If this occurs, Microsoft Defender for Identity triggers an alert when a machine in the network tries to register as a rogue domain controller."*

![Pasted image 20230203142905](https://user-images.githubusercontent.com/66924945/219874255-13292ea0-5de3-4cd8-b19d-8ab56730d540.png)
The Microsoft Defender for Identity sensor has the following core functionality:

-   Capture and inspect domain controller network traffic (local traffic of the domain controller)
-   Receive Windows events directly from the domain controllers
-   Receive RADIUS accounting information from your VPN provider
-   Retrieve data about users and computers from the Active Directory domain
-   Perform resolution of network entities (users, groups, and computers)
-   Transfer relevant data to the Microsoft Defender for Identity cloud service

Microsoft Defender for Identity security alerts are divided into the following categories or phases, like the phases seen in a typical cyber-attack kill chain:

-   Reconnaissance phase alerts
-   Compromised credential phase alerts
-   Lateral movement phase alerts
-   Domain dominance phase alerts
-   Exfiltration phase alerts

Integration with other tools:
![Pasted image 20230218163125](https://user-images.githubusercontent.com/66924945/219874386-76f3d1ce-2ad7-475b-839d-ecc234b4d7e0.png)


While Microsoft Defender for Identity monitors the traffic on your domain controllers, Microsoft Defender for Endpoint monitors your endpoints, together providing a single interface from which you can protect your environment. Once Microsoft Defender for Endpoint and Microsoft Defender for Identity are integrated, you can click on an endpoint to view Microsoft Defender for Identity alerts in the Microsoft Defender for Endpoint portal.

**Microsoft Defender for Identity is a cloud-based security solution that leverages your on-premises Active Directory**

**Microsoft Defender for Identity can identify rogue users and attackers' attempts to gain information such as usernames, users' group membership, IP addresses assigned to devices, resources, and more, using various methods.**
  
  
### Secure your cloud apps and services with Microsoft Defender for Cloud Apps
**Cloud access security broker (CASBs)** properties:
 - Intermediaries between users and all of the cloud services they access. 
 - Apply monitoring and security controls over users and data. 
  
Microsoft Defender for Cloud Apps is a CASB that helps you identify and combat cyberthreats across Microsoft and third-party cloud services.

High level overview of information flow using Defender for Cloud Apps:
![Pasted image 20230218163318](https://user-images.githubusercontent.com/66924945/219874460-b739cd08-3e86-4a19-897b-3753f3bd834f.png)


There are four elements to the Defender for Cloud Apps framework:

-   **Discover and control the use of Shadow IT**
-   **Protect your sensitive information anywhere in the cloud**: Via DLP
-   **Protect against cyberthreats and anomalies**: Detect unusual behavior across apps, users, and potential ransomware. Defender for Cloud Apps combines multiple detection methods, including anomaly, user entity behavioral analytics (UEBA), and rule-based activity detections, to show who is using the apps in your environment, and how they're using them.
-   **Assess the compliance of your cloud apps**: Assess if your cloud apps comply with regulations and industry standards specific to your organization. Defender for Cloud Apps helps you compare your apps and usage against relevant compliance requirements, prevent data leaks to noncompliant apps, and limit access to regulated data.
  

### Respond to data loss prevention alerts using Microsoft 365
To view DLP Alerts from DLP Policies created in Microsoft Purview use the following steps:
1.  In the Microsoft Purview compliance portal, [https://compliance.microsoft.com](https://compliance.microsoft.com/) on the left menu pane under Solutions, select **Data loss prevention**.
2.  Select the **Alerts** tab to view the DLP alerts dashboard.

**File Policy** is used for DLP
  
### Manage insider risk in Microsoft Purview
The insider risk management solution in **Microsoft Purview** leverages the Microsoft Graph, security services and connectors to human resources (HR) systems like SAP, to obtain real-time native signals such as file activity, communications sentiment, abnormal user behaviors, and resignation date. A set of configurable policy templates tailored specifically for risks – such as digital IP theft, confidentiality breach, and HR violations – use machine learning and intelligence to correlate these signals to identify hidden patterns and risks that traditional or manual methods might miss. These built-in policy templates allow you to identify and mitigate risky activities while balancing employee privacy versus organization risk with privacy-by-design architecture. Finally, end-to-end integrated workflows ensure that the right people across security, HR, legal, and compliance are involved to quickly investigate and take action once a risk has been identified.
  
**Insider risk management policies** are created using pre-defined templates and policy conditions.
  
Insider risk management uses **audit logs** for user insights and activities configured in policies.

Alerts can be assigned to a case so that you can conduct a detailed investigation from the **Cases** section in the insider risk management console.

## Mitigate threats using Microsoft Defender for Endpoint

### Protect against threats with Microsoft Defender for Endpoint
Defender uses **Endpoint behavioural sensors**, **Cloud security analytics** and **Threat intelligence**

**Requires a subscription to the Microsoft Defender for Endpoint online service.**

Provides the following **solutions:**
-   Real-time endpoint detection and response (EDR) insights correlated with endpoint vulnerabilities
-   Linked machine vulnerability and security configuration assessment data in the context of exposure discovery
-   Built-in remediation processes through Microsoft Intune and Microsoft Endpoint Manager

**Attack Surface Reduction via:**
-   **Hardware-based isolation** protects and maintains the integrity of the system as it starts and while it's running, and validates system integrity through local and remote attestation. Container isolation for Microsoft Edge helps protect the host operating system from malicious websites.
-   **Application control** moves away from the traditional application trust model where all applications are assumed trustworthy by default to one where applications must earn trust in order to run.
-   **Exploit protection** applies mitigation techniques to apps your organization uses, both individually and organization-wide.
-   **Network protection** extends the malware and social engineering protection offered by Microsoft Defender SmartScreen in Microsoft Edge to cover network traffic and connectivity on your organization's devices.
-   **Controlled folder access** helps protect files in key system folders from changes made by malicious and suspicious apps, including file-encrypting ransomware malware.
-   **Attack surface reduction** reduces the attack surface of your applications with intelligent rules that stop the vectors used by Office-, script-, and mail-based malware.
-   **Network firewall** uses host-based, two-way network traffic filtering that blocks unauthorized network traffic flowing into or out of the local device.

Alerts with the same attack techniques or attributed to the same attacker are aggregated into an entity called an **incident**.

**Security Operations Dashboard** provides a high-level overview of detections

The **automated investigation feature** uses various inspection algorithms, and processes used by analysts (such as playbooks) to examine alerts and take immediate remediation action to resolve breaches.

**Threat Hunting**
 - You can use threat-hunting queries to build custom detection rules
 - From **Microsoft 365 Defender portal** select Hunting > Advanced Hunting

### Deploy the Microsoft Defender for Endpoint environment
Defender is available on: Windows, MacOS, Linux, Android, iOS

The Microsoft Defender for Endpoint sensor requires **Microsoft Windows HTTP (WinHTTP)** to report sensor data and communicate with the Microsoft Defender for Endpoint service.
The WinHTTP configuration setting is independent of the Windows Internet (WinINet) internet browsing proxy settings and can only discover a proxy server by using the following discovery methods:
- Transparent proxy
- Web Proxy Autodiscovery Protocol (WPAD)

**Onboard/Offboard** devices in the Microsoft 365 Defender portal
 - Multiple deployment options offered depending on OS

Using **role-based access control (RBAC)**, you can create roles and groups within your security operations team to grant appropriate access to the portal

The default data retention period in Microsoft 365 Defender for Endpoint is **Six months**

Storage settings are configured in **Manage portal system settings**

### Implement Windows security enhancements with Microsoft Defender for Endpoint

Attack Surface Reduction components:
**Attack surface reduction rules**
 - Reduce vulnerabilities (attack surfaces) in your applications with intelligent rules that help stop malware. (Requires Microsoft Defender Antivirus).
**Hardware-based isolation**
- Protect and maintain the integrity of a system as it starts and while it's running. Validate system integrity through local and remote attestation. Use container isolation for Microsoft Edge to help guard against malicious websites.
**Application control**
- Use application control so that your applications must earn trust in order to run.
**Exploit protection**
- Help protect operating systems and apps your organization uses from being exploited. Exploit protection also works with third-party antivirus solutions.
**Network protection**
- Extend protection to your network traffic and connectivity on your organization's devices. (Requires Microsoft Defender Antivirus)
**Web protection**
- Secure your devices against web threats and help you regulate unwanted content.
**Controlled folder access**
- Help prevent malicious or suspicious apps (including file-encrypting ransomware malware) from making changes to files in your key system folders (Requires Microsoft Defender Antivirus)
**Device control**
- Protects against data loss by monitoring and controlling media used on devices, such as removable storage and USB drives, in your organization.

Example: Blocking process creation from PSExec 

### Perform device investigations in Microsoft Defender for Endpoint
![Pasted image 20230218163434](https://user-images.githubusercontent.com/66924945/219874524-c55e69f4-e693-46ef-ae8c-be96d33a7e96.png)


**Behavioural Blocking Overview** 
![Pasted image 20230218163509](https://user-images.githubusercontent.com/66924945/219874552-6d488f12-8239-4cc7-b044-8794e53154e2.png)

Behavior-based detections are named according to the MITRE ATT&CK Matrix for Enterprise

**Flag** events for further review
**EDR in block mode** allows for blocking even when third party AV is used
Devices without alerts in **30 days** will not show in the device list

### Perform actions on a device using Microsoft Defender for Endpoint
You can perform the following containment actions:
-   Isolate Device
-   Restrict app execution
-   Run antivirus scan

You can perform the following investigation actions:
-   Initiate Automated Investigation
-   Collect investigation package
-   Initiate Live Response Session

**Investigation Package** includes:
- **Autoruns**
- **Installed programs** (as CSV file)
- **Network connections**
	-   ActiveNetConnections.txt – Displays protocol statistics and current TCP/IP network connections. It provides the ability to look for suspicious connectivity made by a process.
	-   Arp.txt – Displays the current address resolution protocol (ARP) cache tables for all interfaces.
	-   ARP cache can reveal other hosts on a network that have been compromised or suspicious systems on the network that might have been used to run an internal attack.
	-   DnsCache.txt - Displays the contents of the DNS client resolver cache, which includes both entries preloaded from the local Hosts file and any recently obtained resource records for name queries resolved by the computer. This can help in identifying suspicious connections.
	-   IpConfig.txt – Displays the full TCP/IP configuration for all adapters. Adapters can represent physical interfaces, such as installed network adapters, or logical interfaces, such as dial-up connections.
	-   FirewallExecutionLog.txt and pfirewall.log
- **Prefetch files**
	-   Prefetch folder – Contains a copy of the prefetch files from %SystemRoot%\Prefetch. It's suggested to download a prefetch file viewer to view the prefetch files.
	-   PrefetchFilesList.txt – Contains the list of all the copied files that can be used to track if there were any copy failures to the prefetch folder
- **Processes** (as CSV file)
- **Scheduled tasks** (as CSV file)
- **Security event log**
- **Services** (as CSV file)
- **Windows Server Message Block** (SMB) sessions
	- Lists shared access to files, printers, serial ports, and miscellaneous communications between nodes on a network. This can help identify data exfiltration or lateral movement. It also contains files for SMBInboundSessions and SMBOutboundSession. If there are no sessions (inbound or outbound), you'll get a text file that tells you that there are no SMB sessions found.
- **System information**
	- Contains a SystemInformation.txt file that lists system information such as OS version and network cards.
- **Temp directories** (for all users)
- **Users and groups**
- **WdSupportLogs**
	- Provides the MpCmdRunLog.txt and MPSupportFiles.cab.
- **CollectionSummaryReport.xls**
	- This file is a summary of the investigation package collection, it contains the list of data points, the command used to extract the data, the execution status, and the error code if there's failure. You can use this report to track if the package includes all the expected data and identify if there were any errors.

**Live Response** features:
-   Run basic and advanced commands to do investigative work on a device.
-   Download files such as malware samples and outcomes of PowerShell scripts.
-   Download files in the background (new!).
-   Upload a PowerShell script or executable to the library and run it on a device from a tenant level.
-   Take or undo remediation actions.

### Perform evidence and entities investigations using Microsoft Defender for Endpoint
The **Deep analysis feature** executes a file in a secure, fully instrumented cloud environment. Deep analysis results show the file's activities, observed behaviors, and associated artifacts, such as dropped files, registry modifications, and communication with IPs. Deep analysis currently supports extensive analysis of portable executable (PE) files (including .exe and .dll files).

When you investigate a **user account entity**, you'll see:
-   User account details and logged on devices, role, log-on type, and other details
-   Overview of the incidents and user's devices
-   Alerts related to this user
-   Observed locations in the organization (devices logged on to)

You can find information from the following sections in the **IP address view**:
-   IP worldwide
-   Reverse DNS names
-   Alerts related to this IP
-   IP in organization
-   Prevalence

You can see information from the following sections in the **URL view:**
-   URL details, Contacts, Nameservers
-   Alerts related to this URL
-   URL in organization
-   Most recent observed devices with URL

### Configure and manage automation using Microsoft Defender for Endpoint
The Advanced features page in the Settings/General area provides the following automation-related settings:
- Automated Investigation
- Enable EDR in block mode
- Automatically resolve alerts
- Allow or block file

Enable the **File Content Analysis** capability so that certain files and email attachments can automatically be uploaded to the cloud for more inspection in Automated investigation

Enable the **Memory Content Analysis** capability if you would like Microsoft Defender for Endpoint to automatically investigate memory content of processes. When enabled, memory content might be uploaded to Microsoft Defender for Endpoint during an Automated investigation.

### Configure for alerts and detections in Microsoft Defender for Endpoint
You can configure Defender for Endpoint to send email notifications to specified recipients for new alerts. This feature enables you to identify a group of individuals who will immediately be informed and can act on alerts based on their severity.

Only users with **'Manage security settings'** permissions can configure email notifications. If you've chosen to use basic permissions management, users with Security Administrator or Global Administrator roles can configure email notifications.

**Indicator of compromise** (IoCs) matching:
- IPs, Domains & URLs
- Certificates
- Files
Limit of 15,000 indicators per tenant

### Utilize Vulnerability Management in Microsoft Defender for Endpoint
To discover endpoint vulnerabilities and misconfiguration, vulnerability management uses the same agentless built-in **Defender for Endpoint sensors** to reduce cumbersome network scans and IT overhead.

It also provides:
-   Real-time device inventory - Devices onboarded to Defender for Endpoint automatically report and push vulnerability and security configuration data to the dashboard.
-   Visibility into software and vulnerabilities - Optics into the organization's software inventory and software changes like installations, uninstalls, and patches. Newly discovered vulnerabilities are reported with actionable mitigation recommendations for 1st and 3rd party applications.
-   Application runtime context - Visibility on application usage patterns for better prioritization and decision-making.
-   Configuration posture - Visibility into organizational security configuration or misconfigurations. Issues are reported in the dashboard with actionable security recommendations.

The **Weaknesses page** lists the software vulnerabilities your devices are exposed to by listing the Common Vulnerabilities and Exposures (CVE) ID. You can also view the severity, Common Vulnerability Scoring System (CVSS) rating, prevalence in your organization, corresponding breach, threat insights, and more.

**Security baselines assessment** helps you to continuously and effortlessly monitor your organization's security baselines compliance and identify changes in real time.

**Exploit availability graphs**  show each device counted only once based on the highest level of known exploit


## Create queries for Microsoft Sentinel using Kusto Query Language (KQL)

### Construct KQL statements for Microsoft Sentinel
A **KQL query** is a read-only request to process data and return results. The request is stated in plain text, using a data-flow model designed to make the syntax easy to read, write, and automate. The query uses schema entities organized in a hierarchy similar to SQL's: databases, tables, and columns.

**Search operator example:**
```
search "err"

search in (SecurityEvent,SecurityAlert,A*) "err"
```
- The search will search across all columns in tables specified

**Where operator example:**
```
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"
```

**Let statements** allow for the creation of variables to be used in later statements.
Example:
```
let suspiciousAccounts = datatable(account: string) [
    @"\administrator", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent | where Account in (suspiciousAccounts)
```

The **extend operator** will create calculated columns and append the new columns to the result set.
Example:
```
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
```
The **order by operator** can utilize any column or multiple columns by using a comma separator. Each column can be ascending or descending. The default order for a column is descending.
Example:
```
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
```

The **project operators** control what columns to include, add, remove, or rename in the result set of a statement.
**The project operator will limit the size of the result set, which will increase performance**

Example:
```
SecurityEvent
| project Computer, Account


SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
| project Process, StartDir
```
- Project operators control what columns to include, add, remove or rename in the result set of a statement.


### Analyze query results using KQL
The count operator with its variations will create a new column with the calculated result for the specified fields.
Examples:
```
SecurityEvent | summarize by Activity

SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer
```

An aggregate function column can be explicitly named by including the "fieldname=" before the aggregate function.

The KQL statement will return three columns: "cnt", "AccountType", and "Computer". The "cnt" field name will replace the default "count_" name.
```
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize cnt=count() by AccountType, Computer
```

The following example will return a count of unique IP Addresses:
```
SecurityEvent
| summarize dcount(IpAddress)
```

Real world example to detect MFA failures for a user account:
```
let timeframe = 1d;

let threshold = 3;

SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "MFA"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
```

The following statement will return the most current row from the SecurityEvent table for the computer SQL12.NA.contosohotels.com. The * in the **arg_max function** requests all columns for the row:
```
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
```

Using the **arg_min function** - In this statement, the oldest SecurityEvent for the computer SQL12.NA.contosohotels.com will be returned as the result set:
```
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
```

This KQL query will first filter the EventID with the where operator. Next, for each Computer, the results are a JSON array of Accounts. The resulting JSON array will include duplicate accounts:
```
SecurityEvent
| where EventID == "4624"
| summarize make_list(Account) by Computer
```

This KQL query will first filter the EventID with the where operator. Next, for each Computer, the results are a JSON array of unique Accounts:
```
SecurityEvent
| where EventID == "4624"
| summarize make_set(Account) by Computer
```

Visualisation examples:
```
SecurityEvent 
| summarize count() by Account
| render barchart
```

```
SecurityEvent 
| summarize count() by bin(TimeGenerated, 1d) 
| render timechart
```


### Build multi-table statements using KQL
The union operator supports wildcards to union multiple tables. The following KQL will create a count for the rows in all tables with names that start with Security.

```
union Security* 
| summarize count() by Type
```

The graphic below shows which records will be kept if there is or isn't a matching record in the other dataset. The **inner join** will only show records from the left side if there's a matching record on the right side. The right side will also require a left side record.
![Pasted image 20230209185659](https://user-images.githubusercontent.com/66924945/219874606-791cbb14-df14-4dbb-ae46-3d55232495f4.png)

Inner contains a row in the output for every combination of matching rows from left and right.
The $left and $right preceding the field name specifies the table.
When you use union on two tables, the two tables do not need matching columns

### Work with data in Microsoft Sentinel using Kusto Query Language
The following example uses the extract function to pull out the Account Name from the Account field of the SecurityEvent table:
```
SecurityEvent 
| where EventID == 4672 and AccountType == 'User' 
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account)) 
| summarize LoginCount = count() by Account_Name 
| where Account_Name != "" 
| where LoginCount < 10
```

Parse evaluates a string expression and parses its value into one or more calculated columns. The computed columns will have nulls for unsuccessfully parsed strings.

Within a Log Analytics table, there are field types defined as Dynamic. **Dynamic fields contain a key-value pair**
To access the strings within a Dynamic field, use the dot notation. e.g:
```
SigninLogs 
| extend OS = DeviceDetail.operatingSystem
```

KQL provides functions to manipulate JSON stored in string fields. Many logs submit data in JSON format, which requires you to know how to transform JSON data to queryable fields.
Example:
```
SigninLogs
| extend Location =  todynamic(LocationDetails)
| extend City =  Location.city
| extend City2 = Location["city"]
| project Location, City, City2


SigninLogs
| mv-expand Location = todynamic(LocationDetails)

SigninLogs
| mv-apply Location = todynamic(LocationDetails) on 
( where Location.city == "Canberra")
```

Use the **externaldata** operator to create a virtual table from an external source.


## Configure your Microsoft Sentinel environment

### Introduction to Microsoft Sentinel
Microsoft Sentinel is a cloud-native SIEM system that a security operations team can use to:
-   Get security insights across the enterprise by collecting data from virtually any source.
-   Detect and investigate threats quickly by using built-in machine learning and Microsoft threat intelligence.
-   Automate threat responses by using playbooks and by integrating Azure Logic Apps.

**Data connectors** include:
-   syslog
-   Common Event Format (CEF)
-   Trusted Automated eXchange of Indicator Information (TAXII) (for threat intelligence)
-   Azure
-   AWS services

Data is stored by using **Log Analytics**

Use **workbooks** to visualize your data within Microsoft Sentinel. Think of workbooks as dashboards. Each component in the dashboard is built by using an underlying KQL query of your data.

An **incident** is created when an **alert** that you've enabled is triggered. Visually investigate incidents by mapping entities across log data along a timeline.

Microsoft Sentinel integrates with Azure Logic Apps, enabling you to create automated workflows, or _playbooks_, in response to events. This functionality could be used for incident management, enrichment, investigation, or remediation. These capabilities are often referred to as _security orchestration, automation, and response (SOAR)_.


### Create and manage Microsoft Sentinel workspaces
3 implementation options:
-   Single-Tenant with a single Microsoft Sentinel Workspace
-   Single-Tenant with regional Microsoft Sentinel Workspaces
-   Multi-Tenant

**Azure Lighthouse** allows greater flexibility to manage resources for multiple customers without having to sign in to different accounts in different tenants. For example, a service provider may have two customers with different responsibilities and access levels. By using Azure Lighthouse, authorized users can sign in to the service provider's tenant to access these resources.

Microsoft Sentinel-specific roles
-   **Microsoft Sentinel Reader**: can view data, incidents, workbooks, and other Microsoft Sentinel resources.
-   **Microsoft Sentinel Responder**: can, in addition to the above, manage incidents (assign, dismiss, etc.)
-   **Microsoft Sentinel Contributor**: can, in addition to the above, create and edit workbooks, analytics rules, and other Microsoft Sentinel resources.
-   **Microsoft Sentinel Automation Contributor**: allows Microsoft Sentinel to add playbooks to automation rules. It isn't meant for user accounts.

Data retention at the workspace level can be configured from **30 to 730 days** (two years) for all workspaces unless they're using the legacy Free pricing tier.

There are three primary log types in Microsoft Sentinel:
-   Analytics Logs - Default
-   Basic Logs - Cheaper, reduced features, **retained for 8 days**
-   Archive Logs 

### Query logs in Microsoft Sentinel
Defender for Endpoint data is stored in tables starting with Device, e.g DeviceLogonEvents

**SecurityAlert** tables tores Alerts from Microsoft Defender for Endpoint

### Use watchlists in Microsoft Sentinel
Microsoft Sentinel watchlists enable collecting data from external data sources for correlation with the events in your Microsoft Sentinel environment.

To access a new watchlist named MyList in KQL: _**GetWatchlist('MyList')**

### Utilize threat intelligence in Microsoft Sentinel
Cyber threat intelligence (CTI) can come from many sources. Sources include open-source data feeds, threat intelligence-sharing communities, paid intelligence feeds, and security investigations within organizations. CTI can range from written reports on a threat actor's motivations, infrastructure, and techniques, to specific observations of IP addresses, domains, and file hashes. CTI provides essential context for unusual activity, so security personnel can act quickly to protect people and assets.

You can integrate threat intelligence (TI) into Microsoft Sentinel through the following activities:
-   Use Data connectors to various TI platforms to import threat intelligence into Microsoft Sentinel.
-   View and manage the imported threat intelligence in Logs and the new Threat Intelligence area of Microsoft Sentinel.
-   Use the built-in Analytics rule templates to generate security alerts and incidents using your imported threat intelligence.
-   Visualize critical information about your threat intelligence in Microsoft Sentinel with the Threat Intelligence workbook.
-   Perform threat hunting with your imported threat intelligence.

To view your threat indicators with KQL. Select **Logs** from the General section of the Microsoft Sentinel menu. Then run a query on the ThreatIntelligenceIndicator table:
```
ThreatIntelligenceIndicator
```

## Connect logs to Microsoft Sentinel

### Connect data to Microsoft Sentinel using data connectors
Data Connectors page:
![Pasted image 20230209220952](https://user-images.githubusercontent.com/66924945/219874646-3f7dcb83-6d7c-4353-a26b-b13d2deea6b1.png)

If there's no vendor-provided connector, you can use the generic **Common Event Format(CEF)** or **Syslog Connector**.

CEF is always a superior choice because the log data is parsed into predefined fields in the CommonSecurityLog table. Syslog provides header fields, but the raw log message is stored in a field named SyslogMessage in the Syslog table.


### Connect Microsoft services to Microsoft Sentinel
**Connectors:**
- The **Office 365 activity log connector** provides insight into ongoing user activities. You'll get details of operations such as file downloads, access requests sent, changes to group events, set-mailbox, and details of the user who performed the actions

- **Audit and Sign in logs** to gather insights around Azure Active Directory scenarios - App usage, conditional access policies, legacy auth, Self-Service Password Reset (SSPR) usage, Azure Active Directory Management activities like user, group, role, and app management.

- **Azure Active Directory Identity Protection** provides a consolidated view of at-risk users, risk events, and vulnerabilities, with the ability to remediate risk immediately and set policies to auto-remediate future events.

- **The Azure Activity Log** is a subscription log that provides insight into subscription-level events that occur in Azure. The events included are from Azure Resource Manager operational data, service health events, write operations taken on the resources in your subscription, and the status of activities performed in Azure.

### Connect Microsoft 365 Defender to Microsoft Sentinel
The Microsoft 365 Defender integration with Microsoft Sentinel currently provides these data connectors:
-   Microsoft 365 Defender (Preview)
-   Microsoft Defender for Cloud Apps - LEGACY
-   Microsoft Defender for Endpoint - LEGACY
-   Microsoft Defender for Identity - LEGACY
-   Microsoft Defender for Office 365 (Preview) - LEGACY
Other relevant Microsoft Defender data connectors include:
-   Microsoft Defender for IoT
-   Microsoft 365 Insider Risk Management (Preview)

### Connect Windows hosts to Microsoft Sentinel
There are two agents available:
-   Windows Security Events via AMA Connector
-   Security Events via Legacy Agent Connector

The second option is to configure a Windows Event Collector device to receive events from the Windows devices. The Windows Event Collector device would then forward events to Microsoft Sentinel with the **Windows Forwarded Events connector**.

**Azure Arc** is an agent installed on the device or VM that allows the device to be managed the same as an Azure VM. Azure Arc provides other functionality including running Azure based services in a hybrid environment.

### Connect Common Event Format logs to Microsoft Sentinel
The CEF Connector deploys a Syslog Forwarder server to support the communication between the appliance and Microsoft Sentinel. The server consists of a dedicated Linux machine with the Log Analytics agent for Linux installed. Many of the Microsoft Sentinel Data Connectors that are vendor-specific utilize CEF Connector.

If you plan to use this log forwarder machine to forward Syslog messages as CEF, then to avoid the duplication of events to the Syslog and CommonSecurityLog tables:
**On each source machine that sends logs to the forwarder in CEF format, you must edit the Syslog configuration file to remove the facilities used to send CEF messages.**


### Connect syslog data sources to Microsoft Sentinel
You can stream events from Linux-based, Syslog-supporting machines or appliances into Microsoft Sentinel using the agent for Linux. You can do this streaming for any device that allows you to install the agent directly on the host. The host's native Syslog daemon will collect local events of the specified types and forward them locally to the agent, which will stream them to your Log Analytics workspace.

Log Analytics supports collecting messages sent by the **rsyslog** or **syslog-ng** daemons, where rsyslog is the default. The default syslog daemon on version 5 of Red Hat Enterprise Linux (RHEL), CentOS, and Oracle Linux version (sysklog) isn't supported for Syslog event collection. The rsyslog daemon should be installed and configured to replace sysklog for these versions of Linux.


### Connect threat indicators to Microsoft Sentinel
There are two Threat Intelligence Connectors. The TAXII Connector and the Threat Intelligence Platforms Connector. Both connectors write to the ThreatIntelligenceIndicator table.

Microsoft Sentinel integrates with TAXII 2.0 and 2.1 data sources to enable monitoring, alerting, and hunting using your threat intelligence. Use this connector to send threat indicators from TAXII servers to Microsoft Sentinel. Threat indicators can include IP addresses, domains, URLs, and file hashes.

Microsoft Sentinel integrates with Microsoft Graph Security API data sources to enable monitoring, alerting, and hunting using your threat intelligence. Use this connector to send threat indicators to Microsoft Sentinel from your Threat Intelligence Platform (TIP), such as Threat Connect, Palo Alto Networks MindMeld, MISP, or other integrated applications. Threat indicators can include IP addresses, domains, URLs, and file hashes.

## Create detections and perform investigations using Microsoft Sentinel

### Threat detection with Microsoft Sentinel analytics
**Microsoft Sentinel Analytics** helps you detect, investigate, and remediate cybersecurity threats.
- You can analyze historical data collected from your workstations, servers, networking devices, firewalls, intrusion prevention, sensors, and so on. Microsoft Sentinel Analytics analyzes data from various sources to identify correlations and anomalies.
- By using analytics rules, you can trigger alerts based on the attack techniques that are used by known malicious actors.

Common security analytics use cases include:
-   Identification of compromised accounts
-   User behavior analysis to detect potentially suspicious patterns
-   Network traffic analysis to locate trends indicating potential attacks
-   Detection of data exfiltration by attackers
-   Detection of insider threats
-   Investigation of incidents
-   Threat hunting

Types of analytics rules:
-   **Anomaly** - Informational
-   **Fusion** - Correlates alerts from multiple sources and uses ML to detect advanced attacks
-   Microsoft security - Alerts from connected services
-   Machine learning (ML) behavior analytics - Built-in, not editable
-   Scheduled alerts - Can filter using custom KQL expression

### Automation in Microsoft Sentinel
**Automation rules** allow users to centrally manage the automation of incident handling. Automation rules also allow you to automate responses for multiple analytics rules at once. Automatically tag, assign, or close incidents without the need for playbooks, and control the order of actions that are executed.

A **playbook** is a collection of response and remediation actions and logic that can be run from Microsoft Sentinel as a routine. A playbook can help automate and orchestrate your threat response. It can integrate with other systems both internal and external, and it can be set to run automatically in response to specific alerts or incidents, when triggered by an analytics rule or an automation rule, respectively. It can also be run manually on-demand, in response to alerts, from the incidents page.
- Based on workflows built in Azure Logic Apps,

Automation rules can change an incident status.

### Threat response with Microsoft Sentinel playbooks
You can create **security playbooks** in Microsoft Sentinel to respond to alerts. _Security playbooks_ are collections of procedures based on Azure Logic Apps that run in response to an alert. You can run these security playbooks manually in response to your investigation of an incident or you can configure an alert to run a playbook automatically.

A Microsoft Sentinel playbook uses a **Microsoft Sentinel Logic Apps connector**. It provides the triggers and actions that can start the playbook and perform defined actions.

Currently, there are two triggers from Microsoft Sentinel Logic Apps connector:
-   When a response to a Microsoft Sentinel alert is triggered
-   When Microsoft Sentinel incident creation rule is triggered

[Microsoft Sentinel repository on GitHub](https://github.com/Azure/Azure-Sentinel) contains ready-to-use playbooks to help you automate responses on incidents. These playbooks are defined with Azure Resource Manager (ARM template) that uses Logic App Microsoft Sentinel triggers.

### Security incident management in Microsoft Sentinel
**Incident management** is the complete process of incident investigation, from creation to in-depth investigation and finally to resolution. Microsoft Sentinel provides a complete incident-management environment in which you can perform these steps. You can use Sentinel to review detailed incident information, assign an incident owner, set and maintain incident severity, and manage incident status.


### Identify threats with Behavioral Analytics
The **Entity Behavior** capability delivers high-fidelity and actionable intelligence, so they can focus on investigation and remediation.

As Microsoft Sentinel collects logs and alerts from all the connected data sources, it analyzes and builds baseline behavioral profiles of your organization’s entities (users, hosts, IP addresses, applications etc.). The analysis is across the time and peer group horizon. Microsoft Sentinel uses various techniques and machine learning capabilities, and can then identify anomalous activity and help you determine if an asset has been compromised. Not only that, but it can also figure out the relative sensitivity of particular assets, identify peer groups of assets, and evaluate the potential impact of any given compromised asset (its “blast radius”). Armed with this information, you can effectively prioritize your investigation and incident handling.

Architecture:
![Pasted image 20230210132300](https://user-images.githubusercontent.com/66924945/219874676-2d64f1b2-bca5-44ad-a1cd-9a9cd3fd0e33.png)


### Data normalization in Microsoft Sentinel
The **Advanced Security Information Model (ASIM)** is a layer that is located between data sources and the user.

ASIM provides a seamless experience for handling various sources in uniform, normalized views, by providing the following functionality:
-   **Cross source detection**. Normalized analytics rules work across sources, on-premises and cloud, and detect attacks such as brute force or impossible travel across systems, including Okta, AWS, and Azure.
-   **Source agnostic content**. The coverage of both built-in and custom content using ASIM automatically expands to any source that supports ASIM, even if the source was added after the content was created. For example, process event analytics support any source that a customer may use to bring in the data, such as Microsoft Defender for Endpoint, Windows Events, and Sysmon.
-   **Support for your custom sources**, in built-in analytics
-   **Ease of use**. After an analyst learns ASIM, writing queries is much simpler as the field names are always the same.

ASIM aligns with the Open Source Security Events Metadata (OSSEM) common information model, allowing for predictable entities correlation across normalized tables.

OSSEM is a community-led project that focuses primarily on the documentation and standardization of security event logs from diverse data sources and operating systems. The project also provides a Common Information Model (CIM) that can be used for data engineers during data normalization procedures to allow security analysts to query and analyze data across diverse data sources.

### Query, visualize, and monitor data in Microsoft Sentinel
**Microsoft Sentinel Workbooks** provide interactive reports that help you visualize important signals by combining text, table, charts, and tiles.

Sentinel logs are stored in a **Log Analytics Workspace**

**A new Microsoft Sentinel alert creates an analytics rule**

**Kusto Query Language (KQL)** is used in Sentinel to search and filter data
 - | character separates commands i.e Event | search error
**Microsoft Sentinel repository** available on Github

**Azure Data Explorer, which is also known as Kusto, is a log analytics cloud platform optimized for ad-hoc big data queries.**

Sentinel uses **Markdown** for text visualizations

### Manage content in Microsoft Sentinel
Content in Microsoft Sentinel includes any of the following types:
-   **Data connectors** provide log ingestion from different sources into Microsoft Sentinel
-   **Parsers** provide log formatting/transformation into ASIM formats, supporting usage across various Microsoft Sentinel content types and scenarios
-   **Workbooks** provide monitoring, visualization, and interactivity with data in Microsoft Sentinel, highlighting meaningful insights for users
-   **Analytics** rules provide alerts that point to relevant SOC actions via incidents
-   **Hunting queries** are used by SOC teams to proactively hunt for threats in Microsoft Sentinel
-   **Notebooks** help SOC teams use advanced hunting features in Jupyter and Azure Notebooks
-   **Watchlists** support the ingestion of specific data for enhanced threat detection and reduced alert fatigue
-   **Playbooks** and Azure Logic Apps custom connectors provide features for automated investigations, remediations, and response scenarios in Microsoft Sentinel

To maintain **content** in for Microsoft Sentinel use:
-   **Content hub**: - Microsoft Sentinel **solutions** are packages of Microsoft Sentinel content or Microsoft Sentinel API integrations, which fulfill an end-to-end product, domain, or industry vertical scenario in Microsoft Sentinel.
-   **Repositories**: - Repositories help you automate the deployment and management of your Microsoft Sentinel content through central repositories.
-   **Community**: Onboard community content on-demand to enable your scenarios. The GitHub repo at [https://github.com/Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) contains content by Microsoft and the community that is tested and available for you to implement in your Sentinel workspace.

5 repository connections maximum for each workspace.

## Perform threat hunting in Microsoft Sentinel

### Explain threat hunting concepts in Microsoft Sentinel
The term "threat hunting" is defined differently by different people. The most commonly used definition is the idea that you're proactively hunting through your environment for a threat or a set of activities that you haven't previously detected. The "not previously detected" part is what differentiates threat hunting from incident response or alert triage.

Hunting starts with a **Hypothesis**. The idea of what we are going to hunt. Getting this right is critical because it drives our focuses on what we are going to do.

When developing a threat hunting hypothesis, it's critical to understand tactics and techniques you're searching for. **The MITRE ATT&CK framework** is used throughout Microsoft Sentinel.


### Threat hunting with Microsoft Sentinel
The **Hunting** page in Microsoft Sentinel has built-in queries. These queries can guide your hunting process and help you pursue the appropriate hunting paths to uncover issues in your environment. Hunting queries can expose issues that aren't significant enough on their own to generate an alert but have happened often enough over time to warrant investigation.

You can select individual MITRE ATT&CK tactics from the timeline on the **Hunting** page.
![Pasted image 20230210205906](https://user-images.githubusercontent.com/66924945/219874692-57f6e32e-0a8a-45e5-9cce-7118974cfe3d.png)

All Microsoft Sentinel hunting queries use Kusto Query Language (KQL) syntax used in Log Analytics.

**Bookmarks** in Microsoft Sentinel can help you hunt for threats by preserving the queries you ran in Microsoft Sentinel, along with the query results that you deem relevant. You can also record your contextual observations and reference your findings by adding notes and tags. Bookmarked data is visible to you and your teammates for easy collaboration.

You can use the hunting livestream to test queries against live events as they occur. **Livestream** provides interactive sessions that can notify you when Microsoft Sentinel finds matching events for your query.


### Use Search jobs in Microsoft Sentinel
In Microsoft Sentinel, you can search across long time periods in large datasets by using a search job. While you can run a search job on any type of log, search jobs are ideally suited to search archived logs.

Search in Microsoft Sentinel is built on top of search jobs. Search jobs are asynchronous queries that fetch records. The results are returned to a search table that's created in your Log Analytics workspace after you start the search job. The search job uses parallel processing to run the search across long time spans, in large datasets. So search jobs don't impact the workspace's performance or availability.

When you need to do a full investigation on data stored in archived logs, restore a table from the Search page in Microsoft Sentinel. Specify a target table and time range for the data you want to restore. Within a few minutes, the log data is restored and available within the Log Analytics workspace. Then you can use the data in high-performance queries that support full KQL.

A restored log table is available in a new table that has a ***_RST** suffix.

Search results remain in a search results table that has a ***_SRCH** suffix.

Before you start to restore an archived log table, be aware of the following limitations:

-   Restore data for a minimum of two days.
-   Restore data more than 14 days old.
-   Restore up to 60 TB.
-   Restore is limited to one active restore per table.
-   Restore up to four archived tables per workspace per week.
-   Limited to two concurrent restore jobs per workspace.

### Hunt for threats using notebooks in Microsoft Sentinel
Before hunting with notebooks, it's essential to understand the foundation of Microsoft Sentinel is the Log Analytics data store, which combines high-performance querying, dynamic schema, and scales to massive data volumes. The Azure portal and all Microsoft Sentinel tools use a standard API to access this data store. The same API is also available for external tools such as Python and PowerShell. There are two libraries that you can use to simplify API access:
-   Kqlmagic - easy to implement API wrapper to run KQL queries.
-   msticpy - Microsoft Threat Intelligence Python Security Tools is a set of Python tools intended to be used for security investigations and hunting. Many of the tools originated as code Jupyter notebooks written to solve a problem as part of a security investigation.

A **Jupyter Notebook** allows you to create and share documents that contain live code, equations, visualizations, and explanatory text. Uses include data cleaning and transformation, numerical simulation, statistical modeling, machine learning, and much more. Jupyter extends the scope of what you can do with Microsoft Sentinel data. It combines full programmability with a vast library collection for machine learning, visualization, and data analysis. These attributes make Jupyter a useful tool for security investigation and hunting.

Notebooks have two components:
-   The browser-based interface where you enter and run queries and code and where the execution results are displayed.
-   The kernel is responsible for parsing and executing the code itself.

The **msticpy** package is used in many of the included notebooks. Msticpy tools are explicitly designed to help with creating notebooks for hunting and investigation.
<!-- Author: Stuart Mackay -->
