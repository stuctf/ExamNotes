# SC-100 Microsoft Cybersecurity Architect - Study Notes
## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWVbXN)
- [Official Microsoft Learning Path](https://docs.microsoft.com/en-us/certifications/exams/sc-100)
- [Mark Simos MCRA Playlist (Youtube)](https://www.youtube.com/watch?v=6iYxNm3TOiI&list=PLtVMyW0H7aiOQwZSsn2d-tg2z729ce1BZ)
- [John Savill SC-100 Study Playlist (Youtube)](https://www.youtube.com/watch?v=2Qu5gQjNQh4&list=PLlVtbbG169nHcbeVtWUfP8BeEjGniBJeb)
- [Microsoft Security Best Practises (MS Docs)](https://docs.microsoft.com/en-us/security/compass/compass)
- [Microsoft Cybersecurity Reference Architectures (MCRA)](https://docs.microsoft.com/en-us/security/cybersecurity-reference-architecture/mcra) 
- [Cloud Adoption Framework](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/)
  -  Specifically - [Security in the Microsoft Cloud Adoption Framework for Azure](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/secure/)
- [Cloud Economics](https://azure.microsoft.com/overview/cloud-economics)
- [Security Baselines](https://docs.microsoft.com/en-us/security/benchmark/azure/security-baselines-overview)
  

  
## Notes from Microsoft Learn & Microsoft Docs:
## Design a Zero Trust strategy and architecture
### Build an overall security strategy and architecture

3 foundational principles of Zero Trust:
-   **Verify explicitly** - Always authenticate and authorise based on all available data points.
-   **Use least privilege access** - Limit user access with Just-In-Time and Just-Enough-Access (JIT/JEA), risk-based adaptive policies, and data protection.
-   **Assume breach** - Minimize blast radius and segment access. Verify end-to-end encryption and use analytics to get visibility, drive threat detection, and improve defenses.

**Identity** - Authentication & Authorization (least privilege)  
**Endpoints** - Monitor and enforce device health for compliance  
**Applications** - Discover "shadow IT" apps, ensure permissions, monitor behaviour  
**Data** - Classify, label, encrypt, restrict access  
**Infrastructure** - Assess version, config, access. Detect/Block anomalies  
**Networks** - Segmentation, threat protection, encryption, monitoring  
	Data generated requires **Visibility, automation and orchestration**. 

[Microsoft Cybersecurity Reference Architectures (MCRA)](https://docs.microsoft.com/en-us/security/cybersecurity-reference-architecture/mcra)  
	Describes Microsoft's cybersecurity capabilities/integrations. 
	Includes an overview of Zero Trust rapid modernization plan (**RaMP**)   
	Information on Operations, initiatives, securing privileged access, beyond VPN...  
Uses of the MCRA - Starting template, reference, integration info, general learning   

**Domains and Microsoft Technologies**  

- **Identity and Access**
	- **Azure Active Directory** - Cloud based Identity, MFA, PIM, B2B/B2C
	- **Identity Protection** - Leaked credential Protection, behavioural analytics
	- **Identity Governance** - Access lifecycle/request, policy/role, governance, reports
	- **Defender for Identity** - User behaviour, lateral movement detection, AD/AzureAD

- **Security Operations**
	- **Microsoft Defender** - eXtended Detection and Response
	- **Microsoft Sentinel** - SIEM/SOAR, User Entity Behaviour Analytics, logs+data

- **Endpoint and Device Security**
	- **Microsoft Endpoint Manager** - Unified, Intune and Configuration Manager
	- **Microsoft Defender for Endpoint** - EDR, Web filtering, DLP, Threat/Vuln mgmt

- **Hybrid Infrastructure**
	- **Defender for Cloud** - Security Posture Management, Cross platform/Cloud
	- **Azure AD App Proxy** - Secure Remote Access, Web apps SSO
	- **Azure Arc** - Hybrid/Multi-Cloud Management
	- **Azure Stack** - Hybrid/Edge Computing, IoT, Machine Learning, Datacenter
	- **Azure Firewall** - L7 Network Firewall, TLS Inspection, IDPS, URL Filtering
	- **Azure WAF** - Application Firewall, Web Apps
	- **DDoS Protection** - Mitigates Distributed Denial of Service attacks
	- **Azure Key Vault** - Encryption, Authentication and Secrets management (certs)
	- **Azure Bastion** - PaaS Admin workstation (jumphost), VM via RDP/SSH
	- **Azure Lighthouse** - Cross-Tenant Management
	- **Azure Backup** - Supports on-premise and cloud, VMs, DBs, Disks, Blobs etc
	- **Express Route** - On-prem Network Extension, L3, connect to MS, redundancy
	- **Private Link** - Private Azure Access, on-prem/peered networks, DLP

- **Information Protection**
	- **Azure Purview** - Unified Data Governance, eDiscovery, classification, MIP
	- **Compliance Manager** - Pre-Built assessments, Risk-Based Compliance Score

- **People Security**
	- **Attack Simulator** - Training platform, credential harvest, attachments, drive-by
	- **Insider Risk Management** - Compliance, Data Leak, Policy, Alerts, Investigation
	- **Communication Compliance** - Insider Risk Solution, Remediation workflows

- **IoT and Operational Technology**
	- **Azure Sphere** - IoT and OT Security Services via Micro-controller Unit
	- **Defender for IoT** - Asset Discovery, Network Detection and Response (NDR)

[Microsoft Security Best Practises (MS Docs)](https://docs.microsoft.com/en-us/security/compass/compass)   

[Cloud Adoption Framework](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/)  
![Pasted image 20220711134834](https://user-images.githubusercontent.com/66924945/179813588-3a89f351-4d51-42b9-8d02-32e8e1d639b0.png)  
[Microsoft Cybersecurity Reference Architectures - Security documentation](https://docs.microsoft.com/en-us/security/cybersecurity-reference-architecture/mcra)
  
Understand [cloud economics](https://azure.microsoft.com/overview/cloud-economics)  

To assess workloads using the tenets found in the Azure Well-Architected Framework, reference the [Microsoft Azure Well-Architected Review](https://docs.microsoft.com/en-us/assessments/?id=azure-architecture-review&mode=pre-assessment).  

Two main priorities during an incident: **Protect critical Operations**, **Prevent further damage**.  

Reference secure hybrid network architecture  
![Pasted image 20220711140200](https://user-images.githubusercontent.com/66924945/179814998-cdd25daf-c472-411f-ae3b-7db6256a59df.png)

**What's the difference between Service Endpoints and Private Endpoints?**
-  Private Endpoints grant network access to specific resources behind a given service providing granular segmentation. Traffic can reach the service resource from on premises without using public endpoints.
-  A Service Endpoint remains a publicly routable IP address. A Private Endpoint is a private IP in the address space of the virtual network where the private endpoint is configured.
  
### Design a security operations strategy
**Security Operations Best Practices:**
-   Follow the NIST Cybersecurity Framework functions as part of operations:
    -   **Detect** the presence of adversaries in the system.
    -   **Respond** by quickly investigating whether it's an actual attack or a false alarm.
    -   **Recover** and restore the confidentiality, integrity, and availability of the workload during and after an attack.
-   Acknowledge an alert quickly. A detected adversary must not be ignored while defenders are triaging false positives.
-   Reduce the time to remediate a detected adversary. Reduce their opportunity to conduct attacks and reach sensitive systems.
-   Prioritize security investments into systems that have high intrinsic value.
-   Proactively hunt for adversaries as your system matures. This effort will reduce the time that a highly skilled adversary can operate in the environment.

**Metrics that have a direct influence on risk**
	**MTTA** - Mean Time To Acknowledge
	**MTTR** - Mean Time To Remediate
	**Incidents remediated**
	**Escalations between tiers** 

**MITRE ATT&CK Framework Stages**
![Pasted image 20220712131500](https://user-images.githubusercontent.com/66924945/179815061-85b07d78-15c6-4489-afc4-be5cce680691.png)


**MCRA Defence Products Integration**   
![Pasted image 20220712131904](https://user-images.githubusercontent.com/66924945/179815111-42b37a37-ea00-48f3-b1b6-ea84caa71573.png)


**Log Types in Azure**
Most services have available logging. NSG flow logs in JSON format via **Azure Network Watcher**  
Integration with REST API, **Azure Monitor**, **Graph API**, **Power BI**, **Windows Azure Diagnostics (WAD)**  

**Azure Management Services**
- [Azure security operations](https://docs.microsoft.com/en-us/azure/security/fundamentals/operational-security) refer to the services, controls, and features available to users to protect their data, applications, and other assets in Microsoft Azure. It is a framework that incorporates the knowledge gained through various capabilities that are unique to Microsoft. These capabilities include the Microsoft Security Development Lifecycle (SDL), the Microsoft Security Response Center program, and deep awareness of the cybersecurity threat landscape.
- [Microsoft Azure Monitor logs](https://docs.microsoft.com/en-us/azure/azure-monitor/overview) is a cloud-based IT management solution that helps you manage and protect your on-premises and cloud infrastructure.
- [Azure Monitor](https://docs.microsoft.com/en-us/azure/azure-monitor/overview) - collects data from managed sources into central data stores. This data can include events, performance data, or custom data provided through the API. After the data is collected, it is available for alerting, analysis, and export.
- [Azure Automation](https://docs.microsoft.com/en-us/azure/automation/automation-intro) provides a way to automate the manual, long-running, error-prone, and frequently repeated tasks commonly performed in a cloud and enterprise environment. It saves time and increases the reliability of administrative tasks.
- [Azure Backup](https://docs.microsoft.com/en-us/azure/backup/backup-overview) is the Azure-based service that you can use to back up (or protect) and restore your data in the Microsoft Cloud. Azure Backup replaces existing on-premises or off-site backup solutions with a cloud-based solution**** that's reliable, secure, and cost-competitive.
- [Azure Site Recovery](https://azure.microsoft.com/documentation/services/site-recovery) provides business continuity by orchestrating the replication of on-premises virtual and physical machines to Azure or a secondary site. If primary sites are unavailable, failover to the secondary location so that users can keep working.

**Example security architecture for hybrid and multicloud:**  

![Pasted image 20220712133420](https://user-images.githubusercontent.com/66924945/179815345-e11923aa-75f9-4e7f-b493-0c929a301cfd.png)

**Microsoft Threat Protection (MTP)**, a key feed into Microsoft Sentinel, provides a unified enterprise defence suite that brings context-aware protection, detection, and response across all Microsoft 365 components.   

**Zero Trust Deployment Objectives:**
1. Establish Visibility - via MTP
2. Enable Automation - via AIR [Automated Investigation and Remediation](https://docs.microsoft.com/en-us/microsoft-365/security/mtp/mtp-autoir) 
3. Enable additional protection/detection controls -  [Attack surface reduction](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/overview-attack-surface-reduction) 

[Azure Network Watcher](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview) is a regional service. Use its diagnostic and visualization tools to monitor and diagnose conditions at a network scenario level in, to, and from Azure.  
	Supports [packet capture](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-alert-triggered-packet-capture)  
	Also [using network security group flow logs](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview).  
  
**Monitor for suspicious actions related to your user accounts** - Monitor for [users at risk](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection) and [risky sign-ins](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection) by using **Azure AD security reports**.   
  
**Automation** via **Azure Logic Apps**, **Defender for Cloud**, **Graph Security**, **Sentinel**  
[Improve threat protection by integrating security operations with Microsoft Graph Security & Azure Logic Apps](https://docs.microsoft.com/en-us/azure/connectors/connectors-integrate-security-operations-create-api-microsoft-graph-security).  
  
**Incident Management Process**  
![Pasted image 20220712135827](https://user-images.githubusercontent.com/66924945/179815412-1706a7ac-c3a7-4e3c-921b-0254fbea89cb.png)

  
**Microsoft Threat Intelligence**
![Pasted image 20220712140033](https://user-images.githubusercontent.com/66924945/179815478-ee6e5715-dc19-4260-b77f-e2331603546c.png)

  
### Design an identity security strategy  
Zero Trust framework for identity initial deployment objectives:  

-   [I. Cloud identity federates with on-premises identity systems](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#i-cloud-identity-federates-with-on-premises-identity-systems)
-   [II. Conditional Access policies gate access and provide remediation activities](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#ii-conditional-access-policies-gate-access-and-provide-remediation-activities)
-   [III. Analytics improve visibility](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#iii-analytics-improve-visibility)

After these are completed, focus on these additional deployment objectives:  

-   [IV. Identities and access privileges are managed with identity governance](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#iv-identities-and-access-privileges-are-managed-with-identity-governance)
-   [V. User, device, location, and behavior are analyzed in real time to determine risk and deliver ongoing protection](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#v-user-device-location-and-behavior-is-analyzed-in-real-time-to-determine-risk-and-deliver-ongoing-protection).
-   [VI. Integrate threat signals from other security solutions to improve detection, protection, and response](https://docs.microsoft.com/en-us/security/zero-trust/deploy/identity#vi-integrate-threat-signals-from-other-security-solutions-to-improve-detection-protection-and-response).

Publishing app to the **App Gallery** enables SSO and publisher verification  
**SCIM** (System for Cross-Domain Identity Management) API to provision users between app and Azure AD  
**Azure B2C** is a **CIAM** (Customer Identity and Access Management) solution  
	Integrate by using **Microsoft Graph**  

**Identity is the new control plane of IT security, so authentication is an organization's access to the new cloud world.**  

**Authentication Methods**  
Cloud:  
	**Azure AD password hash synchronization** - Simplest, required for Identity Protection and **Azure AD Domain Services**  
	**Azure AD Pass-through Authentication** - Software agent on-prem, validates on-prem, immediate enforcement of user account states  
Federated Authentication - Auth is handled by other system, AD FS for example  
  
**Authorization Methods** - Security Group Membership, Role-based access control, Access levels, Feature flags, Security namespaces & permissions  
  
**Conditional Access** is the main policy engine for Zero Trust  
![Pasted image 20220712165514](https://user-images.githubusercontent.com/66924945/179815660-edf736ec-880f-44d5-b48e-6744ebca5134.png)

Users can be assigned to **Privileged access groups** which can contain multiple roles  
  
**Access reviews** can be done by these administrators: Global, User, Identity Governance, Privileged Role. (Preview) Security group owner (365/AzureAD)  
  
**Stages of securing privileged access**
**Stage 1 (24-48 hours):** Critical items to do right now
-   Use Azure AD Privileged Identity Management
-   Identify and categorize accounts that are in highly privileged roles
-   Define at least two emergency access accounts

**Stage 2 (2-4 weeks):** Mitigate frequently used attack techniques
-   Conduct an inventory of services, owners, and administrators
-   Identify Microsoft accounts in administrative roles that need to be switched to work or school accounts
-   Ensure separate user accounts and mail forwarding for Global Administrator accounts
-   Ensure the passwords of administrative accounts have recently changed
-   Turn on password hash synchronization
-   Require multifactor authentication for users in privileged roles and exposed users
-   Configure Identity Protection
-   Establish incident/emergency response plan owners
-   Secure on-premises privileged administrative accounts

**Stage 3 (1-3 months):** Take control of administrator activity
-   Complete an access review of users in administrator roles
-   Continue rollout of stronger authentication for all users
-   Use dedicated workstations for administration for Azure AD
-   Review National Institute of Standards and Technology recommendations for handling incidents
-   Implement Privileged Identity Management (PIM) for JIT in additional administrative roles
-   Determine exposure to password-based sign-in protocols (if using Exchange Online)
-   Inventory your privileged accounts within hosted Virtual Machines
-   Implement PIM for Azure AD administrator roles

**Stage 4 (six months and beyond):** Continue building defenses
-   Review administrator roles in Azure AD
-   Review users who have the administration of Azure AD joined devices
-   Validate incident response plan

## Evaluate Governance Risk Compliance (GRC) technical strategies and security operations strategies  
  
### Evaluate a regulatory compliance strategy  
**Operational risk** is the failure to establish a system of internal controls and an independent assurance function and exposes the organization to the risk of signification fraud, defalcation, and other operational losses  
**Compliance risk** is the risk of legal or regulatory sanctions, financial loss, or damage to reputation resulting from failure to comply with laws, regulations, rules, other regulatory requirements, or codes of conduct.  
  
Patch Management - **Azure Automation Update Management**  
Policy Enforcement - **Azure Policy**  
Environment Configuration - **Azure Blueprints**  
Resource Configuration - **Desired State Configuration**   
  
**Microsoft Defender for Cloud** - Has Regulatory Compliance Dashboard  
-   Provides a unified view of security across your workloads.
-   Collects, searches, and analyzes security data from a variety of sources, which includes firewalls and other partner solutions.
-   Provides actionable security recommendations to fix issues before they can be exploited.
-   Can be used to apply security policies across your hybrid cloud workloads to ensure compliance with security standards.

While **data sovereignty** implies data residency, it also introduces rules and requirements that define who has control over and access to the data stored in the cloud.  
  
**Microsoft Purview** - Unified Data Governance, solution for data classification  
![Pasted image 20220713135203](https://user-images.githubusercontent.com/66924945/179815738-8e90ff3e-8457-414a-ac90-e7569c8ab494.png)

**Azure AD Identity Protection** - Ensures privacy regulations are met  
  
### Evaluate security posture and recommend technical strategies to manage risk  
  
**Security posture management** is an emerging function. It represents a step forward in the long-term convergence of security functions. These functions answer the question "how secure is the environment?", including vulnerability management and security compliance reporting.  
![Pasted image 20220713171056](https://user-images.githubusercontent.com/66924945/179815806-009c87d0-82bd-41d0-abf1-f614ec287754.png)

**Rapid Modernization Plan (RaMP)**  
![Pasted image 20220713171331](https://user-images.githubusercontent.com/66924945/179815847-a5438296-960c-49a6-8ca0-d1196c74f044.png)
  
**Three pillars of security posture management:** Protect, Detect, Respond  
  
**Azure Security Benchmark** - Located in Microsoft Defender for Cloud regulatory compliance dashboard  
![Pasted image 20220713172152](https://user-images.githubusercontent.com/66924945/179815899-adc77017-8309-41be-a94a-90d4a04aa51f.png)

Microsoft Defender for Cloud maps its recommendations against the **MITRE ATT&CK Framework** - Can create filters based on this for campaigns  
  
**Secure Score** - Microsoft Defender for Cloud > Cloud Security > Secure Score.  
	Some recommendations will be based on policies that can use the _Deny_ effect, which in this case can stop unhealthy resources from being created. Some other recommendations are based on the _DeployIfNotExist_ effect, which can automatically remediate non-compliant resources upon creation.  
  
In Defender for Cloud you can use the [Workflow Automation](https://docs.microsoft.com/en-us/azure/defender-for-cloud/workflow-automation) capability to activate actions such as sending an email to the resource owner, when a recommendation is triggered.  
  
**Azure landing zones** are the output of a multi-subscription Azure environment that accounts for scale, security governance, networking, and identity.  
![Pasted image 20220713180156](https://user-images.githubusercontent.com/66924945/179815942-d9e7bd0e-5c46-4747-a7f2-8dd70f7e0810.png)
**A landing zone is an environment for hosting your workloads, pre-provisioned through code.**  
  
Threat Intelligence products: **Microsoft Sentinel**, **Microsoft Defender for Cloud**, **Azure AD Identity Protection**  
  
**Microsoft Sentinel** Related acronyms  
	**CTI** - Cyber Threat Intelligence  
	**IoC** - Indicators of Compromise  
	**SIEM** - Security Information and Event Management  
	**SOAR** - Security Orchestration And Response  
	**STIX** - Structured Threat Information Expression  
	**TAXII** - Trusted Automated Exchange of Intelligence Information  
	**TIP** - Threat Intelligence Platform  
  
**Risk management 4 phases** - Identification, Assessment, Response, Monitoring and Reporting  
	Detection includes reactive measures, Protect is proactive  
  
## Design security for infrastructure  
  
### Understand architecture best practices and how they are changing with the Cloud  
As an architect you need to ensure all teams are aligned to a single strategy that both enables and secures enterprise systems and data.  
  
**Security Strategy Principles**  
	Ruin Attacker ROI  
	Productivity and Security  
	Assume Compromise  
	Shared Responsibility  
	Cloud is more secure  
	
  
A security plan should be part of the main planning documentation for the cloud. Microsoft has a [strategy and plan template](https://raw.githubusercontent.com/microsoft/CloudAdoptionFramework/master/plan/cloud-adoption-framework-strategy-and-plan-template.docx),  
  
Adopt agile security: Establish minimum security requirements first and move all noncritical items to a prioritized list of next steps. This should not be a traditional, detailed plan of 3-5 years. The cloud and threat environment changes too fast to make that type of plan useful. Your plan should focus on developing the beginning steps and end state:  
- Quick wins for the immediate future that will deliver a high impact before longer-term initiatives begin. The time frame can be 3-12 months, depending on organizational culture, standard practices, and other factors.      
- Clear vision of the desired end state to guide each team's planning process (which might take multiple years to achieve).  
  
**11 essential security practices for cloud adoption:**  
**People:**  
- Educate teams about the cloud security journey
- Educate teams on cloud security technology
  
**Process:**  
- Assign accountability for cloud security decisions
- Update incident response processes for cloud
- Establish security posture management
  
**Technology:**  
- Require passwordless or multifactor authentication
- Integrate native firewall and network security
- Integrate native threat detection
  
**Foundational architecture decisions:**  
- Standardize on a single directory and identity
- Use identity-based access control (instead of keys)
- Establish a single unified security strategy
  
Microsoft Defender for Cloud - **Secure Score** to identify current risk level  
  
In a SaaS environment with Microsoft 365, you can use **Compliance Manager** for continuous assessment.  
  
Microsoft recommended security strategy metrics:
-   Business enablement -- How much security friction is in user experience and business processes?
-   Security Improvement -- Are we getting better every month?
-   Security Posture - How good are we at preventing damage?
-   Security Response -- How good are we at responding to and recovering from attacks?
  
  
### Design a strategy for securing server and client endpoints  
**Security Compliance Toolkit (SCT)** - Microsoft security baselines  
	Policy Analyzer  
	Local Group Policy Object (LGPO) tools  
**Azure Security Benchmark (ASB)** - OS Hardening guidance for Windows & Linux  
Intune security baselines are not CIS or NIST compliant.  
**Local Administrator Password Solution (LAPS)** - Randomised, stored in AD  
	Requires PowerShell Update-AdmPwdADSchema to update AD Schema  
  
SMB end-to-end encryption from SMB3.0  
SMB3.1.1 (Server 2016) includes pre-authentication checks  
  
**Intune app protection policies** help protect your work files on devices that are enrolled into Intune.  
Using **Windows Autopilot**, you can enroll hybrid Azure AD joined devices in Intune.  
  
**Microsoft Defender for Identity (MDI)** monitors your domain controllers by capturing and parsing network traffic and using Windows events directly from your domain controllers, then analyzes the data for attacks and threats.  
  
**Azure Key Vault** is a centralized cloud service for storing application secrets such as encryption keys, certificates, and server-side tokens.  
  
**Azure Point-to-site(P2S) VPN** gateway - Connect to virtual network from client  
Site-to-site VPN - Connection over IPSec/IKE VPN tunnel. Cross-premises/hybrid  
  
Accessing resources via **Azure Bastion** (Cloud Jumphost)  
![Pasted image 20220714132755](https://user-images.githubusercontent.com/66924945/179816239-40da5d57-74d3-4b3d-beb4-0a59ab65cc04.png)

**Azure Virtual Desktop** - No inbound access needed, outbound required.  
  
Main metrics for organisational risk:   
	**Mean time to acknowledge (MTTA)** - Responsiveness  
	**Mean time to remediate (MTTR)** - Effectiveness  
	**Incidents remediated (manually or with automation)** - Measurement  
	**Escalations between each tier** - Workload management  
  
Only two individuals within the SOC team should have rights to modify the controls governing access to the subscription and its data. (Forensics, Chain of Custody)  
  
**Microsoft Defender for Endpoint** provides forensics information.  
**Live Response**  
	Upload files and run with "Run SCRIPT.ps1"  
	getfile FILENAME to download files/logs  
  
### Design a strategy for securing PaaS, IaaS, and SaaS services  
**Azure Security Baselines** - https://docs.microsoft.com/en-us/security/benchmark/azure/security-baselines-overview  
	**Microsoft Defender** for Cloud recommendations based on these  
  
**IoT architecture zones**: Device, Field Gateway, Cloud Gateways, Services  
	subject to Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service and Elevation of Privilege (STRIDE).  
  
**Microsoft Defender for IoT**  
![Pasted image 20220714153054](https://user-images.githubusercontent.com/66924945/179816305-0d6bb437-8980-41d6-976e-b9655d9d988d.png)

  
**Microsoft Defender for Cloud** integration with **Microsoft Purview** allows metadata to be used in recommendations based on data classification.  
  
**Microsoft Defender for SQL** detects threats such as SQL Injection, brute-force attacks and privilege abuse.  
Dedicated Defender for Azure Cosmos DB  
  
Consider the following recommendations to optimize security when configuring your **Azure Storage** Account:  
-   Turn on soft delete for blob data
-   Use Azure AD to authorize access to blob data.
-   Consider the principle of least privilege when you assign permissions to an Azure AD security principal through Azure RBAC.
-   Use blob versioning or immutable blobs to store business-critical data.
-   Restrict default internet access for storage accounts.
-   Configure firewall rules to limit access to your storage account
-   Limit network access to specific networks.
-   Allow trusted Microsoft services to access the storage account.
-   Enable the Secure transfer required option on all your storage accounts.
-   Limit shared access signature (SAS) tokens to HTTPS connections only.
-   Avoid and prevent using Shared Key authorization to access storage accounts.
-   Regenerate your account keys periodically.
-   Create a revocation plan and have it in place for any SAS that you issue to clients.

  
**Azure Container Registry** optionally integrates with **Microsoft Defender for Cloud** to automatically scan all Linux images pushed to a registry  
  
**Microsoft Defender for Cloud** integrated **Qualys scanner** detects image vulnerabilities, classifies them, and provides remediation guidance.  
  
Sanction a single Linux distribution as a base image, preferably one that is lean (Alpine or CoreOS rather than Ubuntu), to minimize the surface for potential attacks.  
  
**Protecting Kubernetes**
  ![Pasted image 20220714155355](https://user-images.githubusercontent.com/66924945/179816539-b7409b25-be15-493a-87cd-fa7fef56ad39.png)


-   Defender profile includes a _DaemonSet_, which is a set of containers that focus on collecting inventory and security events from the Kubernetes environment.
-   Gatekeeper, Azure Policy, which is the admission controller webhook for Open Policy Agent (OPA), to apply at-scale enforcements and safeguards on your clusters in a centralized, consistent manner.
  
IoT Manufacturer/Integrator is responsible to: Scope hardware to minimum requirements, Make hardware tamper proof, Make upgrades secure.  
  
## Design a strategy for data and applications  
  
### Specify security requirements for applications  
Microsoft Security Development Lifecycle uses STRIDE:  
	Spoofing  
	Tampering  
	Repudiation  
	Information Disclosure  
	Denial of Service  
	Elevation of Privilege  
OWASP has an alternative threat modelling approach for applications  

-   Toolkit for [Secure DevOps on Azure](https://azsk.azurewebsites.net/).  
-   [Guidance on DevOps pipeline security](https://owasp.org/www-project-devsecops-guideline/) by OWASP  
  
The Threat Modeling Tool is a core element of the Microsoft Security Development Lifecycle (SDL).  
  
**SAST** - Static Application testing, source/compiled code that is not executing  
**DAST** - Dynamic Application Security Testing - Testing code while in operation  
  
**DevOps application lifecycle**  
![Pasted image 20220715100401](https://user-images.githubusercontent.com/66924945/179816604-e1435602-69f4-490e-bf5f-7c7f5fdd5664.png)

You can use [CredScan](https://secdevtools.azurewebsites.net/helpcredscan.html) to discover potentially exposed keys in your application code.  
  
### Design a strategy for securing data  
  
**Classifying Data**  
**SIT** - Sensitive Information Type  
**EDM** - Exact Data Match  

![Pasted image 20220715105049](https://user-images.githubusercontent.com/66924945/179816641-c1e34197-70b1-4825-a7f3-85685cafa110.png)
  
**Defender for Cloud Apps**: Discover, Classify, Protect, Monitor.  
**Microsoft Purview**: Know your data, Protect your data, Prevent Data loss, Govern your data.  
  
**Know Your Data**  
	**Sensitive information types** - Identified with Regex/functions  
	**Trainable classifiers** - Identifies by using example data, builtin or custom  
	**Data Classification** - Graphical identification of labels/classification  
  
**Protect your data**  
	**Sensitivity labels** - label and protect data inside and outside of organisation  
	**Azure Information Protection unified labelling client** - Windows explorer/PowerShell  
	**Double Key Encryption** - Nobody else can decrypt. Hold within geographical boundary.  
	**Office 365 Message Encryption (OME)** - Encrypts email + attachments  
	**Service encryption with Customer key** - Protects against viewing, complements Bitlocker in Microsoft Datacenters  
	**SharePoint Information Rights Management (IRM)** - Authorised people only can view with checkout and can use the file according to organisation policies  
	**Rights Management connector** - On-prem protection for Exchange, SharePoint and File Classification Infrastructure (FCI) file servers  
	**Azure Information Protection unified labelling scanner** - on-premise scanner  
	**Microsoft Defender for Cloud Apps** - Handles information in the cloud  
	**Microsoft Purview Data Map** - Labels files in Azure Data Lake, Azure Files, Azure SQL DB and Cosmos DB  
	**Microsoft Information Protection SDK** - Extends labels to third-party apps  
  
**Best Practice - Isolating data environments:**  
![Pasted image 20220715110623](https://user-images.githubusercontent.com/66924945/179816690-4423d765-bc42-4c50-abd8-3f7d0914c34c.png)

Principles can be applied for compliance between regions also  
  
**Encryption of data in transit**  
	**Data-link Layer encryption in Azure** - IEEE 802.1AE (MACsec)  
	**TLS encryption in Azure** - Between cloud and customer  
	**Perfect Forward Secrecy (PFS)** - RSA 2048 keylength unique keys  
	**Azure Storage Transactions** - REST API over HTTPS  
	**Shared Access Signatures (SAS)** - Delegate access to Azure storage objects   
	**SMB Encryption over Azure virtual networks** - SMB 3.0  
	**Point-to-site VPNs** - Clients > Azure via Secure Socket Tunneling Protocol (SSTP)  
	**Site-to-site VPNs** - Network > Azure via IPsec/IKE VPN tunnel  
  
Manage **Azure Key Vault** with the **Key Vault Contributor** RBAC Role.  
  
Use a [privileged access workstation](https://4sysops.com/archives/understand-the-microsoft-privileged-access-workstation-paw-security-model/) to reduce the attack surface in workstations.  
  
Use [Azure Disk Encryption](https://docs.microsoft.com/en-us/azure/security/fundamentals/azure-disk-encryption-vms-vmss). It enables IT administrators to encrypt Windows and Linux IaaS VM disks.  

