# SC-900 Microsoft Security, Compliance, and Identity Fundamentals - Study Notes

**Author:** Stuart Mackay
<!-- Author: Stuart Mackay -->

## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://learn.microsoft.com/en-us/certifications/resources/study-guides/sc-900)
- [Official Microsoft Learning Path](https://learn.microsoft.com/en-us/certifications/exams/sc-900/)
- [SC-900 Labs](https://github.com/MicrosoftLearning/SC-900-Microsoft-Security-Compliance-and-Identity-Fundamentals/tree/master/Instructions/Labs)
- [John Savill SC-900 Study Cram (Youtube)](https://www.youtube.com/watch?v=Bz-8jM3jg-8)


## Notes from Microsoft Learn & Microsoft Docs:

## Part 1: Describe the concepts of security, compliance, and identity

###  Describe security and compliance concepts

![Pasted image 20220621102849](https://user-images.githubusercontent.com/66924945/232289824-89960a9d-6872-48de-ac6a-9bada3263bf3.png)


![Pasted image 20220621103337](https://user-images.githubusercontent.com/66924945/232289833-8c9aee76-d76e-4e86-95a2-699ea51848b0.png)


-   **Data residency** - When it comes to compliance, data residency regulations govern the physical locations where data can be stored and how and when it can be transferred, processed, or accessed internationally. These regulations can differ significantly depending on jurisdiction.

-   **Data sovereignty** - Another important consideration is data sovereignty, the concept that data, particularly personal data, is subject to the laws and regulations of the country/region in which it's physically collected, held, or processed. This can add a layer of complexity when it comes to compliance because the same piece of data can be collected in one location, stored in another, and processed in still another; making it subject to laws from different countries/regions.

-   **Data privacy** - Providing notice and being transparent about the collection, processing, use, and sharing of personal data are fundamental principles of privacy laws and regulations. Personal data means any information relating to an identified or identifiable natural person. Privacy laws previously referenced "PII" or "personally identifiable information" but the laws have expanded the definition to any data that is directly linked or indirectly linkable back to a person. Organizations are subject to, and must operate consistent with, a multitude of laws, regulations, codes of conduct, industry-specific standards, and compliance standards governing data privacy.

### Describe identity concepts
**Define Identity as the primary security perimeter**

![Pasted image 20220621104229](https://user-images.githubusercontent.com/66924945/232289840-f69c6a7c-b5f7-40c8-b1a6-da3d3bb814d9.png)


**Four pillars of an identity infrastructure**
-   **Administration**. Administration is about the creation and management/governance of identities for users, devices, and services. As an administrator, you manage how and under what circumstances the characteristics of identities can change (be created, updated, deleted).
-   **Authentication**. The authentication pillar tells the story of how much an IT system needs to know about an identity to have sufficient proof that they really are who they say they are. It involves the act of challenging a party for legitimate credentials.
-   **Authorization**. The authorization pillar is about processing the incoming identity data to determine the level of access an authenticated person or service has within the application or service that it wants to access.
-   **Auditing**. The auditing pillar is about tracking who does what, when, where, and how. Auditing includes having in-depth reporting, alerts, and governance of identities.

**Describe the role of the identity provider**

Watch this video (with cool air drawing) - https://docs.microsoft.com/en-gb/learn/modules/describe-identity-principles-concepts/4-describe-role-identity-provider

As you see in the video, thanks to modern authentication, the client communicates with the identity provider by giving an identity that can be authenticated. When the identity (which can be a user or an application) has been verified, the identity provider issues a _security token_ that the client sends to the server.
The server validates the security token through its _trust relationship_ with the identity provider. By using the security token and the information that's contained within it, the user or application accesses the required resources on the server. In this scenario, the token and the information it contains is stored and managed by the identity provider. The centralized identity provider is supplying the authentication service.
Microsoft Azure Active Directory is an example of a cloud-based identity provider. Other examples include Twitter, Google, Amazon, LinkedIn, and GitHub.

**AD DS** doesn't, however, natively support mobile devices, SaaS applications, or line of business apps that require _modern authentication_ methods.
Azure Active Directory is the next evolution of identity and access management solutions. It provides organizations with an **Identity as a Service (IDaaS)** solution for all their apps across cloud and on-premises.

## Part 2: Describe the capabilities of Microsoft Identity and access management solutions

### Describe the services and identity types of Azure AD
**Azure AD is available in four editions: Free, Office 365 Apps, Premium P1, and Premium P2**

**Azure Active Directory Free**. The free version allows you to administer users and create groups, synchronize with on-premises Active Directory, create basic reports, configure self-service password change for cloud users, and enable single sign-on across Azure, Microsoft 365, and many popular SaaS apps. The free edition is included with subscriptions to Office 365, Azure, Dynamics 365, Intune, and Power Platform.

**Office 365 Apps**. **Self-service password reset for cloud users**, and device write-back, which offers **two-way synchronization between on-premises directories and Azure AD**. The Office 365 Apps edition of Azure Active Directory is included in subscriptions to Office 365 E1, E3, E5, F1, and F3.

**Premium P1** - **dynamic groups**, **self-service group management**, **Microsoft Identity Manager** and cloud write-back capabilities (**on-prem self-service password reset**)

**Premium P2** - **PIM** & **AAD Identity Protection**

There's also an option for "**Pay as you go**"  **feature licenses**. 

A **service principal** is an identity for an application

- **Managed identities** are a type of service principal that are automatically managed in Azure AD and eliminate the need for developers to manage credentials. Managed identities provide an identity for applications to use when connecting to Azure resources that support Azure AD authentication and can be used without any extra cost.
	- **System assigned** - identity tied to lifecycle of a service
	- **User-assigned** - Standalone resource, assignable to one or many services

- **B2B** - Users from other orgs, can be added to groups, self-service flows, type:guest
- **B2C** - CIAM Solution (Customer Identity Access Management) social,local,enterprise 
	managed in Azure AD B2C directory (seperate), customizable login screen
- **Both of these external identity types need P1 or P2 Azure AD**

- **Azure AD Password hash synchronization** - uses **AD Connect** to sync passwords
- **Azure AD pass-through authentication** - Same as hash but Validation only on-prem
- **Federated authentication** - Federation is recommended as an authentication for organizations that have advanced features not currently supported in Azure AD, including sign-on using smart cards or certificates, sign-on using on-premises multi-factor authentication (MFA) server, and sign-on using a third party authentication solution.
In federated authentication, Azure AD hands off the authentication process to a separate trusted authentication system, such as on-premises Active Directory Federation Services (AD FS), to validate the user’s password. This sign-in method ensures that all user authentication occurs on-premises.

### Describe the authentication capabilities of Azure AD
**OATH** (Open Authentication) is an open standard that specifies how time-based, one-time password (TOTP) codes are generated. Software and Hardware

**Windows Hello for Business** replaces passwords with strong two-factor authentication on devices.

**FIDO 2** - Fast Identity Online (FIDO) is an open standard for passwordless authentication.
	incorporates the web authentication (WebAuthn) standard

**Microsoft Authenticator app** - Can be used as a primary or additional verification

**Security Defaults** - A set of basic identity security mechanisms reccomended by MS
	Enforcing MFA
	Good place for organisations to start, many not be appropriate for P1/2

**Self-service password reset (SSPR)**
	User must have an Azure AD License, enabled for SSPR and registered

**Global banned password list**, **Custom banned password list (P1/P2)**
	Helps defend agains **Password Spraying**
	Can be applied on-prem

### Describe the access management capabilities of Azure AD

**Conditional Access**  - Like IF>THEN statements based on conditions

**Azure AD RBAC**

-   _Global administrator_: users with this role have access to all administrative features in Azure Active Directory. The person who signs up for the Azure Active Directory tenant automatically becomes a global administrator.
-   _User administrator_: users with this role can create and manage all aspects of users and groups. This role also includes the ability to manage support tickets and monitor service health.
-   _Billing administrator_: users with this role make purchases, manage subscriptions and support tickets, and monitor service health.

**Custom roles** only on P1/P2

![Pasted image 20220621130819](https://user-images.githubusercontent.com/66924945/232289847-62714622-1add-4f70-a67c-ad8fc5ddfd84.png)


-   Azure AD RBAC - Azure AD roles control access to Azure AD resources such as users, groups, and applications.
-   Azure RBAC - Azure roles control access to Azure resources such as virtual machines or storage using Azure Resource Management.

### Describe the identity protection and governance capabilities of Azure AD
Azure AD identity governance gives organizations the ability to do the following tasks:
	- Govern the identity lifecycle.
	- Govern access lifecycle.
	- Secure privileged access for administration.

It's intended to help organizations address these four key questions:
	1. Which users should have access to which resources?
	2. What are those users doing with that access?
	3. Are there effective organizational controls for managing access?
	4. Can auditors verify that the controls are working?

**Entitlement management**, a feature of Azure AD Premium P2, uses access packages to manage access to resources.

**Access reviews** are a feature of Azure AD Premium P2.

**Privileged Identity Management** is a feature of Azure AD Premium P2.

**Azure Identity Protection**
	Automate the detection and remediation of identity-based risks.
	Investigate risks using data in the portal.
	Export risk detection data to third-party utilities for further analysis.
Identity Protection categorizes risk into **three tiers**: low, medium, and high. It can also calculate the sign-in risk, and user identity risk.
Anon/Malware IPs, atypical travel, password spray, Azure AD Threat intelligence, unfamiliar sign in properties (previous locations)
-   Azure AD threat intelligence. This risk detection type indicates user activity that is unusual for the given user or is consistent with known attack patterns based on Microsoft's internal and external threat intelligence sources.
Three reports:  **risky users**, **risky sign-ins**, and **risk detections**.

Identity Protection is a feature of Azure AD Premium P2
	Uses **Security Signals** to identify potential threats 

## Part 3: Describe the capabilities of Microsoft security solutions

### Describe basic security capabilities in Azure
- **DDoS Protection**
	- Basic - Automatically enabled for all, uses same defences as for MS services
	- Standard - Extra mitigation tuned for VMs, policies applied to Gateway/Balancer
		- Fixed monthly charge for up to 100 resources

- **Azure Firewall** is a managed, cloud-based network security service that protects your Azure virtual network (VNet) resources from attackers.
	best approach is to use it on a centralized virtual network
	- **Built-in high availability and availability zones**
	- **Network and application level filtering**
	- **Outbound SNAT and inbound DNAT to communicate with internet resources**
	- **Multiple public IP addresses**
	- **Threat intelligence**
	- **Integration with Azure Monitor**

**Azure Web Application Firewall** - Protect application from known exploits

**Azure Virtual Network (VNet)** is the building block for private network in Azure.
	VNet is similar to a traditional network that you'd operate in your own data center, but brings with it additional benefits of Azure's infrastructure such as scale, availability, and isolation.
	Can create **multiple VNets per region per subscription**, and multiple smaller networks (subnets) can be created within each VNet.

![Pasted image 20220621153337](https://user-images.githubusercontent.com/66924945/232289856-6508d047-3ed7-46e6-b16f-855e65f8c38c.png)


- **Network security groups (NSGs)** let you filter network traffic to and from Azure resources in an Azure virtual network.
	- You can associate only one network security group to each virtual network subnet and network interface in a virtual machine. The same network security group, however, can be associated to as many different subnets and network interfaces as you choose.
	- NSG security rules are evaluated by priority using **five information points**: source, source port, destination, destination port, and protocol to either allow or deny the traffic.

- **Default 3 rules in all NSGs** - (Priority 65000,65001,65500 - lowest first)
	- AllowVNetInBound, AllowAzureLoadBalancerInBound, DenyAllInBound

**Network security groups** provide distributed network layer traffic filtering to limit traffic to resources _**within**_ virtual networks in each subscription. 

**Azure Firewall** is a fully stateful, centralized network firewall as-a-service, which provides network and application-level protection _**across**_ different subscriptions and virtual networks.

**Azure Bastion** is a service you deploy that lets you connect to a virtual machine using your browser and the Azure portal.

![Pasted image 20220621154456](https://user-images.githubusercontent.com/66924945/232289867-0945f030-82e5-436b-bbdd-301dc92a5e6e.png)

Azure Bastion deployment is **per virtual network** with support for virtual network peering, not per subscription/account or virtual machine. Once you provision the Azure Bastion service in your virtual network, the RDP/SSH experience is available to all your VMs in the same VNet, as well as peered VNets.

**Just-in-time (JIT)** access allows lock down of the inbound traffic to your VMs, reducing exposure to attacks while providing easy access to connect to VMs when needed.
	When a user requests access to a VM, Defender for Cloud checks that the user has Azure role-based access control (Azure RBAC) permissions for that VM. If the request is approved, Defender for Cloud configures the NSGs and Azure Firewall to allow inbound traffic to the selected ports from the relevant IP address (or range), for the amount of time that was specified. After the time has expired, Defender for Cloud restores the NSGs to their previous states. Connections that are already established are not interrupted.
- **JIT requires Microsoft Defender** for servers to be enabled on the subscription.

**Encryption on Azure**
-   **Azure Storage Service Encryption** helps to protect data at rest by automatically encrypting before persisting it to Azure-managed disks, Azure Blob Storage, Azure Files, or Azure Queue Storage, and decrypts the data before retrieval.
-   **Azure Disk Encryption** helps you encrypt Windows and Linux IaaS virtual machine disks. Azure Disk Encryption uses BitLocker and the dm-crypt feature of Linux to provide volume encryption for the OS and data disks.
-   **Transparent data encryption (TDE)** helps protect Azure SQL Database and Azure Data Warehouse against the threat of malicious activity. It performs real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application.

**Azure Key Vault**
-   **Secrets management** -  Control access to tokens, passwords, certificates, Application Programming Interface (API) keys, and other secrets.
-   **Key management** 
-   **Certificate management** 
-   **Store secrets backed by hardware security modules (HSMs)** - The secrets and keys can be protected either by software or by FIPS 140-2 Level 2 validated HSMs.

### Describe security management capabilities of Azure
**CSPM (Cloud security posture management)** uses a combination of tools and services:
-   **Zero Trust-based access control**: Considers the active threat level during access control decisions.
-   **Real-time risk scoring**: To provide visibility into top risks.
-   **Threat and vulnerability management (TVM)**: Establishes a holistic view of the organization's attack surface and risk and integrates it into operations and engineering decision-making.
-   **Discover risks**: To understand the data exposure of enterprise intellectual property, on sanctioned and unsanctioned cloud services.
-   **Technical policy**: Apply guardrails to audit and enforce the organization's standards and policies to technical systems.
-   **Threat modeling systems and architectures**: Used alongside other specific applications.
The main goal for a cloud security team working on posture management is to continuously report on and improve the organization's security posture by focusing on disrupting a potential attacker's return on investment (ROI).

**Use CSPM to improve your cloud security management by assessing the environment, and automatically alerting security staff for vulnerabilities**

**Microsoft Defender for Cloud** is a tool for security posture management and threat protection.

![Pasted image 20220621162253](https://user-images.githubusercontent.com/66924945/232289919-5f8e7e79-42ec-420b-b2db-5a235a3d11ed.png)

**Up to 24h for a change to be reflected in Secure Score**

The second pillar of cloud security is **cloud workload protection**

**Microsoft Defender for Cloud** is offered in two modes:
	Free - Secure Score, Security Policy, Continuous Security Assessment, Recs
	With enhanced security features - multiple Microsoft Defender Plans:
- **Microsoft Defender for servers** adds threat detection and advanced defenses for your Windows and Linux machines.
-   **Microsoft Defender for App Service** identifies attacks targeting applications running over App Service.
-   **Microsoft Defender for Storage** detects potentially harmful activity on your Azure Storage accounts.
-   **Microsoft Defender for SQL** secures your databases and their data wherever they're located.
-   **Microsoft Defender for Kubernetes** provides cloud-native Kubernetes security environment hardening, workload protection, and run-time protection.
-   **Microsoft Defender for container registries** protects all the Azure Resource Manager based registries in your subscription.
-   **Microsoft Defender for Key Vault** is advanced threat protection for Azure Key Vault.
-   **Microsoft Defender for Resource Manager** automatically monitors the resource management operations in your organization.
-   **Microsoft Defender for DNS** provides an additional layer of protection for resources that use Azure DNS's Azure-provided name resolution capability.
-   **Microsoft Defender for open-source relational protections** brings threat protections for open-source relational databases.

**Enhanced Microsoft Defender security features**:
- **Comprehensive endpoint detection and response** - Microsoft Defender for servers includes Microsoft Defender for Endpoint for comprehensive endpoint detection and response (EDR).
    
-   **Vulnerability scanning for virtual machines, container registries, and SQL resources** - Easily deploy a scanner to all of your virtual machines. View, investigate, and remediate the findings directly within Microsoft Defender for Cloud.
    
-   **Multi-cloud security** - Connect your accounts from Amazon Web Services (AWS) and Google Cloud Platform (GCP) to protect resources and workloads on those platforms with a range of Microsoft Defender for Cloud security features.
    
-   **Hybrid security** – Get a unified view of security across all of your on-premises and cloud workloads. Apply security policies and continuously assess the security of your hybrid cloud workloads to ensure compliance with security standards. Collect, search, and analyze security data from multiple sources, including firewalls and other partner solutions.
    
-   **Threat protection alerts** - Monitor networks, machines, and cloud services for incoming attacks and post-breach activity. Streamline investigation with interactive tools and contextual threat intelligence.
    
-   **Track compliance with a range of standards** - Microsoft Defender for Cloud continuously assesses your hybrid cloud environment to analyze the risk factors according to the controls and best practices in Azure Security Benchmark. When you enable the enhanced security features, you can apply a range of other industry standards, regulatory standards, and benchmarks according to your organization's needs. Add standards and track your compliance with them from the regulatory compliance dashboard.
    
-   **Access and application controls** - Block malware and other unwanted applications by applying machine learning powered recommendations adapted to your specific workloads to create allowlists and blocklists. Reduce the network attack surface with just-in-time, controlled access to management ports on Azure VMs. Access and application controls drastically reduce exposure to brute force and other network attacks.

**The Azure Security Benchmark (ASB)** (Currently V3)
Is an Excel Spreadsheet hosted on GitHub - https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/Azure%20Security%20Benchmark/3.0
Has mapping to frameworks - CIS, NIST, PCI DSS 

**Security baseline for Azure** - apply guidance from the ASB to a service

![Pasted image 20220621164116](https://user-images.githubusercontent.com/66924945/232289984-a1fc4f6d-b436-496f-99f9-153ed28cee87.png)

https://docs.microsoft.com/en-us/azure/security/benchmarks/

### Describe security capabilities of Microsoft Sentinel
A **SIEM** system is a tool that an organization uses to collect data from across the whole estate, including infrastructure, software, and resources. It does analysis, looks for correlations or anomalies, and generates alerts and incidents.

A **SOAR** system takes alerts from many sources, such as a SIEM system. The SOAR system then triggers action-driven automated workflows and processes to run security tasks that mitigate the issue.

Collect, Detect, Investigate, Respond

- **Connectors:** Microsoft 365 Defender, Office 365, Azure AD etc, + 3rd Party
- **Azure Monitor Workbooks** - Canvas for data analysis and reports, customised
- **Analytics** - built-in rules, build your own, machine learning rules
- **Incident Management** - View alerts and related entities, trigger playbooks
	- **Playbooks** - Work best with single, repeatabke tasks - no coding
- **Automation & Orchestration** - Integration with **Azure Logic Apps**
- **Hunting** - Based on MITRE Framework, **bookmarking** possble
- **Notebooks** - Sentinal supports Jupyter Notebooks (live code)
	- Can be used to integrate on-prem data sets
- **Community** - Custom workbooks, playbooks, hunting queries etc..

Billing is based on the volume of data ingested for analysis in Microsoft Sentinel and stored in the Azure Monitor Log Analytics workspace. 
2 Ways to pay:
	- **Capacity Reservations**: Fixed fee based on tier
	- **Pay-As-You-Go**: With Pay-As-You-Go pricing, you're billed per gigabyte (GB) for the volume of data ingested for analysis in Microsoft Sentinel and stored in the Azure Monitor Log Analytics workspace.

### Describe threat protection with Microsoft 365 Defender

![Pasted image 20220622131957](https://user-images.githubusercontent.com/66924945/232290011-2c24d9b2-6eeb-44b7-a9ce-060393dd3dc8.png)

Microsoft 365 Defender suite protects:

-   **Identities with Microsoft Defender for Identity and Azure AD Identity Protection** - uses Active Directory signals to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.
-   **Endpoints with Microsoft Defender for Endpoint** - unified endpoint platform for preventative protection, post-breach detection, automated investigation, and response.
-   **Applications with Microsoft Defender for Cloud Apps** - comprehensive cross-SaaS solution that brings deep visibility, strong data controls, and enhanced threat protection to your cloud apps.
-   **Email and collaboration with Microsoft Defender for Office 365** -  safeguards against malicious threats posed by email messages, links (URLs), and collaboration tools.

Threat protection policies, Reports, Threat investigation/response-can automate

Microsoft Defender for Office 365 - **2 Plans**
- **Plan 1** - Safe Attachments/links, Anti-Phising, Real-time detection
		- Applies to Email, Teams, SharePoint, OneDrive
- **Plan 2** - Same + **Threat trackers**, **Threat Explorer**, **Automated investigation and response (AIR)**, **Attack Simulator**, **Proactive threat hunting**, **Investigate alerts and incidents**

**Microsoft Defender for Endpoint** - 

![Pasted image 20220622132950](https://user-images.githubusercontent.com/66924945/232290020-caa54ee9-8945-45e8-92cb-cfb43a2966b5.png)


Microsoft Defender for Endpoint includes Microsoft Secure Score for Devices to help you dynamically assess the security state of your enterprise network, identify unprotected systems, and take recommended actions to improve overall security.

**Microsoft Defender for Cloud Apps** - Is a Cloud Access Security Broker (CASB)
A CASB acts as a gatekeeper to broker real-time access between your enterprise users and the cloud resources they use, wherever they're located, and regardless of the device they're using. CASBs help organizations protect their environment by providing a wide range of capabilities across the following pillars:

-   **Visibility** - Detect cloud services and app use and provide visibility into Shadow IT.
-   **Threat protection** - Monitor user activities for anomalous behaviors, control access to resources through access controls, and mitigate malware.
-   **Data security** - Identify, classify and control sensitive information, protecting against malicious actors.
-   **Compliance** - Assess the compliance of cloud services.

**Defender for Cloud Apps framework**
Built on a framework that provides the following capabilities:
-   **Discover and control the use of Shadow IT**: Identify the cloud apps, and IaaS and PaaS services used by your organization. Investigate usage patterns, assess the risk levels and business readiness of more than 25,000 SaaS apps against more than 80 risks.
-   **Protect against cyberthreats and anomalies**: Detect unusual behavior across cloud apps to identify ransomware, compromised users, or rogue applications, analyze high-risk usage, and remediate automatically to limit risks.
-   **Protect your sensitive information** **anywhere in the cloud**: Understand, classify, and protect the exposure of sensitive information at rest. Use out-of-the-box policies and automated processes to apply controls in real time across all your cloud apps.
-   **Assess your cloud apps' compliance**: Assess if your cloud apps meet relevant compliance requirements, including regulatory compliance and industry standards. Prevent data leaks to non-compliant apps and limit access to regulated data.

**Microsoft Defender for Cloud Apps functionality**
Delivers on the framework via features/functionality. Some examples:
-   **Cloud Discovery** maps and identifies your cloud environment and the cloud apps your organization uses. Cloud Discovery uses your traffic logs to dynamically discover and analyze the cloud apps being used.

-   **Sanctioning and unsanctioning apps** in your organization by using the Cloud apps catalog that includes over 25,000 cloud apps. The apps are ranked and scored based on industry standards. You can use the cloud app catalog to rate the risk for your cloud apps based on regulatory certifications, industry standards, and best practices.
   
-   Use **App connectors** to integrate Microsoft and non-Microsoft cloud apps with Microsoft Defender for Cloud Apps, extending control and protection. Defender for Cloud Apps queries the app for activity logs, and it scans data, accounts, and cloud content that can be used to enforce policies, detect threats and provide governance actions to resolve issues.
  
-   **Conditional Access** App Control protection provides real-time visibility and control over access and activities within your cloud apps. Avoid data leaks by blocking downloads before they happen, setting rules to require data stored in and downloaded from the cloud to be protected with encryption, and controlling access from non-corporate or risky networks.
   
-   Use **policies** to detect risky behavior, violations, or suspicious data points and activities in your cloud environment. You can use policies to integrate remediation processes to achieve risk mitigation.

**Office 365 Cloud App Security** - Protection for office, Shadow IT Detection

**Enhanced Cloud App Discovery in Azure Active Directory**
	Included in **P1** for free - Reduced subset of Microsoft Defender for Cloud Apps


**Microsoft Defender for Identity**
Cloud-based security solution. It uses your on-premises Active Directory data (called signals) to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions.
	- **Monitor and profile user behavior and activities.**
	- **Protect user identities and reduce the attack surface.**
	- **Identify and investigate suspicious activities and advanced attacks** across the cyberattack kill-chain.
	- **Provide clear incident information** on a simple timeline for fast triage

Defender for Identity identifies these advanced threats at the source throughout the entire cyberattack kill-chain:
-   Reconnaissance
-   Compromised credentials
-   Lateral movements
-   Domain dominance

Microsoft 365 Defender natively coordinates detection, prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated protection against sophisticated attacks. **The Microsoft 365 Defender portal** brings this functionality together into a central place

![Pasted image 20220622140909](https://user-images.githubusercontent.com/66924945/232290045-316fd370-b969-452f-9059-3e39ca72aebd.png)

**You must be assigned an appropriate role, such as Global Administrator, Security Administrator, Security Operator, or Security Reader in Azure Active Directory to access the Microsoft 365 Defender portal.**

**Incidents & Queue**

![Pasted image 20220622141057](https://user-images.githubusercontent.com/66924945/232290052-1cd7bcb8-87b8-40da-af1c-db630d1bae8f.png)


**Advanced Hunting** - Query based tool, 30 days of raw data, custom rules

**Threat Analytics** - Threat intelligence solution designed to assist security teams track and respond to emerging threats. 

![Pasted image 20220622141257](https://user-images.githubusercontent.com/66924945/232290061-40de0882-4c06-4467-aa88-791d7e07321b.png)


**Secure Score** - Representation of security posture
Differences between 
	- **Microsoft 365 Defender** - Apps, Devices, Identities
	- **Microsoft Defender for Cloud** - Azure Subcriptions

**Learning Hub** - MS Security blog, YouTube, docs.microsoft.com

**Reports** - General and specific

**Permissions and Roles** - Azure AD global roles or custom


## Part 4: Describe the capabilities of Microsoft compliance solutions

### Describe the Service Trust Portal and privacy at Microsoft

**Microsoft Priva** - helps organizations safeguard personal data and build a privacy-resilient workplace.

- **The Service Trust Portal** - (servicetrust.microsoft.com)
	- **Service Trust Portal** - Home
	- **Compliance Manager** - Redirects to Microsoft Purview compliance portal
	- **Trust Documents** - Audit Reports, Data Protection, Azure Stack
	- **Industries & Regions** - Eg Finance industry and UK region
	- **Trust Center** - More info about pravacy, security and compliance
	- **Resources** - links to Security & Compliance for Office 365 & FAQs
	- **My Library** - Save docs & get updates

- **Microsoft's Privacy Principles**
	- **Control**
	- **Transparency**
	- **Security**
	- **Strong legal protections**
	- **No content-based targeting**
	- **Benefits to you**

**Describe Microsoft Priva**

2 solutions
 - **Priva Privacy Risk Management** - Visibility into templates for reducing risks
 - **Priva Subject Rights Requests** - Automation and workflow for requests


**Priva Privacy Risk Management**

![Pasted image 20220622155415](https://user-images.githubusercontent.com/66924945/232290068-f72ecdcb-1e42-43b0-b191-327276d86c2e.png)


**Data profile page** provides a snapshot of data stored in Microsoft 365 + location

![Pasted image 20220622160248](https://user-images.githubusercontent.com/66924945/232290073-7f31a66f-c1b7-4973-be55-ffc7cca85c8e.png)


**Privacy Risk Management** in Microsoft Priva also gives you the capability to set up policies that identify privacy risks in your Microsoft 365 environment and enable easy remediation. Privacy Risk Management policies are meant to be internal guides and can help you:
-   Detect overexposed personal data so that users can secure it.
-   Spot and limit transfers of personal data across departments or regional borders.
-   Help users identify and reduce the amount of unused personal data that you store.


### Describe the compliance management capabilities in Microsoft Purview
**Microsoft 365 compliance is now called Microsoft Purview**

**Purview compliance portal** - Global/Compliance/Compliance data administrator

![Pasted image 20220622161629](https://user-images.githubusercontent.com/66924945/232290090-d4469efe-1dc6-4cd9-8be2-e24b8011e7bf.png)

- **Compliance Manager** Card
- **Solution catalog** card
- **Active alerts** card

![Pasted image 20220622164252](https://user-images.githubusercontent.com/66924945/232290123-cf42f710-b718-45bb-a911-c4fce054d8e2.png)

**Compliance manager** 

### Describe information protection and data lifecycle management in Microsoft Purview
**Microsoft Purview Information Protection** discovers, classifies, and protects sensitive and business-critical content throughout its lifecycle across your organization. It provides the tools to know your data, protect your data, and prevent data loss.

**Microsoft Purview Data Lifecycle Management** manages your content lifecycle using solutions to import, store, and classify business-critical data so you can keep what you need and delete what you don't. It gives organizations the capabilities to govern their data, for compliance or regulatory requirements.

**Data Classification** - 
- **Overview** - Home page
- **Trainable classifiers** - profanity, CVs etc
	- Can create custom classifiers
- **Sensitive info types** - Credit Cards etc
- **Content explorer** - how many items are sensitive, how many labels
- **Activity explorer** - review classification activity - label change, file change

- **Labels** - Mark content, encrypt, classify, can be required, custom etc
- **DLP** - automatically protect. Conditions, Actions, Locations
- **Endpoint DLP** - View what users do - Create, rename, print, access etc
- **Retention Policy** - site/mailbox level
- **Retention label** - item level folder/document/email
- **Records management** - Manuall or auto applying retention/delete actions

### Describe insider risk capabilities in Microsoft Purview
**Microsoft Purview Insider Risk Management** is a solution that helps minimize internal risks by enabling an organization to detect, investigate, and act on risky and malicious activities. Insider risk management is available in the Microsoft Purview compliance portal.

![Pasted image 20220622170640](https://user-images.githubusercontent.com/66924945/232290136-52e3176c-9e2c-48b8-8638-5abbda2aaf9f.png)


**Purview Information Barriers** - restrict communications between groups
**Communication compliance** - Restrict language used

### Describe the eDiscovery and audit capabilities of Microsoft Purview

![Pasted image 20220622171451](https://user-images.githubusercontent.com/66924945/232290143-e4810398-0ce6-4360-b4dd-065ee3756c09.png)


![Pasted image 20220622171514](https://user-images.githubusercontent.com/66924945/232290149-4ca68fa3-0df7-409b-92fa-919c86cb759e.png)


### Describe resource governance capabilities in Azure

**Azure Policy**
Azure Policy is designed to help enforce standards and assess compliance across your organization. Through its compliance dashboard, you can access an aggregated view to help evaluate the overall state of the environment. You can drill down to a per-resource, or per-policy level granularity. You can also use capabilities like bulk remediation for existing resources and automatic remediation for new resources, to resolve issues rapidly and effectively. Common use cases for Azure Policy include implementing governance for resource consistency, regulatory compliance, security, cost, and management.

**Azure Blueprints**
Azure Blueprints provide a way to define a repeatable set of Azure resources. Azure Blueprints enable development teams to rapidly provision and run new environments, with the knowledge that they're in line with the organization’s compliance requirements. Teams can also provision Azure resources across several subscriptions simultaneously, meaning they can achieve shorter development times and quicker delivery.

**Microsoft Purview**

![Pasted image 20220622171926](https://user-images.githubusercontent.com/66924945/232290161-bd62c62f-dfcf-4769-9594-e551e02f101b.png)

- **Data Map** - Captures metadata
- **Data Catalog** - Search with filters - glossary terms, classifications, labels
- **Data Estate Insights** - high level, what is scanned, where it is, how it moves

<!-- Author: Stuart Mackay -->
