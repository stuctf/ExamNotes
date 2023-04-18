# MS-500 Microsoft 365 Security Administration - Study Notes

**Author:** Stuart Mackay
<!-- Author: Stuart Mackay -->

>**Warning**
>This exam will retire on June 30, 2023, but I will keep these notes up for reference

## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://learn.microsoft.com/en-us/certifications/resources/study-guides/MS-500)
- [Official Microsoft Learning Path](https://docs.microsoft.com/en-us/certifications/exams/ms-500)
- [MS-500 Labs](https://microsoftlearning.github.io/MS-500-Microsoft-365-Security/)

  
## Notes from Microsoft Learn & Microsoft Docs:

## Implement and manage identity and access
  
### Create, configure, and manage identities
Roles which can restore (up to 30 days) or permanently delete users:
-   Global administrator
-   Partner Tier1 Support
-   Partner Tier2 Support
-   User administrator
  
**Security groups** - Apply set of permissions to users
**Microsoft 365 groups**  (Distriburion Groups) - Adds collaboration via mailbox, calendar, SharePoint etc - Users outside organization can be added.
  **Assigned vs Dynamic:** Assigned maintained manually, Dynamic based on rules/filters

**Azure AD registered devices** - For BYOD & Mobile Scenarios
**Azure AD Joined Devices** - For Cloud first / Hybrid approach (Win 10/11 only), SSO to cloud **and on-prem**
**Device Writeback** - Objects in Azure AD copied to "Registered Devices" AD container
  
**Group-based licences** available with the following subscriptions:
-   Paid or trial subscription for Azure AD Premium P1 and above
-   Paid or trial edition of Office 365 Enterprise E3 or Office 365 A3 or Office 365 GCC G3 or Office 365 E3 for GCCH or Office 365 E3 for DOD and above
**Group-based licensing is currently available only through the Azure portal**
For group license assignment, any users without a usage location specified inherit the location of the directory.  Recommendation to always set location as part of user creation flow in Azure AD.
  
**Custom security attributes** in Azure Active Directory (Azure AD) are business-specific attributes (key-value pairs) that you can define and assign to Azure AD objects. These attributes can be used to store information, categorize objects, or enforce fine-grained access control over specific Azure resources.


![Pasted image 20220905112510](https://user-images.githubusercontent.com/66924945/231984119-124a9863-369b-4fb2-8f7f-8dd2dc0b4722.png)


**Components of system SCIM (System for Cross-Domain Identity Management)**
-   **HCM system** - Applications and technologies that enable Human Capital Management process and practices that support and automate HR processes throughout the employee lifecycle.
-   **Azure AD Provisioning Service** - Uses the SCIM 2.0 protocol for automatic provisioning. The service connects to the SCIM endpoint for the application, and uses the SCIM user object schema and REST APIs to automate provisioning and de-provisioning of users and groups.
-   **Azure AD** - User repository used to manage the lifecycle of identities and their entitlements.
-   **Target system** - Application or system that has SCIM endpoint and works with the Azure AD provisioning to enable automatic provisioning of users and groups.
If a user can be automatically deprovisioned from Azure AD, as soon as the're removed from your HR-systems; you have less worry on a possible breach.
  
### Explore identity synchronization
**Authentication options:**
 - **Cloud-only** - Everything handled by Azure AD
 - **Directory sync with Pass-Through authentication (PTA)** - Users managed On-Prem
 - **Single Sign-On with AD FS** - Users authenticate to AD FS Proxy
  
**Provisioning options:**
- **On-Premises** - Using Active Directory
- **Cloud** - Using Azure AD
- **Hybrid** - Using both via synchronization and optionally Federation Services
  
**Azure AD Connect** - Officially recommended sync tool for Microsoft 365  
Important to check for latest changes and security fixes here: https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-version-history
  
Azure AD Connect provides password writeback functionality that allows your users to change and reset their passwords in the cloud and have your on-premises password policy applied.
  

### Implement and manage hybrid identity
  
**Cloud Authentication**
- **Azure AD password hash synchronization (PHS)** - Simplest, same on-prem creds
- **Azure AD pass-through authentication (PTA)** - Software agent on prem servers
You can use password hash synchronization as a backup authentication method for pass-through authentication when the agents can't validate a user's credentials due to a significant on-premises failure. Fail over to password hash synchronization doesn't happen automatically and you must use Azure AD Connect to switch the sign-in method manually.
- **Federated Authentication** - Auth handled by ADFS, smartcard, 3rd party MFA
Architecture diagrams available for all scenarios
  
**sourceAnchor** - Unique Identifier for object which is on prem and in Azure
Some organizations have non-routable domains, like contoso.local, or simple single label domains like contoso. You're not able to verify a non-routable domain in Azure AD. Azure AD Connect can sync to only a verified domain in Azure AD. When you create an Azure AD directory, it creates a routable domain that becomes the default domain for your Azure AD

![Pasted image 20220627152234](https://user-images.githubusercontent.com/66924945/231984253-88b51769-7ebb-4342-992a-acf1f182a74e.png)

  
**Azure Active Directory cloud sync**
Azure AD Connect cloud sync is designed to accomplish hybrid identity goals for synchronization of users, groups and contacts to Azure AD. The synchronization is accomplished by using the **Azure AD cloud provisioning agent** instead of the Azure AD Connect application. It can be used alongside Azure AD Connect sync
  
**Password hash synchronization (PHS)**

![Pasted image 20220627152500](https://user-images.githubusercontent.com/66924945/231984301-303a1d03-f3ba-41d3-9582-797dfedd720b.png)

Azure AD Connect synchronizes a hash, of the hash, of a user's password from an on-premises Active Directory instance to a cloud-based Azure AD instance.
The password hash synchronization process runs every 2 minutes.
  
**Pass-through authentication and Seamless Single Sign-On(SSO)**
Azure AD now talks Kerberos
Using PTA allows passwords and authentication to stay on prem 
Install agent on same server as AD Connect - these agents auto-update
  
Use **Azure AD Connect wizard** to repair trust, federate using alternate login ID, add an ADFS Web Application Proxy server.
**Device writeback** is used to enable device-based conditional Access for ADFS-protected devices.
  
**Azure Active Directory Connect Health** provides robust monitoring of on-prem identity infrastructure.  Info in **Azure AD Connect Health portal** - P1 Required
  
### Implement and manage external identities
  
![Pasted image 20220627133403](https://user-images.githubusercontent.com/66924945/231984353-3f3d05ff-1bde-4771-93d6-074b146accd1.png)

  
B2B users can be added as members instead of guests via the API (partner org)
Microsoft 365 can invite guest users for collaboration - shown as external
After you set up direct federation with an organization, any new guest users you invite will be authenticated using direct federation.
  
**Microsoft Entra verified ID** - uses a Digital ID issuer and subject to identify claims
  

### Manage secure user access in Microsoft 365
**Global banned password list** - Based on Azure AD security telemetry and analysis
**Custom banned password list** - Add company specific words, variants auto-blocked
**Azure AD Password protection** - Uses Azure telemetry to combat password spraying
  
**Azure AD pass-through authentication (PTA)** used instead of password hash synchronisation when authentication is required to happen on-prem.
- Handled by AD Connect
- Can be configured to fail back to Password hash synchronisation if on-prem AD fails
- Requires agent on one or more on-prem servers

![Pasted image 20220906113732](https://user-images.githubusercontent.com/66924945/231984405-84e07205-77fe-4f05-baf2-7b94ad06e4d4.png)
  
**Multifactor Authentication** can be enabled using security defaults or with more granularity via conditional access policies
 - Avoid over-prompting users for MFA to avoid conditioning to always accept
  
**Microsoft recommended MFA policies** based on internal research:
-   If you have Azure AD Premium:
    -   Enable single sign-on (SSO) across applications using managed devices or Seamless SSO.
    -   If reauthorization is required, use a Conditional Access sign-in frequency policy.
    -   For users that sign-in from non-managed devices or mobile device scenarios, persistent browser sessions may not be preferable. Or, you may use Conditional Access to enable persistent browser sessions with sign-in frequency policies. Limit the duration to an appropriate time that's based on the sign-in risk, where a user with less risk has a longer session duration.
-   If you have Microsoft 365 apps licenses or the free Azure AD tier:
    -   Enable single sign-on (SSO) across applications using managed devices or Seamless SSO.
    -   Keep the **Remain signed-in** option enabled and guide your users to accept it.
-   For mobile device scenarios, ensure your users use the Microsoft Authenticator app. This app is used as a broker to other Azure AD federated apps. It reduces the authentication prompts on the device.
  
**Self-Service password reset (SSPR)** 
 - Admins cannot use security questions, must use 2 verification methods
 - Azure AD Premium needed for write-back, needed for synchronised/federated IDs
  
**Azure AD Smart Lockout**
- Locks account for 1 minute after 10 attempts (default)
- Same wrong password entered multiple time does not increment failed attempts
- Admin cannot unlock cloud account smart lockouts, user must use SSPR
  
**Azure Active Directory (Azure AD) Identity Governance**
- **Azure AD entitlement management** - helps manage access to groups, apps and SharePoint Online sites. Approval and access review covered also.  **Access packages** are part of this too.
  
**Access package example:**

![Pasted image 20220906124338](https://user-images.githubusercontent.com/66924945/231984497-ca950de4-dd6b-44c0-b502-81c1481a9945.png)

Within each access package policy, an administrator or access package manager must define the users who are eligible to request access, the approval process, the users who can approve or deny access, and the duration of a user's access assignment, once it's approved.
  
**Conditional Access policies** can be thought of as IF-THEN statements
 - Requires Azure AD Premium licence
  
**Access Reviews**
- Requires P2 licence, included in Microsoft Enterprise Mobility + Security, E5.
  
Azure Active Directory portal provides administrators with access to **three activity logs:**
-   **Sign-in logs**. Provides information about sign-ins and how your resources are used by your users.
-   **Audit logs**. Provides information about changes applied to the company's tenant. For example, users and group management, or updates applied to the tenant’s resources.
-   **Provisioning logs**. Provides a list of activities performed by the provisioning service. For example, the creation of a group in ServiceNow, or a user imported from Workday.

### Manage user authentication

![Pasted image 20220628114229](https://user-images.githubusercontent.com/66924945/231984546-36f96c7a-8429-488c-8ddd-e62a51638a09.png)

All of these authentication methods can be configured in the Azure portal and increasingly using the Microsoft Graph REST API beta.
  
**FIDO2** - The FIDO (Fast IDentity Online) Alliance helps to promote open authentication specifications and reduce the use of passwords as a form of authentication
	FIDO2 security keys are an unphishable specification-based passwordless authentication method that can come in any form factor
**Azure Active Directory** > **Security** > **Authentication methods** > **Authentication method policy**

**Microsoft Entra Authenticator app** - Not seen the "Entra" wording used here...

**Windows Hello**
- Credentials are based on certificate or asymmetrical key pair. Windows Hello credentials can be bound to the device, and the token that is obtained using the credential is also bound to the device
- Keys can be generated in hardware (TPM (Trusted Platform Module) 1.2 or 2.0 for enterprises, and TPM 2.0 for consumers) or software, based on the policy
- PIN entry and biometric gesture both trigger Windows 10 to use the private key to cryptographically sign data that is sent to the identity provider. The identity provider verifies the user's identity and authenticates the user.
  
Domains that include Windows Server 2016 domain controllers use the KeyAdmins group, which is created during the installation of the first Windows Server 2016 domain controller.
Azure Active Directory Connect synchronizes the public key on the user object created during provisioning. You assign write and read permission to this group to the Active Directory attribute. This will ensure the Azure AD Connect service can add and remove keys as part of its normal workflow.

**Microsoft Pluton Security Processor**
	TPM attack techniques target the communication channel between the CPU and TPM, which is typically a bus interface. This bus interface provides the ability to share information between the main CPU and security processor. It also provides an opportunity for attackers to steal or modify information in-transit using a physical attack.
	The Pluton design removes the potential for that communication channel to be attacked by building security directly into the CPU. Windows PCs using the Pluton architecture will first emulate a TPM. This emulation works with the existing TPM specifications and APIs.

**Self Service Password Reset (SSPR)** - P1/2, Microsoft 365 Business Premium
Reset password from https://aka.ms/sspr

**Azure AD Password Protection** - banned password lists
![Pasted image 20220628122624](https://user-images.githubusercontent.com/66924945/231984593-2c10329c-dfa8-4ba0-9982-3de1c923b752.png)

Start with audit mode first - Do a DC Promotion and Demotion during this phase
Cloud only = free, Custom banned passwords and/or on-premises - P1/2

**Kerberos and certificate-based authentication in Azure AD**
Authentication flow:
![Pasted image 20220628123909](https://user-images.githubusercontent.com/66924945/231984630-eab552b4-e6d4-403c-93a6-a63fa28e1082.png)

Azure AD used as a core authentication platform to connect to:
-   Windows Server 2019 Datacenter edition and later.
-   Windows 10 1809 and later.
-   Windows 11.
-   Linux virtual machine.
You can then centrally control and enforce role-based-access and Conditional Access policies that allow or deny access to the VMs.

### Plan, implement, and administer Conditional Access
**Benefits of deploying Conditional Access:**
-  Increase productivity. Only interrupt users with a sign-in condition like MFA when one or more signals warrants it. CA policies allow you to control when users are prompted for MFA, when access is blocked, and when they must use a trusted device.
-   Manage risk. Automating risk assessment with policy conditions means risky sign-ins are at once identified and remediated or blocked. Coupling Conditional Access with Identity Protection, which detects anomalies and suspicious events, allows you to target when access to resources is blocked or gated.
-   Address compliance and governance. CA enables you to audit access to applications, present terms of use for consent, and restrict access based on compliance policies.
-   Manage cost. Moving access policies to Azure AD reduces the reliance on custom or on-premises solutions for CA and their infrastructure costs.
-   Zero trust. Conditional Access helps you move toward a zero-trust environment.
  
**Access tokens** enable clients to securely call protected web APIs, and they're used by web APIs to perform authentication and authorization. Per the OAuth specification, access tokens are opaque strings without a set format. Some identity providers (IDPs) use GUIDs; others use encrypted blobs. The Microsoft identity platform uses a variety of access token formats depending on the configuration of the API that accepts the token.
  
**Best practices**: Emergency access accounts, report-only mode, exclude countries
   
Calls made by service principals are not blocked by Conditional Access.

### Plan and implement privileged access
Home > Privileged Identity Management (Found via search function...)
  
Microsoft recommends you manage all your Global Administrators and Security Administrators using PIM as a first step, because they are the users who can do the most harm when compromised.
  
Microsoft recommends that you manage all roles with guest users using PIM to reduce risk associated with compromised guest user accounts.
  
Microsoft recommends you work with subscription/resource owners of critical services to set up PIM workflow for all roles inside sensitive subscriptions/resources.
  
Microsoft recommends that you manage Owner roles and User Access Administrator roles of all subscriptions/resources using PIM.
  
Microsoft recommends that you bring Azure AD role-assignable groups under management by PIM. After a role-assignable group is brought under management by PIM, it's called a privileged access group. Use PIM to require group owners to activate their Owner role assignment before they can manage group membership.
  
Microsoft recommends you to set up recurring access reviews for users with permanent role assignments.
  
With the **privileged access groups** preview, you can give workload-specific administrators quick access to multiple roles with a single just-in-time request.
	Example: Your *_Tier 0 Office Admins_ might need just-in-time access to the **Exchange Admin**, **Office Apps Admin**, **Teams Admin**, and **Search Admin** roles to thoroughly investigate incidents daily.
  
**When to use emergency accounts**:
- The user accounts are federated, and federation is currently unavailable because of a cell-network break or an identity-provider outage. For example, if the identity provider host in your environment has gone down, users might be unable to sign in when Azure AD redirects to their identity provider.
- The administrators are registered through Azure AD Multi-Factor Authentication. All their individual devices are unavailable or the service is unavailable. Users might be unable to complete multi-factor authentication to activate a role. For example, a cell network outage is preventing them from answering phone calls or receiving text messages. Especially when these authentication-methods are the only two authentication mechanisms that they registered.
- The person with the most recent Global Administrator access has left the organization. Azure AD prevents the last Global Administrator account from being deleted, but it doesn't prevent the account from being deleted or disabled on-premises. Either situation might make the organization unable to recover the account.
- Unforeseen circumstances such as a natural disaster emergency, during which a mobile phone or other networks might be unavailable.

**Create two or more emergency access accounts.** These accounts should be cloud-only accounts that use the .onmicrosoft.com domain and that aren't federated or synchronized from an on-premises environment.

When and admin configures emergency accounts, the following requirements must be met:
- The emergency access accounts shouldn't be associated with any individual user in the organization. Make sure that your accounts aren't connected with any employee-supplied mobile phones, hardware tokens that travel with individual employees, or other employee-specific credentials. This precaution covers instances where an individual employee is unreachable when the credential is needed. Any registered devices need to be kept in known, secure location. These locations need multiple means of communicating with Azure AD.
- The authentication mechanism used for an emergency access account should be distinct. Keep it separate from that used by your other administrative accounts, including other emergency-access accounts. For example, if your normal administrator sign-in is via on-premises MFA, then Azure AD MFA would be a different mechanism. However, if Azure AD MFA is your primary part of authentication for your administrative accounts, then consider a different approach for emergency-accounts. Try things such as using Conditional Access with a third-party MFA provider via Custom controls.
- The device or credential must not expire or be in scope of automated cleanup due to lack of use.
- You should make the Global Administrator role assignment permanent for your emergency access accounts.

**At least one of your emergency access accounts shouldn't have the same multi-factor authentication mechanism as your other non-emergency accounts**
During an emergency, you don't want a policy to potentially block your access to fix an issue. At least one emergency access account should be excluded from all Conditional Access policies.

**Validating accounts**
When you train staff members to use emergency access accounts and validate the emergency access accounts, at minimum do the following steps at regular intervals:
- Ensure that security-monitoring staff is aware that the account-check activity is ongoing.
- Ensure that the emergency break-glass process to use these accounts is documented and current.
- Ensure that administrators and security officers who might need to perform these steps during an emergency are trained on the process.
- Update the account credentials, in particular any passwords, for your emergency access accounts, and then validate that the emergency access accounts can sign in and perform administrative tasks.
- Ensure that users haven't registered multi-factor authentication or self-service password reset (SSPR) to any individual user’s device or personal details.
- If the accounts are registered for multi-factor authentication to a device, for use during sign-in or role activation, ensure that the device is accessible to all administrators who might need to use it during an emergency. Also verify that the device can communicate through at least two network paths that don't share a common failure mode. For example, the device can communicate to the internet through both a facility's wireless network and a cell provider network.

These steps should be performed at regular intervals and for key changes:
- At least every 90 days
- When there has been a recent change in IT staff, such as a job change, a departure, or a new hire
- When the Azure AD subscriptions in the organization have changed

**Eligible roles** assigned in PIM
  
### Plan and implement entitlement management
Entitlement management introduces to Azure AD the concept of an **access package**. An access package is a bundle of all the resources with the access a user needs to work on a project or perform their task.
  
**When to use access packages:**
- Employees need time-limited access for a particular task. For example, you might use group-based licensing and a dynamic group to ensure all employees have an Exchange Online mailbox, and then use access packages for situations in which employees need additional access, such as to read departmental resources from another department.
- Access requires the approval of an employee's manager or other designated individuals.
- Departments wish to manage their own access policies for their resources without IT involvement.
- Two or more organizations are collaborating on a project, and as a result, multiple users from one organization will need to be brought in via Azure AD B2B to access another organization's resources.
  
**Azure AD terms of use policies** - PDF, can tune frequency of prompt/acceptance
- Azure AD > Identity Governance > Terms of use
- Can view number of accepted / declined, history of user
- Users - https://myapps.microsoft.com - Overview > Settings and Privacy

**Connecting organizations** 
- Azure AD > Identity Governance > Connected organizations
- **Sponsors** are internal or external users already in your directory. Sponsors are the point of contact for the relationship with this connected organization.
  
**Access packages** should be used for access that requires the approval of an employee's manager
  

### Manage Azure AD Identity Protection
**Sign-in risk policy** - Analyzes probability that sign in is by the user
**User risk policy** - Detects atypical behavioural events of the user
  
If your organization wants to allow users to self-remediate when risks are detected, users must be registered for **both self-service password reset and Azure AD Multi-Factor Authentication.**
  
Microsoft's recommendation is to set the user risk policy threshold to **High** and the sign-in risk policy to **Medium and above**.
**User risk policy** - Recommendation is to Allow access and Require password change.
All reports support .csv file export, sign-in 2500 entries, risk detection 5000
- Azure Portal > Azure Active Directory > Security > Report section
- Can import to **Microsoft Graph** (APIs - riskDetection, riskyUsers, signIn)
  
**Workload identity protection (P2)** - Service Principle / Application
These identities have a higher risk of compromise because:
- No MFA, no formal lifecycle process, creds/secrets need to be stored somewhere
- Use **Conditional Access for workload identities**

**Microsoft Defender for Identity** - Formerly Azure ATP
![Pasted image 20220628134935](https://user-images.githubusercontent.com/66924945/231984719-28e25f8a-80b6-4a4e-934d-056bfee1e9eb.png)

**Security Operator** role can Confirm safe sign-in


## Implement and manage threat protection

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

### Detect and respond to security issues using Microsoft Defender for Endpoint

**Alerts Queue** - list of notifications about potential threats detected on endpoints
**Incidents Queue** - list of correlated alerts and associated data collections
**Manage Alerts & Incidents** - Tag, name, assign, resolve, classify and comment
**Investigate incidents** - Includes alerts, devices, users, investigations, evidence
- Individual alerts within incidents can be investigated separately

**Take response actions** - on devices and files
**Live Response** - Uses a remote shell connection to access devices
 - Run scripts to investigate
 - Download files, samples etc
 - Upload executables and scripts

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

### Protect against malicious attacks and unauthorized access with Microsoft Edge
Microsoft Edge **isolates processes** to maintain a secure browsing environment
**Microsoft Defender SmartScreen** - Blocks malicious URLs and files
**Microsoft Defender Application Guard** - Untrusted sites opened in Hyper-V sandbox
Can be managed with **Microsoft Endpoint Manager (MEM)** admin center
 - Baselines similar to group policies


### Reduce potential attack areas with Microsoft Defender for Endpoint
- **Hardware-based isolation for Microsoft Edge** - Hyper-V container
- **Application control** - Apps run under user context
- **Web Protection** - Threat protection and content filtering
- **Network protection** - Prevents users and apps from accessing malicious addresses
- **Controlled folder access** - Allows access to folder only for specified apps
- **Exploit protection** - Blocks common exploits
- **Reputational Analysis** - File and website based scoring
- **Attack surface reduction rules** - Protects against launching scripts, behavioural analysis

### Understand Microsoft 365 encryption
**Bitlocker:**
 - Encrypts data at the volume level
 - Uses AES 256 bit
 - TPM > Volume Master Key (VMK) > Full Volume Encryption Key (FYEK) > Cleartext
 - (Optional) Recovery keys stored in Microsoft Datacenter

**Application layer encryption** 
 
- **Microsoft Managed Keys** - Default service encryption

![managed-key-hierarchy](https://user-images.githubusercontent.com/66924945/231985072-afff3427-c61f-4bfd-a3b6-b67a9f0c5312.png)
  
- **Customer Managed Keys** - Allows use of own root keys, managed by Key Vault
  
![customer-key-hierarchy](https://user-images.githubusercontent.com/66924945/231985360-a45e38a5-4f95-43f2-b705-808acadcc2b7.png)

-   Providing rights protection and management features on top of strong encryption protection.
-   Enhancing the ability of Microsoft 365 to meet the demands of customers with compliance requirements regarding encryption.
-   Data recovery available with **Availability Keys** if root keys are lost/unavailable

Microsoft owns and manages its own certificate authority to manage the certificates used for TLS encryption alongside third-party solutions. The public certificates are issued by Microsoft using SSLAdmin, an internal Microsoft tool to protect confidentiality of transmitted information.

### Understand app management using Microsoft Endpoint Manager
**App management lifecycle:** Add > Deploy > Configure > Protect > Retire

Use **App configuration policies** to preconfigure apps and provide consistency

**App protection policies** can:
 - Isolate data - separate personal and company data
 - Secure access on personal devices - restrict action such as copy and paste
 - Create and deploy on devices

**Protected apps** have app protection polices built in

**Levels of app protection:**
- **Enterprise basic data protection** (Level 1) - PIN protection, encrypted, wiping
- **Enterprise enhanced data protection** (Level 2, School/Work) - DLP 
- **Enterprise high data protection** (Level 3, High Risk) - Threat Defence

### Manage device compliance
If an organization's devices are managed by **Intune**, it can use device compliance policies to define how devices should be configured.

Non-compliant actions are: 
 - **Notifying users via email** - Can be customized, includes details
 - **Marking device noncompliant** - A grace period can be specified

Two parts to compliance policies in Intune:
- **Compliance policy settings** - Baseline tenant-wide settings
- **Device compliance policy** - More granular rules applied to users and devices

**Intune Device compliance dashboard** - monitor results of compliance policies
 - Granular details in compliance charts

**How Intune resolves policy conflicts:**
- If the conflict is between settings from an Intune configuration policy and a compliance policy, the **settings in the compliance policy take precedence** over the settings in the Intune configuration policy. This result happens even if the settings in the Intune configuration policy are more secure.
- If an organization deployed multiple compliance policies, **Intune uses the most secure of these policies.**

**Device categories**
- Access the Microsoft Endpoint Manager admin center at https://endpoint.microsoft.com 
- From Devices > Devices catagories click on Create device category

**Conditional access** can be applied to devices, templates available

**Monitoring** provided by Microsoft Endpoint Manager & Intune

### Remediate risks with Microsoft Defender for Office 365
**Automated Investigation and Response (AIR) workflow:**
1. Alert triggered, security playbook initiates
2. Depending on alert, automated investigation begins, manual optional
3. If more alerts triggered, the scope of automatic investigation increases
4. Details and results available throughout, also via API - Playbook log available
5. Remediation based on results and recommendations need approval from security operations team

![Pasted image 20220908132847](https://user-images.githubusercontent.com/66924945/231985451-eab83d72-5c4d-4a88-bbdc-b9739339fbc1.png)

**Microsoft Defender for Office 365 Safe Attachments** - Scans email for malware using Microsoft servers

**Microsoft Defender for Office 365 Safe Links** Blocks malicious URLs

**Microsoft Defender for Office 365 anti-phishing** - Checks domain for legitamacy

**Simulating attacks:**
- **Threat trackers** - provides the latest intelligence on prevailing cybersecurity issues.
- **Threat Explorer** - Real-time report to identify and analyze recent threats
- **Attack Simulator** - Can run realistic attack scenarios to identify vulnerabilities

**Microsoft Defender for Office 365 is a cloud-based email filtering service that helps protect your organization. No agents are deployed.**

### Query, visualize, and monitor data in Microsoft Sentinel
**Microsoft Sentinel Workbooks** provide interactive reports that help you visualize important signals by combining text, table, charts, and tiles.

Sentinel logs are stored in a **Log Analytics Workspace**

**A new Microsoft Sentinel alert creates an analytics rule**

**Kusto Query Language (KQL)** is used in Sentinel to search and filter data
 - | character separates commands i.e Event | search error
**Microsoft Sentinel repository** available on Github

**Azure Data Explorer, which is also known as Kusto, is a log analytics cloud platform optimized for ad-hoc big data queries.**

Sentinel uses **Markdown** for text visualizations


## Implement and manage information protection
### Create and manage sensitive information types
The special features of **custom sensitive information types** include:
-   **Exact Data Match (EDM)-based classification** - enables you to create custom sensitive information types that refer to exact values in a database of sensitive information. The database can be refreshed daily and contain up to 100 million rows of data.
-   **Document Fingerprinting** - identifies standard forms that are used throughout your organization via patterns.  Forms and templates are most effective.
-   **Keyword dictionaries** - Large lists of words subject to change

**Confidence level** component uses more evidence to reduce false positives


### Apply and manage sensitivity labels
Containers where labels can be published include:
-   Microsoft 365 Groups
-   Microsoft Teams
-   Yammer Communities
-   SharePoint Sites
  
Manage sensitivity labels from: [https://admin.microsoft.com/](https://admin.microsoft.com/).
  
The **Unified Labeling Scanner** enables you to label on-premises files.
- Install and config via **AIPService Powershell module**

Users can apply just **one label at a time** for each document or email.

Encryption of a file and access restrictions are connected. **Without encryption it is not possible to restrict access.**

### Prevent data loss in Microsoft Purview
**Microsoft Purview Data Loss Prevention helps prevent users from accidentally, rather than intentionally sharing sensitive content.** (If a user is determined enough to send sensitive data outside the organization, they will find another way to do so.)

Use **Microsoft 365 data classification** to view information to be protected

![Pasted image 20220913135430](https://user-images.githubusercontent.com/66924945/231985650-cdd308b3-cdab-4a09-8c00-0b7781846c27.png)


**Endpoint data loss prevention** (Endpoint DLP) extends the activity monitoring and protection capabilities of DLP to sensitive items on Windows devices.

The DLP-specific reports available in the **Microsoft Purview compliance portal** include:
-   DLP policy matches
-   DLP incidents
-   DLP false positives and overrides
-   Third-party DLP policy matched
  
Navigate to **Microsoft Purview compliance portal > Reports** to view the reports.
  
### Manage data loss prevention policies and reports in Microsoft 365
DLP policies and rules contained within those policies **are processed in a specific order**. This process is called **policy precedence**. You can manually configure the order in which this rule will be selected for evaluation. **The rules of DLP policy with the lowest order/priority number are processed first.**
- Priority starts from 0
- **DLP Compliance Management role** needed to change order
  
The **Microsoft Purview compliance portal** provides the following DLP reports:
-   DLP Policy Matches - Count of DLP policy matches by rule over time
-   DLP Incidents - Count of DLP policy matches by item over time
-   DLP false positive overrides - Count of user overrides and false positives
  
The **DLP alert management dashboard** in the Microsoft Purview compliance portal can be used to show alerts of the following workloads:
-   Exchange
-   SharePoint
-   OneDrive
-   Teams
-   Devices

Can also view a report for DLP alerts in the **Defender for Cloud Apps Dashboard**.
  
Roles needed to view DLP reports in the Microsoft Purview compliance portal:
 - **Security Reader (Exchange)** 
 - **View-Only DLP Compliance Management** - Base role for read only access


### Manage the data lifecycle in Microsoft Purview

![Pasted image 20220913154546](https://user-images.githubusercontent.com/66924945/231985717-f7af0c0b-0e48-44a4-a947-8c12868dac4f.png)


**Microsoft Purview compliance portal > Data Lifecycle Management > Retention** to configure retention policies.
  
**Creating a retention policy** consists of these steps:
1.  Name your policy
2.  Settings
3.  Choose locations
4.  Review your settings
  
**Creating a retention label** consists of these steps:
1.  Name your label
2.  Label settings
3.  Review your settings
  
**Microsoft Purview compliance portal > Data Lifecycle Management > Label policies > Publish labels** to publish labels for manual application.
  
**Creating a retention label policy to publish labels for manual application** consists of these steps:
1.  Choose labels to publish
2.  Publish to users and groups
3.  Name your policy
4.  Review your settings
  
Navigate to **Microsoft Purview compliance portal > Data Lifecycle Management > Label policies > Auto-apply a label** to auto-apply retention labels.
  
Creating an **auto-apply retention label policy** consists of these steps:
1.  Choose label to auto-apply
2.  Choose conditions
3.  Settings (only valid for sensitive info condition)
4.  Name your policy
5.  Locations
6.  Review your settings
  
**Import service** to bulk-import PST files to Exchange Online mailboxes
 - **Network Upload** - Upload to temp Azure Storage location then import
 - **Drive Shipping** - Copy files to BitLocker encrypted drive then ship to Microsoft
  
**The retention period on content in Teams conversations will be based on when messages or conversations were sent or received.**

### Manage data retention in Microsoft 365 workloads
The following image shows **the principal of hidden folders in a mailbox** and describes an example process from the delivery of a message until its final purge from the mailbox by the Managed Folder Assistant (MFA).
![Pasted image 20220913163523](https://user-images.githubusercontent.com/66924945/231985781-1374d764-c9a4-4598-9e0a-b736cb34e372.png)

  
Overview of roles and permissions:

<img width="725" alt="Pasted image 20220913164823" src="https://user-images.githubusercontent.com/66924945/231985923-7f2c0cb9-5e55-4d07-b143-9a251d05a151.png">

To apply retention in SharePoint Online and OneDrive, dedicated libraries for items and versions to hold called **Preservation Hold libraries** are used.

**Versioning retention settings:**
-   **If the retention period is based on when the content was created**, each version has the same expiration date as the original document. The original document and its versions all expire at the same time.
-   **If the retention period is based on when the content was last modified**, each version has its own expiration date based on when the original document was modified to create that version. The original document and its versions expire independently of each other.

Retention Tags and Retention Policies in Exchange Server and Exchange Online are a part of **Messaging records management (MRM)**, which have formerly been used to manage the lifecycle of email messages stored in mailboxes. This functionality is now replaced by **Retention Labels and Retention Policies** in Microsoft 365. Messaging records management (MRM) is still being used for archiving purposes, which move messages between the primary mailbox and the archive mailbox of users and inside the various mailbox folders.
  
There are two different types of mailbox holds in Exchange Online:
-   **Litigation Hold**: Set on a mailbox level and prevents all content within a mailbox from being deleted.
-   **eDiscovery Hold**: Created in an eDiscovery case to prevent only mailbox content that matches the search criteria from being changed or deleted.
  
Recovering content in Exchange Online that is stored in the folder structure of mailboxes, can be done via **compliance searches** and **eDiscovery cases**.

All messages of a single Exchange mailbox can be retained via **litigation hold**

### Manage records in Microsoft Purview
A **file plan** specifies how your records are organized and their retention schedule.
  
An item **declared as a record** becomes immutable and cannot be modified (except for the name and metadata in SharePoint Online and OneDrive), or deleted until after the retention period.
 - Record versioning in SharePoint Online and OneDrive lets you work on a document even after it has been declared as a record.
  
**Microsoft Purview compliance portal > Records management > File plan > Import** to import a file plan (CSV File).
The process consists of the following steps:
1.  Download the file plan template.
2.  Fill out the file plan.
3.  Import the file plan.
  
**Microsoft Purview compliance portal > Records management > File plan** to configure retention labels for records management
The process of creating a retention label consists of these steps:
1.  Name your label.
2.  Add file plan descriptors.
3.  Configure label setting.
4.  Review settings and create the label.
  
Use **event-based retention** when you want the retention period to be based on when a specific type of event occurs, rather than when the content was created, last modified or labeled.
Here is the flow to configure event-driven retention:
1.  Create retention label with event-based retention period.
2.  Publish or auto-apply label.
3.  Create an event.

The **Overview, Content explorer** and **Activity explorer** in **Data classification** provide information before any decision on what retention policies, retention labels, and retention label policies to create.
 - Go to [Microsoft Purview compliance portal](https://compliance.microsoft.com/) and select **Data classification** to view the classification results.



## Manage Governance and Compliance Features in Microsoft 365
### Manage compliance in Microsoft 365 and Exchange Online
**Types of retention tags in Exchange Online**:
- **Default Policy Tag (DPT)** - Applied automatically to entire mailbox
- **Retention policy tag (RPT)** - Applied automatically to default folders (Inbox)
- **Personal tag** - Applied manually to items and folders, automate via inbox rules
  
 With a **data loss prevention (DLP) policy** in the Microsoft 365 Defender portal, you can identify, monitor, and automatically protect sensitive information.
  
Use **Policy Tips** to alert users that they might be violating the business practices or regulations that you're enforcing with DLP policies.
  
By default, **mailbox auditing** is on by default for user mailboxes, shared mailboxes, and Microsoft 365 Group mailboxes. It's not automatically on for resource and public folder mailboxes.
 - Verify with `Get-OrganizationConfig | Format-List AuditDisabled`

**Journaling** is the ability to record all communications, including email communications, in an organization for use in the organization's email retention or archival strategy.
  
To enable or disable a **journal rule**:
1.  In the EAC, go to **Compliance management > Journal rules**. You'll see a list of the journal rules.
2.  To enable a rule, select the check box in the **On** column next to the rule's name.
3.  To disable a rule, clear the check box.

Use **Content Search** to search for items in these services:
-   Exchange Online mailboxes and public folders
-   SharePoint Online sites and OneDrive for Business accounts
-   Skype for Business conversations
-   Microsoft Teams
-   Microsoft 365 Groups
-   Yammer Groups
Access content search via the portal at [https://compliance.microsoft.com/](https://compliance.microsoft.com/),


### Manage Microsoft Purview eDiscovery (Premium)
Main features of **eDiscovery Premium**:
-   manage eDiscovery workflows by identifying persons of interest and their data sources.
-   apply holds to preserve data.
-   manage the legal hold communication process.

**Machine learning capabilities** used:
-   deep indexing
-   email threading
-   near duplicate detection

Workflow of eDiscovery Premium aligns with the EDRM eDiscovery process:
![Pasted image 20220914140329](https://user-images.githubusercontent.com/66924945/231986030-7746a05c-133a-40e5-8496-9c8e1bcbac2b.png)


**After an organization identifies potential persons of interest in an investigation, it can add them as custodians to an eDiscovery (Premium) case.**
  
**Steps to set up eDiscovery Premium:**
1. Verify and assign licenses
2. Assign eDiscovery Permissions
3. Configure global settings

![Pasted image 20220914140927](https://user-images.githubusercontent.com/66924945/231986087-0f50a11d-6e2e-4751-bf79-9bb324cfa6ac.png)


**Adding and managing custodians in eDiscovery:**
1. Identify the custodians.
2. Choose custodian data locations.
3. Configure hold settings.
4. Review the custodians and complete the process.
  
**Tools to analyze collected documents:**
-   Near duplicate detection
-   Email threading
-   Themes

Once you've configured and verified that a search returns the expected data, the next step is to add the search results to a **review set**.

Once all documents have been compared and grouped, a document from each group is marked as the **pivot**. When reviewing your documents, you can review a pivot first and review the other documents in the same near duplicate set. This process enables you to focus on the difference between the pivot and the document that's in review.

### Explore Microsoft Purview Compliance Manager
The **Compliance Manager dashboard** shows current compliance posture + score.
-   Overall compliance score
-   Key Improvement actions
-   Compliance score breakdown - Assessments and Categories sections
-   Solutions that affect your score

**Assessments** combine actions Microsoft takes on your behalf with actions you take to protect your data and achieve compliance.

The **assessment templates page** displays a list of templates and key details.
-   Microsoft-provided assessment templates
-   Microsoft-provided assessment templates you have extended
-   Custom assessment templates you have created and imported

### Manage regulatory and privacy requirements with Microsoft Priva
**Privacy Risk Management policies** can help you address risk scenarios that are important to your organization.

Privacy risk management has **three policy templates**:
 - **Data Overexposure** - Identifies items containing personal data with too much access
 - **Data Transfers** - Detects personal data transfers over defined boundaries
 - **Data minimisation** - Detects longstanding unused personal data

Within the Privacy Risk Management solution, admins can review **alerts** about content that matches your policy conditions. Reviewing alerts allows you to identify cases that need follow-up. You can do this by creating **issues**.

Two ways to create a subject rights request:
 - From a **template**
 - A **custom** option - a guided process 

Three different types of request:
 - **Access** - Summary of the subjects personal information held
 - **Export** - Summary and exported file of above
 - **Tagged list for follow up** - Generates a summary of tagged files during review

Request shown on **Data estimate summary** card on the request's **Overview** page

After you select **Complete review** in the **Review data** stage of the subject rights request, the final reports for the request will start generating automatically. On the **Reports** tab of the subject rights requests details page, the **Status** column indicates when report generation is **In progress** and when a report is **Ready to download**. It can take up to 30 minutes to finish creating the reports.  

Two (self-explanatory)sections for reports:
- **Reports for the data subject**
- **Reports for internal use**


### Prepare Microsoft Purview Communication Compliance
Note: These features will **totally** not be used by companies for malicious reasons

**Communication compliance** monitors outbound and inbound communication across Exchange email, Microsoft Teams chats and channels (including attachments), Skype for Business conversations and third-party platform communications such as Bloomberg, Facebook, and Twitter.

 **Machine learning support** - Built-in (and custom) threat, harassment, and profanity classifiers
 
-  **Conversation threading**: Messages are visually grouped by original message and all associated reply messages that provide better context during investigation and remediation actions.
-   **Keyword highlighting**: Terms matching policy conditions are highlighted in the message text view to help reviewers quickly locate and remediate policy alerts.
-   **Exact and near duplicate detection**: In addition to scanning for exact terms matching communication compliance policies, near duplicate detection groups textually similar terms and messages together to help speed up the review process.
-   **New filters**: Message filters for fields including sender, recipient, date, domains, and many more, enable faster investigation and remediation of policy alerts.
-   **Improved message views**: New message source, text, and annotation views enable quicker investigation and remediation actions. Message attachments are also viewable to provide complete context when taking remediation actions.
-   **User history view**: Historical view of all user message remediation activities, such as past notifications and escalations for policy matches, now provides reviewers with more context during the remediation workflow process. First-time or repeat instances of policy matches for users are now archived and viewable.
  
**Workflow for identifying and resolving compliance issues**:
-   Configure communication compliance policies.
-   Investigate issues detected as matching your communication compliance policies.
-   Remediate the compliance issues you've investigated.
-   Monitor to continually evaluate and improve your compliance posture.
  
  
### Manage insider risk in Microsoft Purview
The insider risk management solution in **Microsoft Purview** leverages the Microsoft Graph, security services and connectors to human resources (HR) systems like SAP, to obtain real-time native signals such as file activity, communications sentiment, abnormal user behaviors, and resignation date. A set of configurable policy templates tailored specifically for risks – such as digital IP theft, confidentiality breach, and HR violations – use machine learning and intelligence to correlate these signals to identify hidden patterns and risks that traditional or manual methods might miss. These built-in policy templates allow you to identify and mitigate risky activities while balancing employee privacy versus organization risk with privacy-by-design architecture. Finally, end-to-end integrated workflows ensure that the right people across security, HR, legal, and compliance are involved to quickly investigate and take action once a risk has been identified.
  
**Insider risk management policies** are created using pre-defined templates and policy conditions.
  
Insider risk management uses **audit logs** for user insights and activities configured in policies.

Alerts can be assigned to a case so that you can conduct a detailed investigation from the **Cases** section in the insider risk management console.
  
### Plan information barriers
**Microsoft Purview Information Barriers** are policies that a compliance administrator or information barriers administrator can configure to prevent individuals or groups from communicating with each other.
  
Blocks the following cross-department functionality in Teams:
-   Searching for a user
-   Adding a member to a team
-   Starting a chat session with someone
-   Starting a group chat
-   Inviting someone to join a meeting
-   Sharing a screen
-   Placing a call
  
Can be managed with PowerShell, sample commands:
`New-OrganizationSegment -Name "Manufacturing" -UserGroupFilter "Department -eq 'Manufacturing'"`
  
`New-InformationBarrierPolicy -Name "Manufacturing-HRMarketing" -AssignedSegment "Manufacturing" -SegmentsAllowed "Manufacturing","HR","Marketing" -State Inactive`
  
**Information barriers are based on address book policies, but the two kinds of policies are not compatible.**

### Implement privileged access management
**Privileged access management** allows granular access control over privileged admin tasks in Microsoft Purview, specifically in Exchange Online.

**Layers of protection in Microsoft 365**

![Pasted image 20220915162410](https://user-images.githubusercontent.com/66924945/231986354-b8355355-4e70-485b-a8b0-76156704b9be.png)


Microsoft Purview Privileged Access Management is defined and scoped at the _task_ level, while Azure AD Privileged Identity Management applies protection at the _role_ level with the ability to execute multiple tasks.

**Steps to Implement privileged access:**
1. Create an approvers group
2. Enable privileged access from **Settings** > **Settings** > **Security & Privacy** > **Privileged access** in the Microsoft 365 Admin Center
3. Create an access policy from **Manage access policies and requests** in above section
4. Now you can submit and approve requests

### Manage Customer Lockbox
**Customer Lockbox** ensures that Microsoft cannot access an organization's data in the cloud to perform a service operation without your explicit approval.

![Pasted image 20220915162915](https://user-images.githubusercontent.com/66924945/231986429-7e304f38-e84d-4edf-9e59-dc70446d8c7c.png)


Feature is turned on from **Settings > Security & privacy** in Microsoft 365 Admin Center

Approve or deny requests from **Support > Customer Lockbox Requests**

**Customer Lockbox requests have a default duration of 12 hours.**

<!-- Author: Stuart Mackay -->
