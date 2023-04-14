# SC-300 Microsoft Identity and Access Administrator - Study Notes

**Author:** Stuart Mackay
<!-- Author: Stuart Mackay -->

## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://learn.microsoft.com/en-us/certifications/resources/study-guides/sc-300)
- [Official Microsoft Learning Path](https://docs.microsoft.com/en-us/certifications/exams/sc-300)
- [SC-300 Labs](https://microsoftlearning.github.io/SC-300-Identity-and-Access-Administrator/)
- [John Savill SC-300 Study Playlist (Youtube)](https://www.youtube.com/watch?v=LGpgqRVG65g&list=PLlVtbbG169nGj4rfaMUQiKiBZNDlxoo0y)
- [John Savill SC-300 Study Cram (Youtube)](https://www.youtube.com/watch?v=LGpgqRVG65g)


## Notes from Microsoft Learn & Microsoft Docs:



## Implement an identity management solution

### Implement initial configuration of Azure Active Directory
**Company Branding** - From Manage Menu in Azure Portal. P1+

**Roles**: Global Administrator, User Administrator, Billing Administrator (Purchases)

**Azure roles vs Azure AD Roles** - These are seperate

![Pasted image 20220627120814](https://user-images.githubusercontent.com/66924945/232015430-924db8ee-21ac-449f-8267-a8c05eb16f6d.png)


**Assigning roles via PIM** - Available to P2 licenses
**Custom Roles** - Azure AD > Roles and administrators > New Custom Role
By default in Azure AD, all users can register application registrations and manage all aspects of applications they create.
The most-privileged application administrator roles are:
-   The **Application Administrator** role, which grants the ability to manage all applications in the directory, including registrations, single sign-on settings, user and group assignments and licensing, Application Proxy settings, and consent. It doesn't grant the ability to manage Conditional Access.
-   The **Cloud Application Administrator** role, which grants all the abilities of the Application Administrator, except it doesn't grant access to Application Proxy settings (because it has no on-premises permission).
- **Default User Permissions** - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions
- **Custom Domain Names** - Up to 900, 450 in each organization if federated/on-prem
- **ForceDelete** of domain name, only when fewer than 1000 references, no Exchange
Guest users can't enumerate the list of all users, groups, and other directory objects.
- **Security Defaults** - MFA, no legacy auth, protect privileged activities (Portal)

### Create, configure, and manage identities
3 user types: Cloud Identities, Directory-synchronized identities, Guest users
**Permanently delete users** - Global/User administrator or Partner Tier1/2 Support
2 group types: **Security Groups** and **Microsoft 365 groups** (Distribution groups)
	Membership type: Assigned and Dynamic
	
**Azure AD registered devices** - Provide support for BYOD/Mobile scenarios
	Registered to Azure AD without requiring organizational account to sign in to the device
**Azure AD Join** - Intended for cloud-first/cloud-only orgs. Can access on-prem.

**Hybrid Azure AD Joined** - Joined to on-prem and registered with Azure AD

**Device Writeback** - Azure AD "Registered Devices" container in AD
	Windows Hello For Business (WHFB) requires device writeback to in Hybrid- Federated scenarios.
	
**Group-based licensing** now possible, license applied automatically on join (P1/E3)
	User location must be defined for this to work
	
**License conflicts** - Need to be resolved by the administrator, business logic

**System for Cross-Domain Identity Management - SCIM** 
	Automates removing user from Azure AD when removed from HR systems

### Implement and manage external identities

![Pasted image 20220627133403](https://user-images.githubusercontent.com/66924945/232015484-54043ff0-fca6-4f9b-90bc-25da0113d731.png)


B2B users can be added as members instead of guests via the API (partner org)
Microsoft 365 can invite guest users for collaboration - shown as external
After you set up direct federation with an organization, any new guest users you invite will be authenticated using direct federation.

**Microsoft Entra verified ID** - uses a Digital ID issuer and subject to identify claims

### Implement and manage hybrid identity
**Azure AD Connect** - Replaces DirSync and Azure AD Sync

**Cloud Authentication**
- **Azure AD password hash synchronization (PHS)** - Simplest, same on-prem creds
- **Azure AD pass-through authentication (PTA)** - Software agent on prem servers
You can use password hash synchronization as a backup authentication method for pass-through authentication when the agents can't validate a user's credentials due to a significant on-premises failure. Fail over to password hash synchronization doesn't happen automatically and you must use Azure AD Connect to switch the sign-in method manually.

**Federated Authentication** - Auth handled by ADFS, smartcard, 3rd party MFA

**Architecture diagrams available for all scenarios**

**sourceAnchor** - Unique Identifier for object which is on prem and in Azure
Some organizations have non-routable domains, like contoso.local, or simple single label domains like contoso. You're not able to verify a non-routable domain in Azure AD. Azure AD Connect can sync to only a verified domain in Azure AD. When you create an Azure AD directory, it creates a routable domain that becomes default domain for your Azure AD

![Pasted image 20220627152234](https://user-images.githubusercontent.com/66924945/232015588-3535c273-82e8-44f6-b025-75792fc020bb.png)


**Azure Active Directory cloud sync**
Azure AD Connect cloud sync is designed to accomplish hybrid identity goals for synchronization of users, groups and contacts to Azure AD. The synchronization is accomplished by using the **Azure AD cloud provisioning agent** instead of the Azure AD Connect application. It can be used alongside Azure AD Connect sync

**Password hash synchronization (PHS)**

![Pasted image 20220627152500](https://user-images.githubusercontent.com/66924945/232015640-e99907ee-da3d-4992-a617-fc9b9e0e9ecd.png)


Azure AD Connect synchronizes a hash, of the hash, of a user's password from an on-premises Active Directory instance to a cloud-based Azure AD instance.
The password hash synchronization process runs every 2 minutes.

**Pass-through authentication and Seamless Single Sign-On(SSO)**
Azure AD now talks Kerberos
Using PTA allows passwords and authentication to stay on prem 
Install agent on same server as AD Connect - these agents auto-update

Use **Azure AD Connect wizard** to repair trust, federate using alternate login ID, add an ADFS Web Application Proxy server.
**Device writeback** is used to enable device-based conditional Access for ADFS-protected devices.

**Azure Active Directory Connect Health** provides robust monitoring of on-prem identity infrastructure.  Info in **Azure AD Connect Health portal** - P1 Required


## Implement an Authentication and Access Management solution

### Secure Azure Active Directory users with Multi-Factor Authentication
- **Something you know** - Password/Security question
- **Something you have** - Mobile app / security token / badge
- **Something you are** - face/finger - biometric

Can be set up from Azure Portal > Azure AD > Security > MFA (needs premium license)
Can skip MFA from trusted IPs...
1-60 days remembering MFA on device (optional)

**OATH software tokens** - Microsoft Authenticator app is an example

**Monitoring adoption**
![Pasted image 20220628113752](https://user-images.githubusercontent.com/66924945/232015709-08213109-c871-4672-a352-7f68934f5cae.png)


### Manage user authentication
![Pasted image 20220628114229](https://user-images.githubusercontent.com/66924945/232015750-76c4c6af-3dbe-465d-a199-387778ec5aef.png)


All of these authentication methods can be configured in the Azure portal and increasingly using the Microsoft Graph REST API beta.

In Azure AD, a password is often one of the primary authentication methods. You can't disable the password authentication method. If you use a password as the primary authentication factor, increase the security of sign-in events using Azure AD Multi-Factor Authentication.

**FIDO2** - The FIDO (Fast IDentity Online) Alliance helps to promote open authentication specifications and reduce the use of passwords as a form of authentication
	FIDO2 security keys are an unphishable specification-based passwordless authentication method that can come in any form factor
**Azure Active Directory** - **Security** - **Authentication methods** - **Authentication method policy**

**Microsoft _Entra_ Authenticator app** 

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
![Pasted image 20220628122624](https://user-images.githubusercontent.com/66924945/232015807-6f8a9845-209b-410e-a297-d756c433289c.png)


Start with audit mode first - Do a DC Promotion and Demotion during this phase
Cloud only = free, Custom banned passwords and/or on-premises - P1/2

**Smart Lockout** - blocks sign-in attempts for 1 min after 10 failed attempts
	Always on, for all Azure AD customers

**Kerberos and certificate-based authentication in Azure AD**
Authentication flow:
![Pasted image 20220628123909](https://user-images.githubusercontent.com/66924945/232015828-c0b97228-8b65-4bc8-86b2-e4f55f04f8f4.png)


You can now use Azure AD as a core authentication platform to connect to:
-   Windows Server 2019 Datacenter edition and later.
-   Windows 10 1809 and later.
-   Windows 11.
-   Linux virtual machine.
You can then centrally control and enforce role-based-access and Conditional Access policies that allow or deny access to the VMs.

### Plan, implement, and administer Conditional Access (P2)

**Benefits of deploying Conditional Access:**
-  Increase productivity. Only interrupt users with a sign-in condition like MFA when one or more signals warrants it. CA policies allow you to control when users are prompted for MFA, when access is blocked, and when they must use a trusted device.
-   Manage risk. Automating risk assessment with policy conditions means risky sign-ins are at once identified and remediated or blocked. Coupling Conditional Access with Identity Protection, which detects anomalies and suspicious events, allows you to target when access to resources is blocked or gated.
-   Address compliance and governance. CA enables you to audit access to applications, present terms of use for consent, and restrict access based on compliance policies.
-   Manage cost. Moving access policies to Azure AD reduces the reliance on custom or on-premises solutions for CA and their infrastructure costs.
-   Zero trust. Conditional Access helps you move toward a zero-trust environment.

**Access tokens**:
	Access tokens enable clients to securely call protected web APIs, and they're used by web APIs to perform authentication and authorization. Per the OAuth specification, access tokens are opaque strings without a set format. Some identity providers (IDPs) use GUIDs; others use encrypted blobs. The Microsoft identity platform uses a variety of access token formats depending on the configuration of the API that accepts the token.

**Best practices**: Emergency access accounts, report-only mode, exclude countries

Calls made by service principals are not blocked by Conditional Access.

### Manage Azure AD Identity Protection (P2)
**Sign-in risk policy** - Analyzes probability that sign in is by the user

**User risk policy** - Detects atypical behavioural events of the user

If your organization wants to allow users to self-remediate when risks are detected, users must be registered for both self-service password reset and Azure AD Multi-Factor Authentication.

Microsoft's recommendation is to set the user risk policy threshold to **High** and the sign-in risk policy to **Medium and above**.
**User risk policy** - Recommendation is to Allow access and Require password change.
All reports support .csv file export, sign-in 2500 entries, risk detection 5000
	Azure Portal > Azure Active Directory > Security > Report section
	Can import to **Microsoft Graph** (APIs - riskDetection, riskyUsers, signIn)

**Workload identity protection (P2)** - Service Principle / Application
These identities have a higher risk of compromise because:
	No MFA, no formal lifecycle process, creds/secrets need to be stored somewhere
	Use **Conditional Access for workload identities**

**Microsoft Defender for Identity** - Formerly Azure ATP

![Pasted image 20220628134935](https://user-images.githubusercontent.com/66924945/232015905-b74e12ab-2fa8-4862-90b1-5522de97c77e.png)


**Security Operator** role can Confirm safe sign-in

## Implement Access Management for Apps
### Plan and design the integration of enterprise apps for SSO
**CASB - Cloud Access Security Broker**

**MDCA  - Microsoft Defender for Cloud Apps**
	Supports log collection, API connectors and reverse proxy

![Pasted image 20220628152053](https://user-images.githubusercontent.com/66924945/232016092-147ebd88-093b-4781-bda3-461a60897ad0.png)



**Cloud Discovery** - uses your traffic logs to dynamically discover and analyze the cloud apps your organization is using

**Cloud Discovery Dashboard** 

**Cloud App Catalog** - Used to sanction or unsanction apps in organization

**AD FS** - Provides SSO to cloud applications 

**Cloud Application Administrator** role have the same permissions as the Application Administrator role, excluding the ability to manage application proxy.

### Implement and monitor the integration of enterprise apps for SSO
While optional claims are supported in both v1.0 and v2.0 format tokens, and SAML tokens, they provide most of their value when moving from v1.0 to v2.0. One of the goals of the Microsoft identity platform is smaller token sizes to ensure optimal performance by clients. As a result, several claims formerly included in the access and ID tokens are no longer present in v2.0 tokens and must be asked for specifically on a per-application basis.

Before an application can access the organization's data, a user must grant the application permissions to do so.
To reduce the risk of malicious applications attempting to trick users into granting them access to your organization's data, it is recommended that you allow user consent only for applications that have been published by a [verified publisher](https://docs.microsoft.com/en-us/azure/active-directory/develop/publisher-verification-overview).
[Enable the admin consent workflow](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-admin-consent-workflow) to allow users to request an administrator's review and approval of an application that the user isn't allowed to consent to—for example, when user consent has been disabled or when an application is requesting permissions that the user isn't allowed to grant.

**Azure Active Directory application proxy**

![Pasted image 20220628154448](https://user-images.githubusercontent.com/66924945/232016129-e8a79350-f45b-4c90-9e0f-25d00ffb8eed.png)


-   You can use Azure AD as your identity system for just about any app. Many apps are already pre-configured and can be set up with minimal effort. These pre-configured apps are published in the Azure AD App Gallery.
-   You can manually configure most apps for single-sign-on if they aren't already in the gallery. Azure AD provides several SSO options. SAML-based SSO and OIDC-based SSO.

The following list is a brief comparison of the various protocols used by Microsoft identity platform.
-   **OAuth vs. OpenID Connect**: OAuth is used for authorization and OpenID Connect (OIDC) is used for authentication. OpenID Connect is built on top of OAuth 2.0, which means the terminology and flow are similar between the two. You can even authenticate a user using OpenID Connect and get authorization to access a protected resource that the user owns using OAuth 2.0 in one request.
-   **OAuth vs. SAML**: OAuth is used for authorization and Security Assertion Markup Language (SAML) is used for authentication.
-   **OpenID Connect vs. SAML**: Both OpenID Connect and SAML are used to authenticate a user and are used to enable single-sign-on. SAML authentication is commonly used with identity providers such as Active Directory Federation Services (ADFS) federated to Azure AD and is therefore frequently used in enterprise applications. OpenID Connect is commonly used for apps that are purely in the cloud, such as mobile apps, web sites, and web APIs.

Applications in the Azure AD gallery support either manual or automatic provisioning.
In the Azure AD gallery, applications that support automatic provisioning are designated by a **Provisioning** icon.

![Pasted image 20220628154812](https://user-images.githubusercontent.com/66924945/232016174-0b25dccb-84c3-42e5-a6c5-a48ab2a83c1e.png)


**System for Cross-Domain Identity Management (SCIM)** API Provisioning
	Uses /Users and /Groups endpoints and REST verbs to function - JSON queries

![Pasted image 20220628155113](https://user-images.githubusercontent.com/66924945/232016228-fda36d1e-1c9b-411c-bfe9-467a5f951ef3.png)

The standard user object schema and REST APIs for management defined in SCIM 2.0 allow identity providers and apps to integrate with each other more easily. Application developers that build a SCIM endpoint can integrate with any SCIM-compliant client without having to do custom work, rather than starting from scratch and building the implementation completely on your own, you can rely on a number of open source SCIM libraries published by the SCIM community.

**Application Audit logs** Azure AD > Enterprise Applications > Audit Logs

**Application collections** - P1/P2, better organisation of company apps in portal
You can also use the **My Apps portal** ( https://myapps.microsoft.com) to add app collections.

**Azure AD gallery** provisioning modes - Manual and automatic

### Implement app registration
Two representations of applications in Azure AD - application objects & service principles
	**application objects** - You can manage application objects in the Azure portal through the App Registrations experience. Application objects define and describe the application to Azure AD, enabling Azure AD to know how to issue tokens to the application based on its settings. The application object will only exist in its home directory
	**service principles** - You can manage service principals in the Azure portal through the Enterprise Applications experience. Service principals govern an application connecting to Azure AD and can be considered the instance of the application in your directory. Any given application can have at most one application object (which is registered in a "home" directory) and one or more service principal objects representing instances of the application in every directory in which it acts.

![Pasted image 20220628160757](https://user-images.githubusercontent.com/66924945/232016396-c09ff6da-91c9-4173-9328-23b104bc1dd7.png)


Not all service principals point back to an application object. When Azure AD was originally built, the services provided to applications were more limited, and the service principal was sufficient for establishing an application identity. The original service principal was closer in shape to the Windows Server Active Directory service account. For this reason, it's still possible to create service principals through different pathways, such as using Azure AD PowerShell, without first creating an application object. The Microsoft Graph API requires an application object before creating a service principal.

While there are some tasks that only Global Administrators can do by default (such as adding applications from the app gallery and configuring an application to use the Application Proxy), you can also assign roles like Application Administrator, and Cloud Application Administrator to perform these tasks. You **must remember** that by default all users in your directory have rights to register application objects they're developing, and they have discretion over which applications they share / give access to their organizational data through consent.

Allowing users to register and consent to applications might initially sound concerning, but keep the following in mind:
-   Applications have been able to leverage Windows Server Active Directory for user authentication for many years without requiring the application to be registered or recorded in the directory. Now the organization will have improved visibility to exactly how many applications are using the directory and for what purpose.
-   Delegating these responsibilities to users negates the need for an admin-driven application registration and publishing process. With Active Directory Federation Services (AD FS), an admin likely had to add an application as a relying party on behalf of their developers. Now developers can deploy themselves (self-service).
-   Users signing in to applications using their organization accounts for business purposes is a good thing. If they subsequently leave the organization, they'll automatically lose access to their account in the application they were using.
-   Having a record of what data was shared with which application is a good thing. Data is more transportable than ever and it's useful to have a clear record of who shared what data with which applications.
-   API owners who use Azure AD for OAuth decide exactly what permissions users are able to grant to applications and which permissions require an admin to agree to. Only admins can consent to larger scopes and more significant permissions, while user consent is scoped to the users' own data and capabilities.
-   When a user adds or allows an application to access their data, the event can be audited. You can view the Audit Reports within the Azure portal to determine how an application was added to the directory.

Use **certificates** instead of client secrets for apps to identify to auth services

**app governance add-on feature** for Defender for Cloud Apps is a security and policy management capability designed for OAuth-enabled apps that access Microsoft 365 data through Microsoft Graph APIs. App governance delivers full visibility, remediation, and governance into how these apps and their users access, use, and share your sensitive data stored in Microsoft 365 through actionable insights and automated policy alerts and actions.

Declare app roles in Azure Portal via **App roles and App manifest editor**

## Plan and implement an identity governance strategy

### Plan and implement entitlement management
Entitlement management introduces to Azure AD the concept of an **access package**. An access package is a bundle of all the resources with the access a user needs to work on a project or perform their task.

When to use access packages:
-   Employees need time-limited access for a particular task. For example, you might use group-based licensing and a dynamic group to ensure all employees have an Exchange Online mailbox, and then use access packages for situations in which employees need additional access, such as to read departmental resources from another department.
-   Access requires the approval of an employee's manager or other designated individuals.
-   Departments wish to manage their own access policies for their resources without IT involvement.
-   Two or more organizations are collaborating on a project, and as a result, multiple users from one organization will need to be brought in via Azure AD B2B to access another organization's resources.

**Azure AD terms of use policies** - PDF, can tune frequency of prompt/acceptance
	Azure AD > Identity Governance > Terms of use
	Can view number of accepted / declined, history of user
Users - https://myapps.microsoft.com - Overview > Settings and Privacy

**Connecting organizations** 
	Azure AD > Identity Governance > Connected organizations
	**Sponsors** are internal or external users already in your directory. Sponsors are the point of contact for the relationship with this connected organization.

**Access packages** should be used for access that requires the approval of an employee's manager

### Plan, implement, and manage access reviews (P2)
Typical targets for review include:
	- **User access** to applications integrated with Azure AD for single-sign-on (such as SaaS, line-of-business).
	- **Group membership** (synchronized to Azure AD, or created in Azure AD or Microsoft 365, including Microsoft Teams).
	- **Access Package** that groups resources (groups, apps, and sites) into a single package to manage access.
	- **Azure AD roles** and Azure Resource roles as defined in Privileged Identity Management (PIM).

The creator of the access review decides at the time of creation who will perform the review. This setting can't be changed once the review is started. Reviewers are represented by three personas:
-   Resource Owners, who are the business owners of the resource.
-   A set of individually selected delegates, as selected by the access reviews administrator.
-   End users who will each self-attest to their need for continued access.

Reviews done via Email trigger or via My Apps Portal - https://myapps.microsoft.com
Can be automated by enabling "Auto apply results to resource" option

### Plan and implement privileged access (P2)
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
-   The user accounts are federated, and federation is currently unavailable because of a cell-network break or an identity-provider outage. For example, if the identity provider host in your environment has gone down, users might be unable to sign in when Azure AD redirects to their identity provider.
-   The administrators are registered through Azure AD Multi-Factor Authentication. All their individual devices are unavailable or the service is unavailable. Users might be unable to complete multi-factor authentication to activate a role. For example, a cell network outage is preventing them from answering phone calls or receiving text messages. Especially when these authentication-methods are the only two authentication mechanisms that they registered.
-   The person with the most recent Global Administrator access has left the organization. Azure AD prevents the last Global Administrator account from being deleted, but it doesn't prevent the account from being deleted or disabled on-premises. Either situation might make the organization unable to recover the account.
-   Unforeseen circumstances such as a natural disaster emergency, during which a mobile phone or other networks might be unavailable.

Create two or more emergency access accounts. These accounts should be cloud-only accounts that use the .onmicrosoft.com domain and that aren't federated or synchronized from an on-premises environment.

When and admin configures emergency accounts, the following requirements must be met:

-   The emergency access accounts shouldn't be associated with any individual user in the organization. Make sure that your accounts aren't connected with any employee-supplied mobile phones, hardware tokens that travel with individual employees, or other employee-specific credentials. This precaution covers instances where an individual employee is unreachable when the credential is needed. Any registered devices need to be kept in known, secure location. These locations need multiple means of communicating with Azure AD.
-   The authentication mechanism used for an emergency access account should be distinct. Keep it separate from that used by your other administrative accounts, including other emergency-access accounts. For example, if your normal administrator sign-in is via on-premises MFA, then Azure AD MFA would be a different mechanism. However, if Azure AD MFA is your primary part of authentication for your administrative accounts, then consider a different approach for emergency-accounts. Try things such as using Conditional Access with a third-party MFA provider via Custom controls.
-   The device or credential must not expire or be in scope of automated cleanup due to lack of use.
-   You should make the Global Administrator role assignment permanent for your emergency access accounts.

at least one of your emergency access accounts shouldn't have the same multi-factor authentication mechanism as your other non-emergency accounts

During an emergency, you don't want a policy to potentially block your access to fix an issue. At least one emergency access account should be excluded from all Conditional Access policies.

**Validating accounts**
When you train staff members to use emergency access accounts and validate the emergency access accounts, at minimum do the following steps at regular intervals:

-   Ensure that security-monitoring staff is aware that the account-check activity is ongoing.
-   Ensure that the emergency break-glass process to use these accounts is documented and current.
-   Ensure that administrators and security officers who might need to perform these steps during an emergency are trained on the process.
-   Update the account credentials, in particular any passwords, for your emergency access accounts, and then validate that the emergency access accounts can sign in and perform administrative tasks.
-   Ensure that users haven't registered multi-factor authentication or self-service password reset (SSPR) to any individual user’s device or personal details.
-   If the accounts are registered for multi-factor authentication to a device, for use during sign-in or role activation, ensure that the device is accessible to all administrators who might need to use it during an emergency. Also verify that the device can communicate through at least two network paths that don't share a common failure mode. For example, the device can communicate to the internet through both a facility's wireless network and a cell provider network.

These steps should be performed at regular intervals and for key changes:

-   At least every 90 days
-   When there has been a recent change in IT staff, such as a job change, a departure, or a new hire
-   When the Azure AD subscriptions in the organization have changed

**Eligible roles** assigned in PIM

### Monitor and maintain Azure Active Directory

Monitoring > Sign-ins
It may take up to two hours for some sign-in records to show up in the portal.
**Note**: The sign-ins report only displays the interactive sign-ins—those in which a user manually signs in using their username and password. Non-interactive sign-ins, such as service-to-service authentication, are not displayed in the sign-ins report.
Download as CSV or JSON

Usage of managed applications report

Azure AD > Monitoring > Audit logs
Users > Monitoring > Audit logs
Groups > Monitoring > Audit logs
Enterprise Applications > Monitoring > Audit logs

Can connect **Microsoft Sentinel** to Azure AD

**Identity Secure Score**  -  Indicator for how aligned you are with Microsoft's best practice recommendations for security.
<!-- Author: Stuart Mackay -->
