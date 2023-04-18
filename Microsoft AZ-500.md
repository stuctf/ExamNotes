# AZ-500 Microsoft Azure Security Technologies - Study Notes
  
**Author:** Stuart Mackay 
<!-- Author: Stuart Mackay -->
## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://learn.microsoft.com/en-us/certifications/resources/study-guides/az-500)
- [Official Microsoft Learning Path](https://learn.microsoft.com/en-us/certifications/exams/az-500/)
- [John Savill AZ-500 Study Playlist (Youtube)](https://www.youtube.com/watch?v=6vISzj-z8k4&list=PLlVtbbG169nHw9T1L_CiLxC-DTwKu-BZG)
- [John Savill AZ-500 Study Cram (Youtube)](https://www.youtube.com/watch?v=6vISzj-z8k4)
- [AZ-500 Labs](https://microsoftlearning.github.io/AZ500-AzureSecurityTechnologies/)

## Notes from Microsoft Learn & Microsoft Docs:

## Manage Identity and Access  
### Secure Azure solutions with Azure Active Directory  
**Azure Active Directory** (Azure AD) is Microsoft’s multi-tenant cloud-based directory and identity management service.  
 - Comes in four editions—**Free**, **Microsoft 365 Apps**, **Premium P1**, and **Premium P2**.
	 - P1+ for Conditional Access, P2 for Identity Protection & Governance
-  **Identity solution.** Azure AD is primarily an identity solution, and it is designed for Internet-based applications by using HTTP and HTTPS communications.
-   **REST API Querying.** Because Azure AD is HTTP/HTTPS based, it cannot be queried through LDAP. Instead, Azure AD uses the REST API over HTTP and HTTPS.
-   **Communication Protocols.** Because Azure AD is HTTP/HTTPS based, it does not use Kerberos authentication. Instead, it uses HTTP and HTTPS protocols such as SAML, WS-Federation, and OpenID Connect for authentication (and OAuth for authorization).
-   **Authentication Services.** Include SAML, WS-Federation, or OpenID.
-   **Authorization Service.** Uses OAuth.
-   **Federation Services.** Azure AD includes federation services, and many third-party services (such as Facebook).
-   **Flat structure.** Azure AD users and groups are created in a flat structure, and there are no Organizational Units (OUs) or Group Policy Objects (GPOs).  
  
Microsoft recommends maximum 5 Global Administrators.  

**Azure Active Directory Domain Services (Azure AD DS)** - Cloud based traditional AD  

Check **MFA** enrollment by checking for **Enforced** in the MFA report screen  

One time bypass is available for locked out users

### Implement Hybrid identity  

**Azure AD Connect** can use Password hash synchronisation & Pass-through authentication.  Optional Federation integration using AD FS infrastructure.  
**AD Connect Health** works by installing an agent on each on-premise sync server.  
  
**Password hash synchronization** (PHS) is a feature used to synchronize user passwords from an on-premises Active Directory instance to a cloud-based Azure AD instance.  
  
**Azure AD Pass-through Authentication** (PTA) - validates the users’ passwords directly against an organization's on-premise Active Directory.  Can use same credentials for cloud and on-prem.
  
You can federate your on-premises environment with Azure AD to ensure authentication on-prem and strictly control access.  PHS can optionally be setup as backup if on-prem fails.  
  
**Password writeback** allows password changes in the cloud to be written back to an existing on-premises directory in real time.  
To use **self-service password reset (SSPR)** you must have already configured Azure AD Connect in your environment.

### Deploy Azure AD identity protection   
-   **User risk policy** - Identifies and responds to user accounts that may have compromised credentials. Can prompt the user to create a new password.
-   **Sign-in risk policy** - Identifies and responds to suspicious sign-in attempts. Can prompt the user to provide additional forms of verification using Azure AD Multi-Factor Authentication. Supports location and client apps.  
-   **MFA registration policy** - Makes sure users are registered for Azure AD Multi-Factor Authentication. If a sign-in risk policy prompts for MFA, the user must already be registered for Azure AD Multi-Factor Authentication. Options include call to phone, text message, notification through mobile app and verification via app/hardware token.  
Risk thresholds can be configured for user and sign-in - low, medium and high

![Pasted image 20220721151207](https://user-images.githubusercontent.com/66924945/231860322-3072a818-53e7-46e4-af7f-ca9b13201486.png)

Identity administrators receive email alerts when users report **fraud alerts** via MFA  
  
Azure AD supports the use of **OATH-TOTP SHA-1 tokens** that refresh codes every 30 or 60 seconds.  
**Trusted IPs** bypass works only from inside of the company intranet.  
  
**Conditional Access** is the tool used by Azure Active Directory to bring signals together, to make decisions, and enforce organizational policies. Conditional Access is at the heart of the new **identity driven control plane**.  Think Identity as a Service.  
- Can be described as if-then statements
- Configured under Azure AD > Manage > Security > Protect > Conditional Access

![Pasted image 20220721153042](https://user-images.githubusercontent.com/66924945/231860414-8faeca72-dd9f-460a-9bba-eb4704d2c29a.png)
  
**Access Reviews** - To manage ongoing access to resources, admin groups etc. Needs P2  
 - Configured under **Identity Governance** in Azure Portal
  
Security Administrator / Operator roles cannot change user passwords  

### Configure Azure AD privileged identity management  
**Principles of Zero Trust**: verify explicitly, least privilege, assume breach  

**Simplified Microsoft reference architecture to implement Zero Trust:**  

![Pasted image 20220721160606](https://user-images.githubusercontent.com/66924945/231860477-73c04ca8-15ad-4081-913b-f3b388d55888.png)
  
**Microsoft Identity Manager (MIM)** - On-prem/hybrid identity management.  

**Privileged Identity Management** - Allows Just In Time access to roles  

![Pasted image 20220721162538](https://user-images.githubusercontent.com/66924945/231860519-1f57a07f-93e7-4415-9820-e912ab3697d7.png)

  
PIM is used to manage **Azure AD roles**

### Design an enterprise governance strategy  
**Shared responsibility model**
Customer always responsible for: Information and data, devices, accounts & identities
Cloud provider always responsible for: physical hosts, network, datacenter  
  
**Azure Resource Manager** is the deployment and management service for Azure.  
  
**Azure Hierarchy** - Tenant > Management Group > Subscription > Resource Groups
**Management group** hierarchies can be up to six levels deep.  
  
**Azure Policy** is a service you use to create, assign, and manage policies  
 - Composed of policy definition, policy assignment & policy parameters
 - Track compliance with an **initiative definition**
 - Unlike RBAC, **Azure Policy is a default-allow-and-explicit-deny system**.
  
**A subscription is associated with only one Azure AD tenant.   
A resource group can have multiple resources but is associated with only one subscription.  
A resource can be bound to only one resource group.**  
  
**RBAC** and admin accounts in Azure

![Pasted image 20220722132634](https://user-images.githubusercontent.com/66924945/231860588-8c8459bd-3d3c-4336-bb4e-36603f6b0c79.png)

    
**Resource Locks** - CanNotDelete or ReadOnly supported, Owner and User Access Administrator  
**Azure Blueprints** - declarative way to orchestrate the deployment of various resource templates and other artifacts
 - Backed by **Azure Cosmos DB**
 - Use instead of multiple ARM templates  

A **billing administrator** or **account administrator** is a person who has permission to manage billing for an account - **enterprise administrators** can transfer billing ownership of subscriptions between accounts.  
  
**Contributor role** at resource group level allows read/write of resource deployment, least privilege  
  
  
## Implement platform protection
### Implement perimeter security
-   **Azure Network Security Groups** can be used for basic layer 3 & 4 access controls between Azure Virtual Networks, their subnets, and the Internet.
-   **Application Security Groups** enable you to define fine-grained network security policies based on workloads, centralized on applications, instead of explicit IP addresses.
-   **Azure Web Application Firewall** and the **Azure Firewall** can be used for more advanced network access controls that require application layer support.
-   **Local Admin Password Solution (LAPS)** or a third-party Privileged Access Management can set strong local admin passwords and just in time access to them.  
  
A VNet is a representation of your own network in the cloud. A VNet is a logical isolation of the Azure cloud network dedicated to your subscription. You can connect VNets to your on-premises networks.  
Dedicated WAN link connectivity to on-prem via **ExpressRoute**  
A virtual network is **scoped to a single Azure region**.  

**DDos** protection: Basic vs Standard.  Basic automatically enabled by default, same protection as MS global network.  Standard adds dedicated ML except app service environments
- When coupled with the **Application Gateway web application firewall**, or a third-party web application firewall deployed in a virtual network with a public IP, DDoS Protection Standard can provide full layer 3 to layer 7 mitigation capability.

**FQDN tag in application rules** allow the required Microsoft Services outbound network traffic through the firewall. For Example, Windows Update tag.  
**Threat intelligence-based filtering** can be enabled for your firewall to alert and deny traffic from/to known malicious IP addresses and domains.  
Rule collections are processed according to the rule type in priority order, **lower numbers to higher numbers** from 100 to 65,000.  
A **service tag** represents a group of IP address prefixes to help minimize complexity for security rule creation.  
Use **Azure Firewall DNAT rules** along with its threat intelligence-based filtering capabilities to protect VDI deployments.  
Must allow a set of outbound network connections for the **Windows Virtual Desktop virtual machines** that run in your virtual network.  
  
**Forced tunneling** lets you redirect, or force, all internet-bound traffic back to your on-premises location via a site-to-site VPN tunnel for inspection and auditing.  

![Pasted image 20220725133658](https://user-images.githubusercontent.com/66924945/231860657-007e124e-a3ec-45e8-960e-c6d017399a5b.png)

If no internet-facing workloads exist in your VMs, you can also apply forced tunneling to the entire virtual network.  
**Configure forced tunneling in Azure via virtual network User Defined Routes (UDR)**  
  
**User Defined Routes (UDR)** - custom route in Azure that overrides Azure's default system routes or adds routes to a subnet's route table.  
![Pasted image 20220725134028](https://user-images.githubusercontent.com/66924945/231860704-a3288ad4-ab5e-4bea-968a-7b59bc9d9621.png)

In this diagram UDRs are used to direct traffic from the Gateway subnet and the Web tier to the **Network Virtual Appliance (NVA)**.  In reality there will be multiple NVAs in an **availability set** for redundancy.  

**UDRs and NSGs help provide layer 3 and layer 4 (of the OSI model) security. NVAs help provide layer 7, application layer, security.**

**Hub and spoke hybrid topology**  

![Pasted image 20220725134606](https://user-images.githubusercontent.com/66924945/231860751-b497cf02-2d1a-48f0-8dce-3a0064bbe944.png)

Example uses: Prod/dev, isolated workloads, central security over segregated workloads
- **Virtual network peering** - Two virtual networks can be connected using a peering connection. Peering connections are non-transitive, low latency connections between virtual networks. Once peered, the virtual networks exchange traffic by using the Azure backbone, without the need for a router. In hub-spoke network topology, you use virtual network peering to connect the hub to each spoke.  
- Where to create peering in Azure Portal:
	-  In the **Portal**, navigate to the virtual network.
	- Under **Settings** select **Peerings**.
	- **+ Add** a virtual network peering.  
  

### Configure network security
VM endpoints map the public port and public IP address of the cloud service to the private port and private IP address of the VM  
  
**Network Security Groups (NSGs)** control inbound and outbound traffic passing through a network adapter (in the Resource Manager deployment model), a VM (in the classic deployment model), or a subnet (in both deployment models).  
NSGs function on ports and IPs, can apply to virtual networks, subnets, VMs, network adapters.  
- By default, you can create 100 NSGs per region per subscription. You can raise this limit to 400 by contacting Azure support.
- You can apply only one NSG to a VM, subnet, or network adapter.
- By default, you can have up to 200 rules in a single NSG. You can raise this limit to 500 by contacting Azure support.
- You can apply an NSG to multiple resources.
- Security rules in an NSG associated to a subnet can affect connectivity between VM's within it.  
- Recommended to associate a network security group to a subnet, or a network interface, but not both.
  
**Application Security Groups** are used to apply rules to multiple resources
- Created within resource groups (search and add, then configure like NSG)
- Applied to VM under Settings > Networking > Application security groups  
  
Using **Service Endpoints** allows access via Private IP instead of Public IP to resources
 - Example is VM accessing storage, restricted based on VM Private IP
 - Provides optimal routing between resources, especially in forced tunneling scenario  
  
**Azure Private Link** provides a direct connection to a service provider via a **private endpoint**  
  
**Azure Application Gateway** is a web traffic loadbalancer, makes decisions based on attributes  
  
**Web Application Firewall** works with **Azure Front Door** and **Azure Application Gateway**
 - Support for **Azure Content Delivery Network** under preview  
  
**Azure Front Door** enables you to define, manage, and monitor the global routing for your web traffic by optimizing for best performance and instant global failover for high availability.
- Works at Layer 7 and uses **split TCP-based anycast protocol**.
- end users connect to the nearest Front Door POP (Point of Presence).  
  
**ExpressRoute** is a direct, private connection from WAN to Microsoft Services, including Azure.  

![Pasted image 20220725160316](https://user-images.githubusercontent.com/66924945/231860813-11bc6076-98d4-4978-b7cf-b221db6b5f98.png)

HQ has ExpressRoute as primary and Site-to-site VPN as failover.  LocalSite2 only has VPN  

**Encryption over ExpressRoute**
- **Azure Virtual WAN** uses IPSec IKE VPN
- **MACsec** can encrypt data at Layer 2, disabled by default on ExpressRoute Direct ports.
**ExpressRoute Direct** gives you the ability to connect directly into Microsoft’s global network at peering locations strategically distributed across the world. ExpressRoute Direct provides dual 100 Gbps or 10 Gbps connectivity, which supports Active/Active connectivity at scale.  
  - Supports **QinQ** and **Dot1Q** VLAN tagging  
  
### Configure and manage host security
**Microsoft Antimalware** is the same underlying technology as **Windows Defender**.  If this is pushed to clients with Defender installed, they will inherit config only.  
  
**Windows Autopilot** avoids the need to re-image hardware, comes in a business-ready state.  

![Pasted image 20220725164933](https://user-images.githubusercontent.com/66924945/231860849-c0c83392-4453-4927-ab65-d73b350e7e19.png)

  
To have a secured workstation you need to make sure the following security technologies are included on the device:
-   Trusted Platform Module (TPM) 2.0
-   BitLocker Drive Encryption
-   UEFI Secure Boot
-   Drivers and Firmware Distributed through Windows Update
-   Virtualization and HVCI Enabled
-   Drivers and Apps HVCI-Ready
-   Windows Hello
-   DMA I/O Protection
-   System Guard
-   Modern Standby

Use **Privileged Access Workstations (PAWs)** for most sensitive use cases and sensitive business functions - These machines are locked down, no admin, no productivity tools.  Only admin tools / bare essentials.  
  
Use VM / Resource manager **templates** to deploy resources.  These are stored in JSON files and executed as REST API operations.  Ensures consistency and rapid (re)deployment.  
  
Use **Azure Bastion** as a cloud jumphost and avoid giving Cloud based VMs public IPs  
- Intial install via portal from VM (Connect > Bastion)
  
**Azure Update Management** included with subscription, uses runbooks to install updates.  
- Config from VM > Operations > Update Management

![Pasted image 20220725171859](https://user-images.githubusercontent.com/66924945/231860898-51c0ee77-43ef-4764-be5e-6745f732d92a.png)

  
**Azure Disk Encryption for Windows VMs** uses BitLocker and **Azure Key Vault**
 - Microsoft Defender for Cloud will show High Severity for unencrypted VMs
 - not available on Basic, A-series VMs, or on virtual machines with less than 2 GB of memory
  
Linux VMs use DM-Crypt and also integrate with Azure Key Vault
- RAM needed: 2GB for storage only, 8GB for <4GB root file system, otherwise root FS * 2  
  
**Windows Defender Credential Guard** isolates secrets via virtualisation, protects against credential theft attacks such as Pass-the-Hash or pass-the-ticket  
**Windows Defender Device Guard** - Branding no longer used due to confusion
**Windows Defender Application Control** mitigates threats by restricting the applications that users can run and the code that runs in the system core, or kernel.  
  
Enable data collection on VMs to allow **Microsoft Defender for Cloud** to provide recommendations  
  
**Azure Security Benchmarks** jointly developed between Microsoft and CIS, provides foundational level security.  Two implementation levels:
 - Level 1 - Recommended minimum security settings, little/no impact
 - Level 2 - For highly secure environments, reduced functionality possible
  
Install endpoint protection is only a **medium-severity** recommendation in Security Center  

### Enable Containers security
Use a private registry for containers such as **Docker Trusted Registry** or **Azure Container Registry**  
Azure Container Registry supports **service principal-based authentication** through Azure Active Directory for basic authentication flows.  
Azure Container Registry optionally integrates with **Microsoft Defender for Cloud** to automatically scan all Linux images pushed to a registry. Microsoft Defender for Cloud integrated **Qualys scanner** detects image vulnerabilities, classifies them, and provides remediation guidance.  
  
**Azure Container Instances (ACI)**, is a PaaS service for scenarios that can operate in isolated containers, including simple applications, task automation, and build jobs.  
 - Azure Container Instances guarantees your application is as isolated in a container as it would be in a VM.  
  
**Kubernetes** is a platform that manages container-based applications and their associated networking and storage components.  
**Azure Kubernetes Service (AKS)** provides a managed Kubernetes service that reduces the complexity for deployment and core management tasks, including coordinating upgrades.  
  
A **Kubernetes cluster** is divided into two components:
-   _Control plane_ nodes provide the core Kubernetes services and orchestration of application workloads.
-   _Nodes_ run your application workloads.

  ![Pasted image 20220725205549](https://user-images.githubusercontent.com/66924945/231860943-42475801-aeb0-49fb-b0cd-c154cd9a0b91.png)

**Kubernetes cluster architecture** is a set of design recommendations for deploying your containers in a secure and managed configuration.  
  
**For true security when running hostile multi-tenant workloads, a hypervisor is the only level of security that you should trust.**  
  
The **Network Policy** feature in Kubernetes lets you define rules for ingress and egress traffic between pods in a cluster.  

## Secure your data and applications
### Deploy and secure Azure Key Vault
Azure Key Vault is designed to support application keys and secrets. Key Vault is not intended as storage for user passwords.  
Azure Key Vault **Premium supports HSM-protected keys**.  
If a user has **contributor permissions (RBAC)** to a key vault management plane, they can grant themselves access to the data plane by setting a key vault access policy.  

![Pasted image 20220726102223](https://user-images.githubusercontent.com/66924945/231860994-ffe2b9b6-47ff-4170-a54b-ce82d6741ea1.png)

  
Cryptographic keys in Key Vault are represented as **JSON Web Key (JWK) objects**.  
 - Soft Keys - Processed in software by Key Vault, but encrypted at rest by HSM
 - Hard Keys - Processed in HSM. Protected in Key Vault HSM Security Worlds  
   
HSMs are FIPS 140-2 Level 2 validated. Azure Key Vault uses Thales nShield family of HSMs  
**Event Grid** and **Function Apps** can be used to automate key rotation.  
**Soft-delete protection** allows recovery of deleted secrets (default), **download backup** too.  
 - There is currently no way to make a backup of your entire Key Vault Instance  
  
**Azure Dedicated HSM** is most suitable for “lift-and-shift” scenarios that require direct and sole access to HSM devices.  
  
To create and delete key vaults in the data plane, you should **grant access with RBAC.**  
  
### Configure application security features
**Microsoft Authentication Library (MSAL)** is recommended for use against the identity platform endpoints.  
Any application that outsources authentication to Azure AD needs to be registered in a directory  
  
**Microsoft Graph** - **Delegated permissions** with signed-in user, **Application permissions** otherwise  
  
**Managed Identities** for Azure resources provides Azure services with an automatically managed identity in Azure AD.  
- A **system-assigned managed identity** is enabled directly on an Azure service instance.
- A **user-assigned managed identity** is created as a standalone Azure resource.
-   **Azure Instance Metadata Service (IMDS)** - a REST endpoint accessible to all IaaS VMs created via the Azure Resource Manager. The endpoint is available at a well-known non-routable IP address (169.254.169.254) that can be accessed only from within the VM.  
  
Microsoft Azure App Service apps redirect requests to an endpoint that signs in users for that provider.  
  
When you enable managed identity on a web app, Azure activates a separate **token-granting REST service** specifically for use by the app. The app will request tokens from this service instead of Azure Active Directory.  

### Implement storage security
**Shared Access Signatures** - A shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources.  Use for untrusted clients.
 - Service-level SAS for specific resource access
 - account-level adds additional resources and abilities such as file system creation
 - user delegation SAS for blob service - access to containers and blobs  

![Pasted image 20220726123029](https://user-images.githubusercontent.com/66924945/231861044-08f6c713-858e-49e3-a8f1-129e002faf8e.png)

   
Where possible use authorizing applications that access Azure Storage using Azure AD. It provides better security and ease of use over other authorization options.  
As a best practice, you shouldn't share **storage account keys** with external third-party applications.  
  
Authorizing requests against **Azure Storage with Azure AD** provides superior security and ease of use over Shared Key authorization. Microsoft recommends using Azure AD authorization with blob applications when possible to assure access with minimum required privileges.  
- All data (including metadata) written to Azure Storage is automatically encrypted using Storage Service Encryption (SSE).
- Data in Azure Storage is encrypted and decrypted transparently using **256-bit AES encryption**

Data retention can be **time-based**, marked for **legal hold** or both (if a container).  
 - When a legal hold policy is set, blobs can be created and read, but not modified or deleted.
 - If the retention interval isn't known, set legal hold to store immutable data.
  
**Azure Files** supports **identity-based authentication** which can extend on-prem permissions  
 - Use robocopy with the /copy:s flag to copy data as well as ACLs to an Azure file share.
  
You can configure your storage account to accept requests from secure connections only by setting the **Secure transfer required property** for the storage account.
 - Requires SMB encryption

### Configure and manage SQL database security
The recommended approach is to create a contained database user, which allows your app to authenticate directly to the database.  
  
**Azure Synapse Analytics** was previously named SQL Data Warehouse
 - only supports server-level IP firewall rules, and not database-level IP firewall rules
  
To create **server-level IP firewall rules** using the Azure portal or PowerShell, you must be the subscription owner or a subscription contributor.  
Whenever possible, as a best practice, use **database-level IP firewall rules** to enhance security and to make your database more portable.  
  
**Auditing** can be applied at server or database level  
  
Definition and customization of your classification taxonomy takes place in one central location for your entire Azure Tenant. That location is in **Microsoft Defender for Cloud**, as part of your Security Policy. Only a user with administrative rights on the Tenant root management group can perform this task.  
  
Vulnerability Assessment is part of the **Advanced Data Security** offering, which is a unified package for advanced SQL security capabilities.  
  
**Microsoft Defender for Cloud for SQL** can identify **Potential SQL injection**, **Access from unusual location or data center, Access from unfamiliar principal or potentially harmful application**, and **Brute force SQL credentials**.  
  
**SQL Database dynamic data masking (DDM)** limits sensitive data exposure by masking it to non-privileged users.  

![Pasted image 20220726134645](https://user-images.githubusercontent.com/66924945/231861088-7137e06f-5745-4a58-9ac3-0f499a91b8df.png)

  
**By default, Transparent data encryption (TDE) is enabled for all newly deployed Azure SQL databases** and needs to be manually enabled for older databases of Azure SQL Database, Azure SQL Managed Instance, or Azure Synapse.  
 - Customer-managed Bring Your Own Key (BYOK) support for TDE. The TDE Protector that encrypts the Database Encryption Key (DEK), is a customer-managed asymmetric key, which is stored in Azure Key Vault
 - To configure TDE through the Azure portal, you must be connected as the Azure Owner, Contributor, or SQL Security Manager.
 - You turn TDE on and off on the database level.
  
**Always Encrypted** protects sensitive data by ensuring on-premises database administrators, cloud database operators, or other high-privileged, but unauthorized users, cannot access the encrypted data  
 - An Always Encrypted-enabled driver installed on the client computer achieves this by automatically encrypting and decrypting sensitive data in the client application.
 - Supports **randomized encryption** and **deterministic encryption**
	 - Deterministic allows more actions but data may be guessed by patterns in columns

## Manage security operation
### Configure and manage Azure Monitor
**Azure Monitor** is a key resource to keep watch on how all your Azure resources are performing, and to trigger alerts if there is any sort of problem.  


![Pasted image 20220726145159](https://user-images.githubusercontent.com/66924945/231861124-52447a71-5950-4e15-818a-0956489193ae.png)

  
Use **Event Hubs** to stream log data from Azure Monitor to a Microsoft Sentinel or a partner SIEM.  
  
Data in **Azure Monitor Logs** is retrieved using a log query written with the **Kusto query language (KQL).  
  
**Log Analytics** is the primary tool in the Azure portal for writing log queries and interactively analyzing their results.
 - **Log Analytics workspace** is at the center, hosted in Azure
 - **Azure Log Analytics agent** for clients in any cloud, on-prem or managed by SCOM
	 - Windows Agent can send to multiple destinations, Linux single destination only
 - **Azure Diagnostics extension** is an alternative for Azure VMs

**Azure Monitor** can send alerts, using action groups - becoming central location for alerts

Streaming of **diagnostic logs** can be enabled programmatically, via the portal, or using the Azure Monitor REST APIs.  
  
**Monitor Metrics** is a feature of Azure Monitor that collects numeric data from monitored resources into a time-series database. You can analyze them interactively by using Metrics Explorer, be proactively notified with an alert when a value crosses a threshold, or visualize them in a workbook or dashboard.

### Enable and manage Microsoft Defender for Cloud
**Microsoft Defender for Cloud** can scan container images in **Azure Container Registry (ACR)** for vulnerabilities.  
**Azure Security Benchmark** is the foundation for **Security Center**’s recommendations and has been fully integrated as the default policy initiative.  
  
When improving **Security Score**, there is a **Quick Fix!** option available for some.  
  
**Just-in-Time VM access** ensures users must request access to VMs, ports not open by default  
  
The Microsoft Defender for Cloud free tier doesn't support monitoring external cloud or non-Azure resources  

### Configure and monitor Microsoft Sentinel
**Microsoft Sentinel** is a scalable, cloud-native, security information event management (**SIEM**) and security orchestration automated response (**SOAR**) solution.  
  
Connect data sources via **connectors**, common event format, Syslog or REST-API  
The **Microsoft Sentinel agent**, which is based on the Log Analytics agent, converts CEF formatted logs into a format that can be ingested by Log Analytics.  
  
**Workbooks** combine text, Analytics queries, Azure Metrics, and parameters into rich interactive reports.
 - saved within an Application Insights resource
 - To make edits, recipients need at least Contributor permissions for the resource.  
  
**Incidents** are groups of related alerts that together create a possible actionable threat that you can investigate and resolve.  
  
Use the built-in rules available in Microsoft Sentinel to choose which connected Microsoft security solutions should create Microsoft Sentinel incidents automatically in real time.

**Playbooks** are built using **Azure Logic Apps**
 - if you use the ServiceNow ticketing system, you can use the tools provided to use Azure Logic Apps to automate your workflows and open a ticket in ServiceNow each time a particular event is detected.
 - Each playbook is created for a specific subscription.

**Investigation graph** visualises entities related to an alert  
  
**Hunting** search and query tools, based on **MITRE Framework**   
  
The Sentinel built-in roles are reader, responder, and contributor.  
  
A **notebook** is a step-by-step playbook that enables the ability to walk through the steps of an investigation and hunt.

<!-- Author: Stuart Mackay -->
