# SC-400 Microsoft Information Protection Administrator - Study Notes

**Author:** Stuart Mackay
<!-- Author: Stuart Mackay -->

## Top Resources
- [Official Microsoft Exam Study Guide / Outline](https://learn.microsoft.com/en-us/certifications/resources/study-guides/SC-400)
- [Official Microsoft Learning Path](https://learn.microsoft.com/en-us/certifications/exams/sc-400)
- [SC-400 Labs](https://github.com/MicrosoftLearning/SC-400T00A-Microsoft-Information-Protection-Administrator/tree/master/Instructions/Labs)


## Notes from Microsoft Learn & Microsoft Docs:


## Implement Information Protection in Microsoft 365

### Prevent data loss

Use **Microsoft Purview Data Loss Prevention** features to help protect and manage sensitive data.

What needs protection?
 - Data Types: Credit cards, Addresses, contracts...
 - Data Formats: Office documents, PDFs, custom...
 - Data Location: SharePoint, Azure, OneDrive, Email, USB...
 - Data Generation: Reports, workflows, archives...

Example:

![Pasted image 20221024120020](https://user-images.githubusercontent.com/66924945/232289051-1f4b6066-202c-454a-b891-7a38507fbe3e.png)


DLP Can be used in this scenario in the following areas:
 - DLP policies to block sending emails with PII
 - Block sharing sensitive information in cloud via Microsoft Defender for Cloud Apps
 - Rights Management Service (RMS) applied to SharePoint libraries

Think of DLP as also meaning Data Lifecycle Protection.

4 key areas for preventing data loss and managing the data lifecycle:
 - Detect/Discover: Identify data to protect with content scans (AIP)
 - Protection: Enforcement types such as blocking, warning and auditing
 - Visibility: Protect but allow access for compliance/risk/investigation
 - Data Immunization: Apply classification immediately to minimize data exposure time and provide context

### Classify data for protection and governance

The data classification solution has two methods of classifying content:
 - Sensitive information types
 - Trainable classifiers

To see the top sensitive information types detected in SharePoint Online, OneDrive and Exchange, go to: **Microsoft Purview compliance portal > Data Classification > Overview** and look for the **Top sensitive info types** card

A **sensitive information type** is defined by a pattern that can be identified by a regular expression or function.
 - 100+ built-in to Microsoft 365, can be customized
 - Types: Format, Pattern, Checksum, Keywords, Definition

A **Luhn test** is used to validate credit card numbers.

Data classification using **trainable classifiers** is useful when content is not easily identified using pattern matching.
 - Uses AI and ML
 - Microsoft 365 E5 Feature
 - Built-in classifiers: CVs, Source Code, Harassment, Profanity, Threat

The trainable classifier configuration process can be broken down as follows:
0. **One-time setup.** Takes 7-14 days to learn about the data content.
1.  **Seed**. Prepare your sample data and create the trainable classifier.
2.  **Test**. Prepare test data, test the predictive model, and evaluate the results.
3.  **Publish**. Make the trainable classifier available for use in your compliance solutions.

The data classification **Overview** page provides snapshots of how sensitive information and labels are being used.
-   What sensitive data is out there?
-   What labels are being used the most?
-   Is sensitive data being copied or shared outside the organization?

The **top activities detected** card summarizes the most common actions taken on items with sensitivity labels applied:

![Pasted image 20221024135716](https://user-images.githubusercontent.com/66924945/232289066-be70c35d-6d72-4406-ad92-9c2a282440f2.png)


**Activity Explorer** provides visibility into document-level activities
 - Microsoft 365 E5 Feature

**Content explorer** shows a current snapshot of the items that have a sensitivity label, a retention label, or have been classified as a sensitive information type.

The **data classification overview page** provides snapshots of how sensitive info and labels are being used across your organization's locations.

### Create and manage sensitive information types
The special features of **custom sensitive information types** include:
-   **Exact Data Match (EDM)-based classification** - enables you to create custom sensitive information types that refer to exact values in a database of sensitive information. The database can be refreshed daily and contain up to 100 million rows of data.
-   **Document Fingerprinting** - identifies standard forms that are used throughout your organization via patterns.  Forms and templates are most effective.
-   **Keyword dictionaries** - Large lists of words subject to change

**Confidence level** component uses more evidence to reduce false positives

### Understand Microsoft 365 encryption

**Bitlocker:**
 - Encrypts data at the volume level
 - Uses AES 256 bit
 - TPM > Volume Master Key (VMK) > Full Volume Encryption Key (FYEK) > Cleartext
 - (Optional) Recovery keys stored in Microsoft Datacenter

**Application layer encryption** 
 
 - **Microsoft Managed Keys** - Default service encryption
 
![managed-key-hierarchy](https://user-images.githubusercontent.com/66924945/232289075-cdfc7c9d-a473-454b-b69d-2d871782260c.png)

- **Customer Managed Keys** - Allows use of own root keys, managed by Key Vault

![customer-key-hierarchy](https://user-images.githubusercontent.com/66924945/232289082-2d92f7dc-5354-45a5-9b2d-96da50b13f08.png)

-   Providing rights protection and management features on top of strong encryption protection.
-   Enhancing the ability of Microsoft 365 to meet the demands of customers with compliance requirements regarding encryption.
- Data recovery available with **Availability Keys** if root keys are lost/unavailable

Microsoft owns and manages its own certificate authority to manage the certificates used for TLS encryption alongside third-party solutions. The public certificates are issued by Microsoft using SSLAdmin, an internal Microsoft tool to protect confidentiality of transmitted information.


### Deploy Microsoft Purview Message Encryption
By default, all newly created Microsoft 365 tenants use the **Microsoft-generated keys** for encryption.

**IRM** = Information Rights Management
**OME** = Office 365 Messaging Encryption
**Azure RMS** = Azure Rights Management System
  
**OME** is managed via configuration objects (templates), which can be assigned and referenced.
  
**Microsoft Purview Advanced Message Encryption** allows you to use multiple templates for email messages and configure an expiration time for protected messages.
  
You can use message expiration on emails that your users send to external recipients that use the **encrypted message portal** to access encrypted emails.

Create mail flow rules from the Exchange Admin Center - **Mail flow** > **Rules** and select **New** > **Apply Office 365 Message Encryption and rights protection to messages**


### Protect information in Microsoft Purview
A **sensitivity label**, when applied, can restrict access to content using encryption, add a mark to the document (like a watermark), or do nothing at all.

**Client-side auto-labeling** is supported in Office apps on Windows for users who have either the Azure Information Protection unified labeling client or certain early adopter versions of Microsoft 365 Apps for enterprise (formally known as Office 365 ProPlus) installed.
 - Microsoft 365 E5 Feature

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


## Implement Data Loss Prevention

### Prevent data loss in Microsoft Purview
**Microsoft Purview Data Loss Prevention helps prevent users from accidentally, rather than intentionally sharing sensitive content.** (If a user is determined enough to send sensitive data outside the organization, they will find another way to do so.)

Use **Microsoft 365 data classification** to view information to be protected

![Pasted image 20220913135430](https://user-images.githubusercontent.com/66924945/232289094-fb10130f-c842-4d8f-b0c0-e27312730d73.png)


**Endpoint data loss prevention** (Endpoint DLP) extends the activity monitoring and protection capabilities of DLP to sensitive items on Windows devices.

The DLP-specific reports available in the **Microsoft Purview compliance portal** include:
-   DLP policy matches
-   DLP incidents
-   DLP false positives and overrides
-   Third-party DLP policy matched
  
Navigate to **Microsoft Purview compliance portal > Reports** to view the reports.


### Configure DLP policies for Microsoft Defender for Cloud Apps and Power Platform
DLP policies in Power Platform are used to **restrict the communication between connectors**. A connector in Power Platform is a wrapper or an API that allows predefined triggers and actions to access the data behind it.

**Connector Types**:
 - Business: Connects only to other Business group connectors
 - Non-Business: Connects only to other Non-Business group connectors
 - Blocked: Blocks any connection attempts
Connectors reside in only one of these groups at a time

Data loss prevention (DLP) policies can be used for non-Microsoft cloud apps as part of the Microsoft Purview Data Loss Prevention features.  These can be created either by:
 - Creating file policies in the Microsoft Defender for Cloud Apps portal
 - Creating DLP policies in the Microsoft Purview compliance portal and specify Microsoft Defender for Cloud Apps as the location
 
You may need to activate the file monitoring in Defender for Cloud Apps before creating file policies. Perform the following steps to enable Defender for Cloud Apps to see files in the SaaS apps:
1.  Navigate to the **Microsoft Defender for Cloud Apps** portal at [https://portal.cloudappsecurity.com](https://portal.cloudappsecurity.com/).
2.  Select the cogwheel in the upper right and select **Settings**, the select **Settings** again.
3.  Select **Files** from the **Information Protection** section.
4.  Check **Enable file monitoring** if not checked already and select **Save**.

**Microsoft Defender for Cloud Apps** built-in DLP engine performs content inspection by extracting text from all common file types.

**Exchange Policies** can be configured in the Microsoft Purview compliance portal.

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

## Implement Data Lifecycle and Records Management

### Manage the data lifecycle in Microsoft Purview

![Pasted image 20220913154546](https://user-images.githubusercontent.com/66924945/232289107-bce64867-3617-453c-8f82-af80a12f5adc.png)
   
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

![Pasted image 20220913163523](https://user-images.githubusercontent.com/66924945/232289122-e1ae2620-53e4-42f6-bae5-7363d81cf66f.png)

  
Overview of roles and permissions:

<img width="725" alt="Pasted image 20220913164823" src="https://user-images.githubusercontent.com/66924945/232289127-d4d145a2-1b7d-4689-9d0b-6e4f563cf0f1.png">

  
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
<!-- Author: Stuart Mackay -->
