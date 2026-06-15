# Azure Sentinel (SIEM) Live Threat & Operational Data Visualization

## Project Overview
This project demonstrates the implementation of a cloud-native Security Information and Event Management (SIEM) system using **Microsoft Azure Sentinel**. By aggregating, parsing, and analyzing diverse log streams within a cloud environment, this project transforms raw, high-volume telemetry data into actionable, interactive **KQL (Kusto Query Language) Workbooks**. 

The primary objective was to build real-time, geographic, and operational visualizations that distinguish normal user activity from anomalous patterns, malicious traffic, and system failures.

---

## Core Visualizations & Scenarios Implemented

### 1. Entra ID (Azure) Authentication Success
* **Log Source:** `SigninLogs`
* **Objective:** Tracks authorized access points globally to establish a baseline of normal user operations.
* **Business Value:** Identifies geographic anomalies (e.g., impossible travel) for legitimate corporate or partner accounts.

### 2. Entra ID (Azure) Authentication Failures
* **Log Source:** `SigninLogs` (ResultType != 0)
* **Objective:** Maps failed login attempts across the tenant.
* **Business Value:** High-density clusters quickly expose targeted credential-stuffing or brute-force campaigns.

### 3. Azure Resource Creation & Modifications
* **Log Source:** `AzureActivity` (OperationNameValue containing "write" or "action")
* **Objective:** Visualizes where and when infrastructure modifications occur.
* **Business Value:** Provides operational visibility into shadow IT, unauthorized resource provisioning, or configuration drift.

### 4. Virtual Machine (VM) Authentication Failures
* **Log Source:** `Syslog` (Linux) / `SecurityEvent` (Windows)
* **Objective:** Monitors brute-force SSH/RDP attempts targeting specific cloud infrastructure components.
* **Business Value:** Isolates vulnerable endpoints requiring stricter Network Security Group (NSG) rules or Just-In-Time (JIT) access.

### 5. Malicious Traffic Entering the Network
* **Log Source:** `AzureDiagnostics` / `CommonSecurityLog` (Firewall/WAF logs)
* **Objective:** Maps inbound traffic flagged by threat intelligence feeds or blocked by edge security policies.
* **Business Value:** Identifies active adversaries and origin networks attempting to exploit infrastructure vulnerabilities.

---

## Technical Architecture & Workflow

1.  **Ingestion:** Telemetry gathered from Azure Active Directory (Entra ID), Platform Activity Logs, Host OS Event Logs, and Network Security Groups into a **Log Analytics Workspace**.
2.  **Data Extraction:** Used **Kusto Query Language (KQL)** to filter, aggregate, and parse unstructured IP/location data from complex JSON payloads.
3.  **Visualization:** Configured **Azure Sentinel Workbooks** utilizing map rendering lenses, shifting raw statistical tables into accessible, geographic dashboards.

---

## Skills Demonstrated
* **Cloud Infrastructure:** Hands-on configuration and operation of Microsoft Azure core services, workspaces, and monitoring tools.
* **Data Analysis & Observability:** Querying and structuring big datasets to identify patterns hidden within distracting background noise.
* **Data Translation:** Translating complex log data into clear, concise visual materials for stakeholder reporting.
* **Problem Resolution:** Investigating system disruptions, anomalies, and failed states to recommend long-term configuration improvements.
