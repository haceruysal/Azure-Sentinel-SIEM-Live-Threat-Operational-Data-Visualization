# Azure Sentinel (SIEM) Live Threat & Operational Data Visualization

## Project Overview
This project demonstrates the implementation of a cloud-native Security Information and Event Management (SIEM) system using **Microsoft Azure Sentinel**. By aggregating, parsing, and analyzing diverse log streams within a cloud environment, this project transforms raw, high-volume telemetry data into actionable, interactive **KQL (Kusto Query Language) Workbooks**. 

The primary objective was to build real-time, geographic, and operational visualizations that distinguish normal user activity from anomalous patterns, malicious traffic, and system failures.

---

## Core Visualizations & Scenarios Implemented

### 1. Entra ID (Azure) Authentication Success

* **Log Source:** `SigninLogs`
* **Objective:** Tracks authorized access points globally to establish a baseline of normal user operations.
* 
#### Visual Dashboard
### Entra ID Authentication Success Map
<img width="1522" height="556" alt="Screenshot 2026-06-16 at 1 24 57 PM" src="https://github.com/user-attachments/assets/8a888548-d605-435b-80cf-2ced7da73337" />

#### The KQL Query
```kusto
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
### 📊 Dashboard Analysis & Key Findings

* **Geographic Baseline:** Visualizes the global distribution of all successful user logins by plotting the exact latitude and longitude coordinates extracted from nested JSON log data. This allows operational teams to map out standard traffic boundaries and establish normal operational patterns.
* **The New York Outlier:** A deep-dive analysis of the live map exposed a massive data spike—a single hashed user identity (`3b6c9593...`) accounting for over 1.69k successful logins originating from New York, US.
* **Human vs. Machine Tracking:** In a production corporate environment, this high-density authentication pattern would instantly flag a potential account compromise or credential stuffing attack because it deviates completely from standard human behavior.
* **Operational Conclusion:** Further root-cause investigation confirmed this cluster was actually safe "system noise"—specifically, a high-frequency automated health-check script running on a continuous loop natively out of an Azure East US data center.
* **Business Value:** Successfully identifying and isolating this background infrastructure traffic ensures cleaner datasets, leading to accurate system observability, reduced false-positive fatigue for analysts, and faster incident investigation times.


---

### 2. Entra ID (Azure) Authentication Failures

* **Log Source:** `SigninLogs`
* **Objective:** Maps failed login attempts across the tenant to expose targeted credential-stuffing or brute-force campaigns.
* **Business Value:** High-density failure clusters identify active threat vectors, allowing engineers to isolate targeted accounts and implement automated conditional access policies or block malicious subnets.

#### Visual Dashboard
### Entra ID Authentication Failure Map
<img width="1756" height="563" alt="image" src="https://github.com/user-attachments/assets/4ed960b4-853a-4e02-9f01-ed6d16b76799" />


#### The KQL Query
```kusto
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

### 🔍 KQL Query Breakdown

* **Isolates Failures:** Filters for `ResultType != 0` to exclusively catch failed or interrupted authentication attempts.
* **Targets User Accounts:** Uses `Identity !contains "-"` to filter out standard system GUIDs and focus on named identities.
* **Flattens Telemetry:** Extracts nested JSON fields (`Latitude`, `Longitude`, `City`, `Country`) to aggregate and count attacks by location.


### 🗺️ Map Visualization & Legend Key

* **Threat Origins:** Bubbles indicate the physical location of the attacking machine, VPN node, or proxy network.
* **Bubble Size (Volume):** Larger bubbles correspond directly to a higher volume of bad login requests (`LoginCount`).
* **Bubble Stacking (Density):** Heavily layered bubbles prove that a wide variety of unique user accounts are being targeted from the exact same region.
* **Color Coding:** * <span style="color:green">**Green Bubbles**</span>: Represent standard credential friction (e.g., bad passwords, missing MFA tokens).
  * <span style="color:red">**Red Bubbles**</span>: Highlight severe security overrides, such as hard **Conditional Access Policy blocks** or account lockouts.

### ⚠️ Key Security Anomalies Detected

* **The "Null Island" Effect:** The massive green bubble over the Atlantic Ocean (coordinates `0,0`) highlights heavily proxied or obfuscated traffic; because the geo-IP system cannot parse the corrupted/masked routing strings, it defaults to zero.
* **North American Red Zone:** A distinct cluster of overlapping red wedges across the Northeastern U.S. and Eastern Canada reveals an aggressive campaign actively hitting corporate security policy barriers.
* **Distributed Brute-Forcing:** Low-volume background noise (3–16 attempts per node) scattered globally across Europe, South Africa, and Asia indicates a typical distributed credential-stuffing script rotating through global proxies.


---

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
