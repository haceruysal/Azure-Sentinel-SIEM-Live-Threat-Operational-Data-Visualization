# Azure Sentinel (SIEM) Live Threat & Operational Data Visualization

## Project Overview
This project demonstrates the implementation of a cloud-native Security Information and Event Management (SIEM) system using **Microsoft Azure Sentinel**. By aggregating, parsing, and analyzing diverse log streams within a cloud environment, this project transforms raw, high-volume telemetry data into actionable, interactive **KQL (Kusto Query Language) Workbooks**. 

The primary objective was to build real-time, geographic, and operational visualizations that distinguish normal user activity from anomalous patterns, malicious traffic, and system failures.

---

## Core Visualizations & Scenarios Implemented



### 1. Entra ID (Azure) Authentication Failures

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
### 📊 Dashboard Analysis & Key Findings
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

### 2. Entra ID (Azure) Authentication Success

* **Log Source:** `SigninLogs`
* **Objective:** Tracks authorized access points globally to establish a baseline of normal user operations.


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

### 🔍 KQL Query Breakdown

* **Isolates Successes:** Filters for `ResultType == 0` to exclusively capture completely successful authentication events across the tenant.
* **Broad Scope Evaluation:** Removes previous identity exclusions (the `!contains "-"` or `contains "-"` logic is entirely absent), tracking all successful connections regardless of whether they are standard users or system accounts.
* **Flattens Telemetry:** Extracts nested JSON properties (`Latitude`, `Longitude`, `City`, `Country`) from the `LocationDetails` payload to count and map successful connections by their physical geographic origin.

### 🗺️ Map Visualization & Legend Key

* **Threat Origins:** Bubbles pinpoint the physical or network location (IP geolocation) from which successful connection events are originating.
* **Bubble Size (Volume):** Larger bubbles correspond directly to a higher volume of events (`LoginCount`).
* **Bubble Stacking (Density):** Heavily layered bubbles prove that a wide variety of unique user accounts or system instances are successfully connecting from the exact same region.
* **Color Coding Key:** * <span style="color:green">**Green Bubbles**</span>: Represent standard, expected successful authentications or expected remote baseline connections.
  * <span style="color:red">**Red Bubbles**</span>: Highlight areas where successful connections are triggering an unexpected policy overlay, a localized anomaly warning, or high-volume traffic shifts within a normally restricted zone.


### ⚠️ Key Security Anomalies Detected

* **The Total Absence of Null Island:** Unlike the failure logs, there is completely **no** giant default bubble at coordinates `(0,0)` off West Africa. This proves that traffic that successfully authenticates passes full infrastructure checking and resolves cleanly to actual regional IP blocks.
* **High-Volume North American Centralization:** The chart bar shows a massive aggregated metric of **24.3K entries** categorized under "Other," with distinct sub-clusters hitting high counts (e.g., 1.7K, 740, 571). The geographic clustering is heavily focused on the United States and Canada, reflecting the core operational regions of the organization.
* **Potential "Successful Travel" Risks:** Active, successful connections are plotting concurrently in Western Europe, South Africa, and East Asia (e.g., Japan/Philippines). If these successes match user accounts that are simultaneously logged into U.S. nodes, it flags an urgent **MFA Fatigue or Session Hijacking anomaly** where an attacker successfully bypassed security barriers from abroad.

---

### 3. Azure Resource Creation & Modifications
* **Log Source:** `AzureActivity` (OperationNameValue containing "write" or "action")
* **Objective:** Visualizes where and when infrastructure modifications occur.
* **Business Value:** Provides operational visibility into shadow IT, unauthorized resource provisioning, or configuration drift.

#### Visual Dashboard
<img width="1525" height="537" alt="image" src="https://github.com/user-attachments/assets/488b0ddb-39b9-4361-8114-7f10115f5941" />

#### The KQL Query
```kusto
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, 
          CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
          CallerIpAddress, 
          ResouceCreationCount, 
          Country = countryname, 
          Latitude = latitude, 
          Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)

```

### 📊 Dashboard Analysis & Key Findings

## 🔍 KQL Query Breakdown

* **Isolates Administrative Modifications:** Filters `AzureActivity` where `OperationNameValue endswith "WRITE"` and the `ActivityStatusValue` equals `"Success"` or `"Succeeded"` to isolate actual, completed infrastructure changes and deployments.
* **Excludes Non-Human Noise:** Uses custom regular expressions (`where not(Caller matches regex ... )`) to strip out automated system GUIDs and internal orchestrators, narrowing the scope down to named administrative users.
* **Enriches Location Data via Watchlist:** Uses the `evaluate ipv4_lookup` operator against a custom `GeoIPDB_FULL` watchlist to translate raw `CallerIpAddress` values into clean physical attributes (`Country`, `Latitude`, `Longitude`).

## 🗺️ Map Visualization & Legend Key

* **Threat Origins:** Bubbles pinpoint the physical or network location (IP geolocation) from which resource modifications or deployment actions are originating.
* **Bubble Size (Volume):** Larger bubbles correspond directly to a higher volume of successful modification logs (`ResourceCreationCount`).
* **Bubble Stacking (Density):** Heavily layered bubbles prove that a wide variety of unique user accounts (`Caller`) are altering or creating infrastructure from within the exact same regional network hub.
* **Color Coding Key:** * <span style="color:green">**Green Bubbles**</span>: Represent expected operational activity or low-density infrastructure changes stemming from standard corporate offices.
  * <span style="color:orange">**Orange/Red Bubbles**</span>: Highlight high-density traffic spikes or activities originating from outside typical working regions, indicating potential policy drift or rapid automated modifications.

## ⚠️ Key Security Anomalies Detected

* **The Australian Volumetric Outlier:** A single, isolated orange bubble stands out prominently over **Southeastern Australia (Sydney)**. The metrics bar confirms explicit activity from user `josh - Sydney, Australia` racking up **126 actions**, presenting a potential privilege abuse or automated script runaway anomaly outside the core North American boundary.
* **Northeastern U.S. Activity Cluster:** The dense, heavy concentration of overlapping green and orange bubbles in the Eastern United States highlights the primary center of resource creation. Because it contains the "Other" bucket of **4.51K events**, the map engine aggregates this massive localized cluster into a warning color layer due to raw deployment density.
* **Sparsely Distributed Global Changes:** Successful infrastructure writes are charting from sporadic locations including South Korea (`josh - Busan`), Madagascar, Brazil, and parts of Western Europe. These require immediate cross-referencing against approved travel records or localized DevOps sprints to ensure they do not represent unauthorized corporate configuration drift or malicious persistence.


**NOTE:** We had to handle the data in a completely different way using this query because the source data itself changed from unstructured identity text to structured network packets. When you look at the raw data coming into a SIEM, different log tables speak completely different "languages."
---

### 4. Virtual Machine (VM) Authentication Failures
* **Log Source:** `Syslog` (Linux) / `SecurityEvent` (Windows)
* **Objective:** Monitors brute-force SSH/RDP attempts targeting specific cloud infrastructure components.
* **Business Value:** Isolates vulnerable endpoints requiring stricter Network Security Group (NSG) rules or Just-In-Time (JIT) access.

#### Visual Dashboard
<img width="1029" height="424" alt="image" src="https://github.com/user-attachments/assets/cd0b99c6-2f64-4f45-ae2f-1b145e5bab37" />


#### The KQL Query
```
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;

```

### 📊 Dashboard Analysis & Key Findings
## 🔍 KQL Query Breakdown

* **Isolates Brute-Force Failures:** Filters the `DeviceLogonEvents` table for `where ActionType == "LogonFailed"` to exclusively focus on unsuccessful local or network device authentication attempts.
* **Chronological Sorting:** Uses `order by TimeGenerated desc` to ensure the most recent security events are processed prior to summary aggregation.
* **Enriches Telemetry via Watchlist:** Utilizes the `evaluate ipv4_lookup` operator against an external `GeoIPDB_FULL` watchlist to dynamically match the raw `RemoteIP` addresses to real-world attributes (`cityname`, `countryname`, `latitude`, `longitude`).
* **Flattens Data for Visualization:** Groups the results using `summarize LoginAttempts = count() by RemoteIP, City... Country...` to provide the map engine with exact physical coordinates paired with a concatenated string label (`friendly_location`).

---

## 🗺️ Map Visualization & Legend Key

* **Threat Origins:** Bubbles pinpoint the physical or network location (IP geolocation) from which the device login failures are originating.
* **Bubble Size (Volume):** Larger bubbles correspond directly to a higher volume of failed authentication events (`LoginAttempts`).
* **Bubble Stacking (Density):** Heavily layered bubbles prove that a wide variety of unique rogue `RemoteIP` addresses or targeted host devices are interacting within the exact same region.
* **Color Coding Key:** * <span style="color:green">**Green Bubbles**</span>: Represent isolated, low-volume credential friction or typical background brute-force noise across disparate global endpoints.
  * <span style="color:red">**Red/Yellow Bubbles**</span>: Highlight high-severity volumetric alerts or aggressive distributed clusters where accumulated logons exceed standard regional baselines.

---

## ⚠️ Key Security Anomalies Detected

* **The United States Red Zone Heatmap:** The most prominent visual anomaly is the dense, red-shaded cluster situated over the **Central/Eastern United States**. Even though individual location rows show double-digit attempts (e.g., Trenton at 19, Stamford at 25), the total regional aggregation triggers the volume heatmap scale, accounting for a massive chunk of the **1.33K "Other" events** bucket.
* **Highly Active Dutch Telemetry:** The background data table reveals a persistent threat actor footprint radiating out of **Leeuwarden, Netherlands**. Multiple distinct IP addresses (such as `91.92.40.217` with **202 attempts** and `91.92.40.50` with **40 attempts**) are targeting resources from this exact coordinate block, standing out as a high-velocity localized campaign.
* **Global Botnet Distribution:** Failed device logons are actively tracking from a highly distributed global network, hitting nodes in Taipei (33), Sydney (27), the United Kingdom (25), Russia, and South Korea (19). This footprint is indicative of an automated, coordinated credential-stuffing or password-spraying campaign leveraging a geographically diverse proxy network to find cracks in the perimeter.
---

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
