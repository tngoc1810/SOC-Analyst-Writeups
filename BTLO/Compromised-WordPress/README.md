# [Writeup] BTLO: Compromised WordPress - Log Analysis

## 📝 Challenge Information
*   **Platform:** Blue Team Labs Online (BTLO)
*   **Category:** Log Analysis
*   **Difficulty:** Medium
*   **Scenario:** One of our WordPress sites has been compromised but we're currently unsure how. The primary hypothesis is that an installed plugin was vulnerable to a remote code execution vulnerability which gave an attacker access to the underlying operating system of the server.

-------------
<img width="639" height="402" alt="image" src="https://github.com/user-attachments/assets/4aecf6a5-7bad-44b3-97ab-1f4311365f45" />

To get a grip on the traffic flow, I examined the first 10 entries of the log file:
head -n 10 access.log
Key Findings from access.log:

Timestamp: The captured activity initiates at 12/Jan/2021:15:52:41 +0000.

Source Identity: All initial requests originate from IP 172.21.0.1.

Note: As a SOC Analyst, I identified this as a Class B Private IP range (172.16.0.0 – 172.31.255.255), likely representing an internal Docker bridge or a local proxy.

User Agent Fingerprinting:
Mozilla/5.0 (X11; Linux x86_64; rv:78.0)

This indicates the attacker (or user) is operating from a Linux environment using Firefox 78.

Request Pattern: The logs show a series of GET requests for static assets (.css, .js) and PHP files, which is typical for a site's initial load.
<img width="1024" height="190" alt="image" src="https://github.com/user-attachments/assets/52606ec7-127d-467e-8ace-46ce47e60018" />
After analyzing the beginning of the logs, I focused on the end of the access.log file to identify the attacker's final actions and potential success.

Bash
Investigating the tail end of the access log for recent activity
tail -n 20 access.log
Observations:

Aggressive Fuzzing/Brute-forcing:
The logs exhibit a high frequency of 404 Not Found errors within a single second (07:46:42). The attacker is systematically probing for specific plugin and theme resources:

wp-content/plugins/contact-form-7/

wp-content/plugins/simple-file-list/

wp-content/themes/kadence/

Analyst Insight: This rapid-fire request pattern is a classic signature of an automated Directory Brute-forcing or Fuzzing attack, aiming to identify vulnerable entry points.

Discovery of a "Smoking Gun":
At the very end of the capture, we see a successful request that deviates from the standard WordPress structure:

Diff
- 172.21.0.1 ... "GET /adminlogin" 404
+ 172.21.0.1 ... [14/Jan/2021:07:46:52] "GET /YouShouldSeeThis.txt HTTP/1.1" 200 488
Evidence: The file YouShouldSeeThis.txt returned a Status Code 200 (OK) with a size of 488 bytes.

Interpretation: The provocative filename suggests this is either a "flag" left by an attacker to prove successful system compromise (Post-Exploitation) or a crucial piece of evidence in this investigation.

Extended Intrusion Timeline:
The investigation confirms that the activity spanned from January 12th to January 14th, indicating a multi-day operation.
<img width="796" height="531" alt="image" src="https://github.com/user-attachments/assets/7b9265d9-ae97-40e7-8179-78b0337736b4" />

To identify the primary threat actor, I performed a statistical analysis of all unique IP addresses communicating with the server. This helps filter out background noise and focus on high-volume, suspicious traffic.

Parsing the access log to count requests per unique IP, sorted by volume
cat access.log | awk '{print $1}' | sort | uniq -c | sort -nr

Key Observations:

Anomalous Volume: The IP 119.241.22.121 stands out as the most active external entity. In a WordPress environment, such high volume from a single external IP often correlates with automated scanning or brute-force attempts.

Internal Routing: The dominance of 172.21.0.1 confirms that the logs are being captured behind a gateway, meaning we must look at the specific request patterns (User Agents, URI paths) to distinguish between legitimate and malicious intent.


<img width="625" height="54" alt="image" src="https://github.com/user-attachments/assets/c05a3823-1757-462f-890d-8bd0c015cb6f" />

To ensure evidence integrity for further deep-dive analysis, I exported the sorted IP distribution to a dedicated text file.

Exporting suspicious IP data for forensic preservation
cat access.log | awk '{print $1}' | sort | uniq -c | sort -nr > IPS.txt


<img width="1024" height="269" alt="image" src="https://github.com/user-attachments/assets/5a2c5d3f-bff6-4524-882e-fcd03aeff5f8" />

By parsing the 6th field of the Apache logs, I identified highly suspicious patterns that confirm the use of automated tools and identity spoofing.

Extracting and counting unique User-Agents
cat access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -nr

Legacy Device Spoofing (Identity Deception):

iPhone (iOS 5_1): 188 requests.

Opera/9.00 (Windows NT 5.1) (Windows XP): 141 requests.

Analyst Insight: These are archaic versions from circa 2012. It is highly improbable for legitimate users to access a modern site with these versions in 2021. This confirms User-Agent Spoofing to bypass simple security filters.

Automated Exploitation Tools (The "Smoking Guns"):
The logs explicitly captured the signature of several well-known security scanning and exploitation frameworks:

python-requests/2.24.0: Indicates custom Python scripts used for direct interaction or payload delivery.

WPScan v3.8.10: A specialized vulnerability scanner for WordPress. This proves the attacker was actively looking for outdated plugins.

sqlmap/1.4.11: A powerful tool used to automate the detection and exploitation of SQL Injection vulnerabilities.


<img width="760" height="50" alt="image" src="https://github.com/user-attachments/assets/67ece36f-6be7-41a0-bf0f-15babb1c75d3" />

To facilitate a more focused forensic review and maintain a clean chain of custody for the investigation, I exported the parsed User-Agent data into a dedicated evidence file.

Exporting unique User-Agent strings to a text file for deep-dive analysis
cat access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -nr > user-agents.txt

<img width="1024" height="440" alt="image" src="https://github.com/user-attachments/assets/1751dbd7-5ba9-4d16-80e1-d8bc84bb770e" />

To move beyond reconnaissance and identify the actual breach, I filtered the logs for successful POST requests. By excluding 403 Forbidden responses, I isolated the actions that actually impacted the server.

Filtering for successful POST requests to identify malicious uploads or executions
grep "POST" access.log | grep -v "403"

Critical Findings & Analysis
The "Eureka" Moment - Malicious Plugin Upload:

HTTP
POST /wp-admin/update.php?action=upload-plugin HTTP/1.1" 200 6434
Observation: A successful POST request to the plugin upload handler.

Risk Assessment: This is the Initial Access vector. In WordPress environments, uploading a "malicious plugin" is a common technique to deploy a Web Shell, granting the attacker Remote Code Execution (RCE) over the underlying operating system.

Persistence via admin-ajax.php:

The logs show repeated successful POST requests to /wp-admin/admin-ajax.php.

Analysis: Attackers often abuse this file to maintain a connection (Persistence) or trigger background tasks without alerting the administrator.

Authentication Bypass / Authorized Session:

Internal IP Activity: As noted in the logs, requests are now appearing under the internal IP 172.21.0.1.

Conclusion: This indicates the attacker successfully authenticated (or bypassed authentication) and is now operating within an Authorized Session. They have moved past the network perimeter and are interacting directly with the WordPress core as an administrative user.

<img width="1024" height="494" alt="image" src="https://github.com/user-attachments/assets/889ffdf8-3c56-4d34-84eb-4a338e9e80c6" />

To pin down the exact mechanism of the breach, I performed a focused analysis of all successful POST requests, correlating source IPs with the targeted URIs.

Correlating Source IPs with POST requests to identify the entry point and Web Shell usage
grep "POST" access.log | grep -v "403" | awk '{print $1 " " $7}' | cut -d'?' -f1 | sort | uniq -c | sort -nr
Analysis of Malicious Indicators
The Web Shell Discovery:

Indicator: 103.69.55.212 -> /wp-content/uploads/simple-file-list/fr34k.php (9 requests).

Technical Breakdown: The /uploads/ directory is intended for media assets, not executable .php files. The filename "fr34k.php" (leetspeak for "freak") is a highly characteristic naming convention for hacker Web Shells.

Impact: These 9 POST requests represent the attacker interacting with the shell to execute arbitrary system commands (Remote Code Execution).

Identifying the Exploit Vector:

Indicator: 119.241.22.121 -> /wp-content/plugins/simple-file-list/ee-upload-engine.php.

Analysis: This log entry reveals the Initial Access phase. The primary suspect IP exploited a vulnerability within the Simple File List plugin's upload engine to bypass security checks.

Conclusion: The attacker leveraged ee-upload-engine.php to drop the fr34k.php payload into the uploads folder.

Attack Lifecycle Summary
Step 1 (Exploitation): IP 119.241.22.121 exploits the Simple File List plugin to upload a malicious file.

Step 2 (Command & Control): IP 103.69.55.212 connects to the newly uploaded fr34k.php to issue commands.

Step 3 (Post-Exploitation): High volume of POST requests to admin-ajax.php suggests automated scripts were used to maintain persistence.


<img width="890" height="42" alt="image" src="https://github.com/user-attachments/assets/642e2324-dccb-4f74-84cd-39f5b4e0ed59" />

To streamline the final analysis and provide a clear overview of the attack's impact, I categorized the successful POST traffic into two distinct forensic artifacts. This allows for a granular look at the "Who" and the "Where" of the intrusion.

Artifact A: Source IP Analysis for POST Requests
I isolated all IP addresses that successfully sent POST data to the server (excluding 403 Forbidden responses) to identify the most active threat actors.

grep "POST" access.log | grep -v "403" | awk '{print $1}' | sort | uniq -c | sort -nr > POST_IP.txt


<img width="1012" height="68" alt="image" src="https://github.com/user-attachments/assets/985b239d-31e0-4227-a9c6-c5931efc9463" />

Next, I extracted the specific endpoints targeted by these POST requests. By stripping out query parameters (using cut -d'?'), I obtained a clean list of the files and scripts involved in the breach.

Identifying the most targeted URI paths during the exploitation phase

grep "POST" access.log | grep -v "403" | awk '{print $7}' | cut -d'?' -f1 | sort | uniq -c | sort -nr > POST_URIpath.txt

POST_IP.txt: Highlights the Command & Control (C2) nodes and scanning IPs.

POST_URIpath.txt: Confirms the location of the Web Shell (fr34k.php) and the vulnerable plugin engines (ee-upload-engine.php).


<img width="289" height="191" alt="image" src="https://github.com/user-attachments/assets/a9d319a2-0f31-4ab8-be72-774b121e5a3b" />

<img width="802" height="605" alt="image" src="https://github.com/user-attachments/assets/25562c74-436a-49de-9a64-ce36510c02c4" />

Reputation checks are necessary but not definitive. I cross-referenced the high-volume POST IP 103.69.55.212 against public Threat Intel databases to determine its origin and known reputation.

External Reputation Check
Geolocation: Taipei, Taiwan.
ISP: Asia Pacific Network Information Centre (APNIC).


<img width="1642" height="876" alt="image" src="https://github.com/user-attachments/assets/f27206e4-e883-41a2-af79-ef048cb43281" />

VirusTotal/AbuseIPDB Result: 0/92 detections (Clean)
Since the IP had no public blacklists, I performed a Deep Dive into its specific behavior within our server logs to build a local profile of the threat.

Isolating all activities associated with the suspect IP for behavioral profiling
grep "103.69.55.212" access.log > suspect_activity.txt
cat suspect_activity.txt


<img width="1243" height="42" alt="image" src="https://github.com/user-attachments/assets/49ae10c0-eae4-457a-8d63-539706b0e8d2" />

Timestamp: 06:27:04. 

Status Code (200 OK): This is the highest level of alert. It confirms the file fr34k.php was alive, accessible, and correctly parsed by the web server.

Response Size (1295 bytes): This is not a blank page. The 1295 bytes represent the Web Shell Interface data sent from the server back to the attacker's browse

<img width="1225" height="56" alt="image" src="https://github.com/user-attachments/assets/d0df133d-20df-4cc5-8967-abf7d139ebc2" />

While the primary attack focused on the Simple File List plugin, the logs reveal that the attacker was simultaneously performing reconnaissance on other components to identify additional vulnerabilities.

Timestamp: 06:19:06. This occurred approximately 8 minutes before the verified execution of the fr34k.php Web Shell.

Target: contact-form-7/includes/css/styles.css?ver=5.3.1

Status Code: 200 OK

Tactical Analysis: Fingerprinting & Surface Expansion
Version Fingerprinting: By requesting specific CSS files, the attacker can extract the exact version number (ver=5.3.1) of installed plugins. This is a critical step in a targeted attack, as it allows the actor to search for specific CVEs (Common Vulnerabilities and Exposures) associated with that version.

Attack Surface Expansion: The suspect IP (103.69.55.212) was not just focused on the Web Shell; they were actively probing the Contact Form 7 plugin to see if it offered an alternative entry point or a way to escalate privileges.

Methodical Approach: This behavior shows that the threat actor is not an amateur. They are systematically mapping the server's internal environment to ensure persistence and discover all possible "open doors."

During the analysis, I identified that the attacker was probing two major WordPress plugins. Based on the logs and the version fingerprinting discovered earlier, the following CVEs are the most likely candidates for the exploit:

A. CVE-2020-8380: Simple File List (RCE)
This is the confirmed entry point used in this lab.

Root Cause: The ee-upload-engine.php script failed to implement a "Strict Allowlist" for file extensions.

Exploitation Technique: The attacker bypassed upload filters to plant fr34k.php directly into the /wp-content/uploads/simple-file-list/ directory.

Impact: Full Remote Code Execution (RCE).

B. CVE-2020-35489: Contact Form 7 (Unrestricted File Upload)
This was the secondary target identified during the fingerprinting phase (detected version 5.3.1).

Nature: Versions prior to 5.3.2 contained a flaw where filenames were not properly sanitized during the upload process.

Technique: Attackers could use double extensions (e.g., shell.php .jpg) or special characters to trick the server into executing the file as a PHP script.

Significance: Even though the attacker successfully used the Simple File List exploit, this vulnerability served as their "Plan B".

The investigation concludes that the WordPress site was compromised due to outdated and vulnerable plugins. The attacker followed a classic "Cyber Kill Chain" from reconnaissance to remote command execution.

To determine if the attacker moved beyond version fingerprinting, I isolated all successful POST requests directed at the Contact Form 7 (CF7) plugin.

Filtering for successful POST requests targeting Contact Form 7
grep "contact-form-7" access.log | grep "POST" | grep -v "403"

<img width="1024" height="271" alt="image" src="https://github.com/user-attachments/assets/1d3df51e-5c21-4d5b-96e5-0457f69feb1d" />

Target Endpoint: POST /wp-json/contact-form-7/v1/contact-forms/7/feedback

This is the standard REST API endpoint used by CF7 to process form submissions.

Status Code (200 OK): All requests were successfully accepted by the server, indicating that the API was active and responding to the attacker's payloads.

Rapid Timeline (06:20:04 - 06:20:38): The logs record multiple requests within a brief 34-second window.

Analyst Insight: This high-frequency pattern is a definitive marker of an Automated Exploit Tool. The attacker was likely using a script to cycle through various payloads to find a bypass for file upload restrictions.

Correlation with CVE-2020-35489
The attempts on the /feedback endpoint align perfectly with the exploitation of CVE-2020-35489 (Unrestricted File Upload). By submitting POST requests to this form, the attacker tried to leverage the attachment functionality to upload a malicious shell, mirroring their successful strategy with the Simple File List plugin.


<img width="1024" height="430" alt="image" src="https://github.com/user-attachments/assets/7adc9b79-7160-480a-9482-2e038c686320" />

The logs reveal a coordinated attack divided into two distinct functional stages: Delivery and Command Execution.

Isolating the full exploit chain for Simple File List
grep "simple-file-list" access.log | grep "POST" | grep -v "403"

Stage 1: Initial Access (Exploitation & Installation)
Source IP: 119.241.22.121

Timestamp: 06:26:53

Activity: A POST request was sent to /wp-content/plugins/simple-file-list/ee-upload-engine.php.

Tooling: The User-Agent python-requests/2.24.0 confirms the use of an automated Python exploit script specifically designed to bypass the plugin's upload restrictions.

Result: This single request successfully "dropped" the malicious payload (fr34k.php) onto the server.

Stage 2: Remote Code Execution (Command & Control)
Source IP: 103.69.55.212 (The primary suspect tracked to Taiwan).

Timeline: Starting at 06:27:06 (just 13 seconds after the upload).

Activity: Continuous POST requests targeting /wp-content/uploads/simple-file-list/fr34k.php.

Technical Impact: Each subsequent POST represents the attacker interacting with the Web Shell interface to execute OS-level commands. This includes directory traversal, file modification, or establishing further persistence through backdoors.


<img width="1023" height="494" alt="image" src="https://github.com/user-attachments/assets/dedf606a-9d3e-45cc-a8c0-16074c0e85be" />

Before discovering the RCE vulnerability, the logs show the attacker spent significant effort attempting to breach the "front door"—the administrative login page.

Detailed Log Analysis (Referencing image_3c812c.jpg):

Target: POST /wp-login.php?itsec-hb-token=adminlogin

Methodology (Brute Force/Credential Stuffing): Between 05:54 and 06:01, the attacker issued a high volume of POST requests to the login page.

Identifying Security Controls: The parameter itsec-hb-token=adminlogin indicates the use of a security plugin (likely iThemes Security) designed to hide the backend login URL. However, the attacker successfully identified or guessed the "Hide Backend" token.

Defensive Success: All these attempts resulted in a 403 Forbidden status code. This suggests the security plugin successfully blocked the attempts, likely due to an IP lockout or failed credential threshold.

Timeline of the Strategic Pivot
05:54 - 06:01: Sustained Brute Force attack on the login page (Failed with 403).

06:01:41: The attacker deployed WPScan v3.8.10 to perform a comprehensive vulnerability scan of the entire site.

06:26:53: Having failed at the login page, the attacker pivoted to exploit the Simple File List upload engine (ee-upload-engine.php), which resulted in a 200 OK and successful compromise.

<img width="489" height="495" alt="image" src="https://github.com/user-attachments/assets/a832893a-bcb1-4ade-a3ba-d012d6616924" />

The initial exploitation requests originated from IP 119.241.22.121. A deep-dive reputation check reveals that this is not a typical data center or VPN IP, suggesting a more sophisticated approach to network camouflage.

Intelligence Data (Referencing image_3c8033.png):

Country: Japan (Nagano)

ISP: BIGLOBE Inc. (A major Japanese consumer Internet Service Provider)

Hostname: FL1-119-241-22-121.ngn.mesh.ad.jp

Reputation: The IP was not found in existing abuse databases at the time of the lookup.

<img width="1260" height="68" alt="image" src="https://github.com/user-attachments/assets/5200e627-d1cf-4539-8908-ae7b8b2ccca6" />


<img width="1238" height="85" alt="image" src="https://github.com/user-attachments/assets/e26de18f-8eee-42ad-b0b9-7a01da427e2e" />

To complete the investigation, I traced the logs back to the initial setup to identify when these vulnerabilities were first introduced into the environment. This Root Cause Analysis reveals that the security gap was created during the initial configuration of the website.

Final Reconstruction: The Attack Lifecycle
1. Preparation Phase: The Genesis of Vulnerability
The security gap was not a result of a system failure but an authorized configuration error. On January 12th, an administrator (IP 172.21.0.1) inadvertently activated two plugins with critical Remote Code Execution (RCE) flaws:

15:56:41 UTC: simple-file-list activated (Affected versions: < 2.0 / CVE-2020-8380).

15:57:07 UTC: contact-form-7 activated (Affected versions: <= 5.3.1 / CVE-2020-35489).

2. Exploitation Phase: January 14th
The threat actor initiated a coordinated multi-vector attack from residential infrastructure in Japan and Taiwan.

05:42:34 UTC: Initial Reconnaissance begins from IP 119.241.22.121 (Japan). The attacker uses User-Agent spoofing to crawl file paths and probe the vulnerable plugins.

05:54:14 UTC: Attacker identifies the hidden login token adminlogin. They attempt a Brute Force attack on wp-login.php?itsec-hb-token=adminlogin but are thrashed by a 403 Forbidden response.

06:01:41 UTC: Following the failed login, the attacker pivots to WPScan to perform a comprehensive vulnerability assessment.

06:08:31 UTC: A second IP, 103.69.55.212 (Taiwan), joins the operation to expand the attack surface.

06:26:53 UTC: Initial Access achieved. The Japanese IP exploits CVE-2020-8380 via python-requests to upload the malicious payload fr34k.php.

3. Execution & Post-Exploitation
06:27:04 UTC: Payload Execution. The Taiwanese IP (103.69.55.212) triggers the Web Shell, receiving a 1295-byte response representing the active command-and-control (C2) interface.

06:30:11 UTC: Final recorded activity from the C2 IP.

## 🕵️ Answers
1. Identify the URI of the admin login panel that the attacker gained access to (include the token)
Answer: /wp-login.php?itsec-hb-token=adminlogin

Reasoning: The attacker performed a brute-force attack on this specific URI between 05:54 and 06:01 UTC. The parameter itsec-hb-token=adminlogin was used to bypass the "Hide Backend" security feature.

2. Can you find two tools the attacker used?
Answer: WPScan and sqlmap

Reasoning:

WPScan v3.8.10 was identified in the User-Agent strings at 06:01:41 UTC during the vulnerability scanning phase.

sqlmap/1.4.11 was also detected in the User-Agent logs, indicating attempts to exploit SQL Injection vulnerabilities.

3. The attacker tried to exploit a vulnerability in ‘Contact Form 7’. What CVE was the plugin vulnerable to?
Answer: CVE-2020-35489

Reasoning: This is an Unrestricted File Upload vulnerability affecting Contact Form 7 versions prior to 5.3.2. The logs showed the attacker (IP 103.69.55.212) sending multiple POST requests to the /feedback endpoint in an attempt to leverage this flaw.

4. What plugin was exploited to get access?
Answer: Simple File List

Reasoning: The attacker successfully exploited CVE-2020-8380 in the Simple File List plugin (versions < 2.0). Specifically, they targeted the ee-upload-engine.php script to bypass upload restrictions.

5. What is the name of the PHP web shell file?
Answer: fr34k.php

Reasoning: After exploitation, a malicious PHP file named fr34k.php was found in the /wp-content/uploads/simple-file-list/ directory. The attacker interacted with this shell to execute remote commands.

6. What was the HTTP response code provided when the web shell was accessed for the final time?
Answer: 200 (OK)

Reasoning: The final recorded interaction with the web shell at 06:27:04 UTC returned a Status Code 200, confirming that the shell was active and successfully executed the attacker's request, returning 1295 bytes of data.

---
**Author:** Nguyen Thai Ngoc
**Role:** Aspiring SOC Analyst | KMA Student
