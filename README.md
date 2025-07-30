# Detailed Project Summary: AD Infrastructure Mapping, Log Analysis, and Attack Simulations

![image alt](https://raw.githubusercontent.com/DEENSec/Cyber_Project_ActiveDirectory_Security-Attack-Detect-analyze/refs/heads/main/AD_Securtiy.png)

## Project Link : https://medium.com/@deensec/ad-infrastructure-mapping-log-analysis-and-attack-simulations-strengthening-edr-security-7c02fd3a3748
## Overview
This project is designed to enhance the security of an Active Directory (AD) environment by simulating real-world cyber attacks, analyzing system logs, and mapping AD infrastructure to identify vulnerabilities. By leveraging tools like BloodHound, Wazuh, Sysmon, Atomic Red Team, and BlueSpawn, the project provides a comprehensive approach to understanding and improving endpoint detection and response (EDR) capabilities in a controlled lab environment. The setup simulates attacker behavior, monitors system activities, and identifies potential weaknesses in AD configurations, enabling proactive security enhancements.
For the full article, refer to: AD Infrastructure Mapping, Log Analysis, and Attack Simulations.

## Project Objectives

Simulate Real-World Attacks: Use tools like Atomic Red Team and Kali Linux to replicate common and advanced attack techniques, such as SSH brute-force attacks and credential dumping with Mimikatz.
Monitor and Analyze Logs: Deploy Wazuh and Sysmon for real-time log collection and analysis to detect malicious activities and authentication events.
Map AD Infrastructure: Utilize BloodHound to visualize AD relationships, identify misconfigurations, and uncover potential privilege escalation paths.
Enhance EDR Capabilities: Test Wazuh’s detection capabilities against MITRE ATT&CK techniques, identify gaps, and create custom detection rules to improve security.
Proactive Security Hardening: Strengthen the AD environment by addressing vulnerabilities and misconfigurations identified through simulations and analysis.

## Architecture and Lab Setup

The lab environment is composed of five virtual machines (VMs) designed to simulate a realistic enterprise AD setup:

### Active Directory Server (Windows Server VM)

Role: Domain controller hosting AD, DNS, and Group Policy.
Purpose: Simulates a corporate AD environment for user management, authentication, and policy enforcement.
Configuration: Configured with organizational units (OUs), users, and Group Policy Objects (GPOs) to mimic a production environment.


### Windows 10 Client VM

Role: Domain-joined workstation.
Purpose: Acts as an endpoint for user interactions, attack simulations, and log collection.
Configuration: Joined to the AD domain, with Sysmon and Wazuh agents installed for monitoring.


### Kali Linux VM (Attack Machine)

Role: Adversary simulation platform.
Purpose: Executes attack techniques such as SSH brute-force (via Metasploit) and credential dumping (via Mimikatz).
Tools: Metasploit Framework, Mimikatz, and SharpHound for AD data collection.


### Ubuntu VM (Security Analyst Machine)

Role: Security monitoring and analysis hub.
Purpose: Hosts BloodHound for AD mapping and serves as the analysis platform for reviewing logs and attack data.
Tools: BloodHound Community Edition, Docker, and log analysis tools.


### Wazuh Server VM (Ubuntu)

Role: Centralized log collection and EDR platform.
Purpose: Collects and analyzes logs from Sysmon and Wazuh agents installed on the AD server and Windows 10 client.
Configuration: Configured with custom rules for enhanced AD security monitoring.



## Network Configuration

The AD server acts as the DNS server, with the Windows 10 client configured to use the AD server’s IP for DNS resolution.
All VMs are interconnected in a virtual network, allowing communication for attack simulation, log collection, and analysis.
The Kali Linux VM operates as an external attacker, while the Ubuntu and Wazuh VMs focus on monitoring and defense.

## How It Works

The project follows a structured workflow to simulate, detect, and mitigate threats in the AD environment:

### AD Environment Setup

The Windows Server VM is configured as a domain controller, with users, OUs, and GPOs created to simulate a realistic AD setup.
The Windows 10 client is joined to the AD domain, enabling user-based attack simulations and policy enforcement.


### Log Collection and Monitoring

### Sysmon Installation: 
Sysmon is installed on both the AD server and Windows 10 client with a custom configuration (downloaded from Wazuh’s resources) to capture detailed system events, such as process creation and network activity.

### Wazuh Deployment: 
The Wazuh server is installed on an Ubuntu VM, and Wazuh agents are deployed on the AD server and Windows 10 client. The agents collect Sysmon logs and forward them to the Wazuh server for analysis.

### Log Analysis:
Wazuh’s dashboard is used to visualize logs, filter events (e.g., Windows Event IDs 4624 for successful logins and 4625 for failed logins), and detect suspicious activities.


### Attack Simulations

SSH Brute-Force Attack: The Kali Linux VM uses Metasploit to launch an SSH brute-force attack against the Windows 10 client, testing authentication defenses and logging capabilities.
Mimikatz Credential Dumping: Mimikatz is executed on the Windows 10 client to dump credentials from system memory, simulating a post-exploitation attack.
Atomic Red Team and BlueSpawn: Atomic Red Team simulates MITRE ATT&CK techniques (e.g., privilege escalation, lateral movement), while BlueSpawn monitors and detects these activities, providing detailed alerts and attack paths.


### AD Mapping with BloodHound

SharpHound is executed on the Windows 10 client to collect AD data in JSON format.
The data is imported into BloodHound (running on the Ubuntu VM) to map AD relationships, identify domain admin paths, and uncover misconfigurations or privilege escalation opportunities.


### EDR Enhancement

Attack simulations reveal gaps in Wazuh’s detection capabilities.
Custom Wazuh rules are created to address undetected MITRE ATT&CK techniques, improving the EDR’s ability to flag sophisticated threats.



## Tools and Technologies

BloodHound: Maps AD relationships and identifies attack paths using SharpHound for data collection.
Wazuh: Centralized EDR platform for log collection, analysis, and threat detection.
Sysmon: Provides detailed system event logging for Windows-based machines.
Atomic Red Team: Simulates MITRE ATT&CK techniques to test EDR capabilities.
BlueSpawn: Monitors and detects simulated attacks, providing insights into attack paths and behaviors.
Metasploit Framework: Executes SSH brute-force attacks.
Mimikatz: Dumps credentials for post-exploitation analysis.
Docker: Used to deploy BloodHound Community Edition on the Ubuntu VM.

## Future Implementations
To expand and improve this project, the following enhancements could be considered:

Advanced Attack Scenarios: Incorporate more complex MITRE ATT&CK techniques, such as persistence mechanisms or advanced lateral movement, to further test EDR capabilities.
Automated Rule Generation: Develop scripts to automate the creation of Wazuh detection rules based on attack simulation outputs, reducing manual effort.
Integration with SIEM Solutions: Combine Wazuh with a Security Information and Event Management (SIEM) system for broader visibility and correlation of security events across multiple environments.
Cloud-Based AD Testing: Extend the lab to include Azure AD or other cloud-based directory services to simulate hybrid environments.
Machine Learning for Anomaly Detection: Integrate machine learning models into Wazuh to detect anomalous behaviors that may not be covered by predefined rules.
Scalability: Expand the lab to include multiple AD domains or forests to simulate larger enterprise environments and test cross-domain attacks.

## Key Outcomes

Improved Detection: The project identifies gaps in Wazuh’s detection capabilities and enhances its ruleset, resulting in a more robust EDR solution.
Proactive Vulnerability Management: BloodHound’s AD mapping uncovers misconfigurations and privilege escalation paths, allowing for preemptive hardening of the AD environment.
Realistic Attack Insights: Simulated attacks provide a deeper understanding of adversary tactics, enabling better preparation for real-world threats.
Enhanced Monitoring: Sysmon and Wazuh provide comprehensive visibility into system activities, improving incident detection and response.

## Conclusion
This project demonstrates a practical approach to strengthening AD security through attack simulation, log analysis, and infrastructure mapping. By simulating real-world threats, monitoring system activities, and identifying vulnerabilities, the setup provides actionable insights for improving EDR capabilities and securing AD environments. The combination of offensive and defensive tools creates a robust framework for testing and enhancing enterprise security.
For a detailed walkthrough, including setup instructions and tool configurations, refer to the full article: https://medium.com/@deensec/ad-infrastructure-mapping-log-analysis-and-attack-simulations-strengthening-edr-security-7c02fd3a3748
