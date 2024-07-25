# PROJECTNAME

## Objective
[Brief Objective - Remove this afterwards]

The Basic Home Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

- Setting up and configuring virtual machines (Kali Linux and Windows)
- Using Nmap for network scanning
- Creating malware with msfvenom
- Configuring and using Metasploit for reverse shells
- Disabling antivirus and executing malware on Windows
- Setting up and using Splunk for telemetry analysis
- Generating and analyzing telemetry data

### Tools Used

- [VirtualBox](https://www.virtualbox.org/) - Virtualization software
- [Kali Linux](https://www.kali.org/) - Penetration testing OS
- [Windows 10](https://www.microsoft.com/en-us/software-download/windows10) - Target OS
- [Nmap](https://nmap.org/) - Network scanner
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom) - Payload generator
- [Splunk](https://www.splunk.com/) - Log management and analysis
- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System monitoring tool

## Steps

## Lab Setup

### Kali Linux Installation

There are many videos out there on how to do this. 

### Windows Installation

This should be fairly simple. 

### VM Configuration

I've asigned a new network adapter to both VM's so they can talk to each othre 
![image](https://github.com/user-attachments/assets/40d54ef7-987f-4b76-ad54-b5f280acf0a2)

Took notes of each machines ip address
![image](https://github.com/user-attachments/assets/28175b72-a46b-4681-96c9-e440d769e413)

And make sure they can talk to each other 
![image](https://github.com/user-attachments/assets/7b6bf5ff-e92a-4f08-95be-87707648944b)



## Attack Scenarios

### Nmap Scan

Ran a Nmap scan to check for open ports on the Kali machine
![image](https://github.com/user-attachments/assets/4c2174a6-2a7a-4d86-9b1f-b315ab6ef402)


### Creating and Deploying Malware

For this exercise I used msfvenom
![image](https://github.com/user-attachments/assets/a27f064c-bab8-4f86-881d-6352dbc2bf90)

Looked at the available payloads 
![image](https://github.com/user-attachments/assets/d00d6daf-004b-46e9-afff-a19a4d143b1b)

And decidet to use meterpreter_reverse_tcp for this exercise

![image](https://github.com/user-attachments/assets/4c785ba3-6609-436d-990d-a8e03608bc0c)




### Setting Up Metasploit Handler

Instructions on setting up Metasploit Handler to listen for the reverse shell connection. Detailed instructions [here](attack-scripts/metasploit-handler.md).

## Telemetry Analysis

### Splunk Setup

Steps to set up Splunk and configure it to ingest Sysmon logs. Detailed instructions [here](telemetry-analysis/splunk-setup.md).

### Analyzing Generated Telemetry

Guide on how to analyze the telemetry data generated from the attack scenarios. Detailed instructions [here](telemetry-analysis/telemetry-analysis.md).




I would like to give a big thanks to MyDFIR on YouTube for helping me go through this 
https://www.youtube.com/watch?v=-8X7Ay4YCoA&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=6&ab_channel=MyDFIR
