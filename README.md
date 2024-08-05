# Basic Home Lab setup

## Objective

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

And made sure they can talk to each other 
![image](https://github.com/user-attachments/assets/7b6bf5ff-e92a-4f08-95be-87707648944b)



## Attack Scenarios

### Nmap Scan

Ran a Nmap scan to check for open ports on the Kali machine

![image](https://github.com/user-attachments/assets/cf06cef7-7778-441a-8c75-856fc1bdc610)


### Creating and Deploying Malware

For this exercise I used msfvenom

![image](https://github.com/user-attachments/assets/a27f064c-bab8-4f86-881d-6352dbc2bf90)

Looked at the available payloads 

![image](https://github.com/user-attachments/assets/d00d6daf-004b-46e9-afff-a19a4d143b1b)

And decidet to use meterpreter_reverse_tcp for this exercise

![image](https://github.com/user-attachments/assets/4c785ba3-6609-436d-990d-a8e03608bc0c)



### Setting Up Metasploit Handler

Opened Metasploit 

![image](https://github.com/user-attachments/assets/23c792eb-189b-43f5-b440-99ff1676c3ac)
Set up a reverse tcp, and changed the host to the attacking host and .... let it rip 
![image](https://github.com/user-attachments/assets/b5d4c90c-3210-4f4e-9e0d-99cbc3e59a26)

![image](https://github.com/user-attachments/assets/13f881a3-80c5-4844-9c37-87b388d5c635)

Then run to the windows machine to install the malware
![image](https://github.com/user-attachments/assets/b72bcd45-d5ba-42e1-9411-b34db6c8bd1e)

Then check if it's actually working

![image](https://github.com/user-attachments/assets/cff90ba8-970a-4583-a280-3bb30f133072)


### Splunk Setup

Steps to set up Splunk and configure it to ingest Sysmon logs, using MyDFIR's help.

### Analyzing Generated Telemetry

Next step looking at Splunk to see if we can actually read some commands that I've put in Kali. 
I've isolated the event by looking at the EventCode and taking the process_guid id and putting that in my search bar. 
After I got the results I've aranged them in a table to show me the ParentImage and the CommandLine

![image](https://github.com/user-attachments/assets/292024a2-6542-438a-85fe-b193fc525904)



I know this is an easy set up, but it took me a few tries to get it right. 

I would like to give a big thanks to MyDFIR on YouTube for helping me go through this 
https://www.youtube.com/watch?v=-8X7Ay4YCoA&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=6&ab_channel=MyDFIR
He's got a more detailed step by step process. 
