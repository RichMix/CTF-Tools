# NetworkMiner
is an open-source traffic sniffer, PCAP handler and protocol analyser. Developed and still maintained by Netresec.
[NetMiner by NetSec](https://www.netresec.com/?page=NetworkMiner)

 
The official description:

"NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). 
NetworkMiner can be used as a passive network sniffer/packet capturing tool to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. 
NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.

 

NetworkMiner has, since the first release in 2007, become a popular tool among incident response teams as well as law enforcement. 
NetworkMiner is today used by companies and organizations all over the world."

## Supported Data Types
There are three main data types investigated in Network Forensics

- Live Traffic
- Traffic Captures
- Log Files

# NetworkMiner in a Nutshell

| Capability | Description |
|------------|-------------|
| Traffic sniffing | It can intercept the traffic, sniff it, and collect and log packets that pass through the network. |
| Parsing PCAP files | It can parse pcap files and show the content of the packets in detail. |
| Protocol analysis | It can identify the used protocols from the parsed pcap file. |
| OS fingerprinting | It can identify the used OS by reading the pcap file. This feature strongly relies on Satori and p0f. |
| File Extraction | It can extract images, HTML files and emails from the parsed pcap file. |
| Credential grabbing | It can extract credentials from the parsed pcap file. |
| Clear text keyword parsing | It can extract cleartext keywords and strings from the parsed pcap file. |

We are using NetworkMiner free edition in this room, but a Professional edition has much more features. 
You can see the differences between free and professional versions [here](https://www.netresec.com/?page=NetworkMiner).

## Operating Modes

There are two main operating modes;

- Sniffer Mode: Although it has a sniffing feature, it is not intended to use as a sniffer. The sniffier feature is available only on Windows. However, the rest of the features are available in Windows and Linux OS. Based on experience, the sniffing feature is not as reliable as other features. Therefore we suggest not using this tool as a primary sniffer. Even the official description of the tool mentions that this tool is a "Network Forensics Analysis Tool", but it can be used as a "sniffer". In other words, it is a Network Forensic Analysis Tool with but has a sniffer feature, but it is not a dedicated sniffer like Wireshark and tcpdump. 
- Packet Parsing/Processing: NetworkMiner can parse traffic captures to have a quick overview and information on the investigated capture. This operation mode is mainly suggested to grab the "low hanging fruit" before diving into a deeper investigation.


## Pros and Cons
 
As mentioned in the previous task, NetworkMiner is mainly used to gain an overview of the network. 
Before starting to investigate traffic data, let's look at the pros and cons of the NetworkMiner.

### Pros
- OS fingerprinting
- Easy file extraction
- Credential grabbing
- Clear text keyword parsing
- Overall overview

## Cons
- Not useful in active sniffing
- Not useful for large pcap investigation
- Limited filtering
- Not built for manual traffic investigation

### Differences Between Wireshark and NetworkMiner
NetworkMiner and Wireshark have similar base features, but they separate in use purpose. 
Although main functions are identical, some of the features are much stronger for specific use cases.
#### The best practice is to record the traffic for offline analysis, quickly overview the pcap with NetworkMiner and go deep with Wireshark for further investigation.

| Feature | NetworkMiner | Wireshark |
|---------|--------------|-----------|
| Purpose |	Quick overview, traffic mapping, and data extraction | In-Depth analysis |
| GUI	✅ | ✅ |
| Sniffing | ✅ | ✅ |
| Handling PCAPS | ✅ | ✅ |
| OS Fingerprinting |	✅ | ❌ |
| Parameter/Keyword Discovery |	✅ | Manual |
| Credential Discovery	✅ | ✅ |
| File Extraction |	✅ | ✅ |
| Filtering Options |	Limited | ✅ | 
| Packet Decoding |	Limited | ✅ |
| Protocol Analysis	| ❌ | ✅ |
| Payload Analysis	| ❌ | ✅ |
| Statistical Analysis	| ❌ | ✅ |
| Cross-Platform Support	| ✅ | ✅ |
| Host Categorisation	| ✅ | ❌ |
| Ease of Management 	| ✅ | ✅ |

# Landing Page

This is the landing page of the NetworkMiner. Once you open the application, this screen loads up. 


## File Menu

The file menu helps you load a Pcap file or receive Pcap over IP. You can also drag and drop pcap files as well. 

NetworkMiner also can receive Pcaps over IP. This room suggests using NetworkMiner as an initial investigation tool for low hanging fruit grabbing and traffic overview. Therefore, we will skip receiving Pcaps over IP in this room. You can read on receiving Pcap over IP from here and here. 

## Tools Menu

The tools menu helps you clear the dashboard and remove the captured data. 

## Help Menu

The help menu provides information on updates and the current version. 

## Case Panel

The case panel shows the list of the investigated pcap files. You can reload/refresh, view metadata details and remove loaded files from this panel.

Viewing metadata of loaded files;

### Hosts
The "hosts" menu shows the identified hosts in the pcap file. 

This section provides information on;
- IP address
- MAC address
- OS type
- Open ports
- Sent/Received packets
- Incoming/Outgoing sessions
- Host details
- OS fingerprinting uses the Satori GitHub repo and p0f, and the MAC address database uses the mac-ages GitHub repo.

You can sort the identified hosts by using the sort menu. You can change the colour of the hosts as well. 
Some of the features (OSINT lookup) are available only in premium mode. 
The right-click menu also helps you to copy the selected value.


### Sessions
The session menu shows detected sessions in the pcap file. 

This section provides information on;
- Frame number
- Client and server address
- Source and destination port
- Protocol
- Start time

You can search for keywords inside frames with the help of the filtering bar. It is possible to filter specific columns of the session menu as well. 

This menu accepts four types of inputs;

"ExactPhrase"
"AllWords"
"AnyWord"
"RegExe"

## DNS

The DNS menu shows DNS queries with details. 

This section provides information on;
- Frame number
- Timestamp
- Client and server
- Source and destination port 
- IP TTL
- DNS time
- Transaction ID and type
- DNS query and answer
- Alexa Top 1M
- 
Some of the features (Alexa Top 1M) are available only in premium mode. The search bar is available here as well.

## Credentials

The credentials menu shows extracted credentials and password hashes from investigated pcaps. 
You can use Hashcat (GitHub) and John the Ripper (GitHub) to decrypt extracted credentials. 

NetworkMiner can extract credentials including;
- Kerberos hashes
- NTLM hashes
- RDP cookies
- HTTP cookies
- HTTP requests
- IMAP
- FTP
- SMTP
- MS SQL

The right-click menu is helpful in this part as well. 
You can easily copy the username and password values.

## Files

The file menu shows extracted files from investigated pcaps. 

This section provides information on;
- Frame number
- Filename
- Extension
- Size
- Source and destination address
- Source and destination port
- Protocol
- Timestamp
- Reconstructed path
- Details

Some features (OSINT hash lookup and sample submission) are available only in premium mode. 
The search bar is available here as well. The right-click menu is helpful in this part as well. 
You can easily open files and folders and view the file details in-depth.


## Images
The file menu shows extracted images from investigated pcaps. 
- The right-click menu is helpful in this part as well. 
- You can open files and zoom in & out easily.
- Once you hover over the image, it shows the file's detailed information (source & destination address and file path).

## Parameters

The file menu shows extracted parameters from investigated pcaps. 

This section provides information on;
- Parameter name
- Parameter value
- Frame number
- Source and destination host
- Source and destination port
- Timestamp
- Details

The right-click menu is helpful in this part as well. You can copy the parameters and values easily.

## Keywords

The file menu shows extracted keywords from investigated pcaps. 

This section provides information on;
- Frame number
- Timestamp
- Keyword
- Context
- Source and destination host
- source and destination port
- How to filter keywords;

### Add keywords
Reload case files!
#### Note: You can filter multiple keywords in this section; however, you must reload the case files after updating the search keywords. 
Keyword search investigates all possible data in the processed pcaps.


## Messages
The messages menu shows extracted emails, chats and messages from investigated pcaps. 

This section provides information on;
- Frame number
- Source and destination host 
- Protocol
- Sender (From)
- Receiver (To)
- Timestamp
- Size
- Once you filter the traffic and get a hit, you will discover additional details like attachments and attributes on the selected message. 

#### Note that the search bar is available here as well. The right-click menu is available here. You can use the built-in viewer to investigate overall information and the "open file" option to explore attachments.



## Anomalies
The anomalies menu shows detected anomalies in the processed pcap. 
#### Note that NetworkMiner isn't designated as an IDS. 
- However, developers added some detections for EternalBlue exploit and spoofing attempts.

# Version Differences
As always, it wouldn't be surprising to see a feature improvement as the version goes up. Unsurprisingly version upgrades provide stability, security fixes and features. Here the feature part is quite tricky. Feature upgrades can represent implementing new features and updating the existing feature (optimisation, alteration or operation mode modification). You can always check the changelog here .

Since there are some significant differences between the versions, the given VM has both of the major versions (v1.6 and v2.7). Of course, as the program version increases, it is expected to increase feature increase and scope. Here are the significant differences between versions 1.6 and 2.7. Here are the differences;

### Mac Address Processing   
NetworkMiner versions after version 2 can process MAC address specific correlation as shown in the picture below. 
- This option will help you identify if there is a MAC Address conflict.
- This feature is not available before version 2.
 
NetworkMiner versions up to version 1.6. can handle packets in much detail. These options will help you investigate the sent/received packets in a more detailed format. This feature is not available after version 1.6.

### Frame Processing
NetworkMiner versions up to version 1.6. can handle frames. 
- This option provides the number of frames and essential details about the frames.
- This feature is not available after version 1.6.

### Parameter Processing
NetworkMiner versions after version 2 can handle parameters in a much more extensive form. 
- Therefore version 1.6.xx catches fewer parameters than version 2.     

### Cleartext Processing
NetworkMiner versions up to version 1.6. can handle cleartext data. 
- his option provides all extracted cleartext data in a single tab; it is beneficial to investigate cleartext data about the traffic data. 

#### However, it is impossible to match the cleartext data and packets. This feature is not available after version 1.6.    


