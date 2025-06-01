#### This repo will cover investigating packet-level details by synthesising the analyst knowledge and  Wireshark functionality for detecting anomalies and odd situations for a given case. // THM-Notes

# Nmap Scans

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. 
As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

TCP connect scans
SYN scans
UDP scans
It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network. 

TCP flags in a nutshell.

| Purpose                           | Display filter                                                                                                        |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **All TCP traffic**               | `tcp`                                                                                                                 |
| **All UDP traffic**               | `udp`                                                                                                                 |
| **SYN only**<br>(handshake start) | `tcp.flags.syn == 1 && tcp.flags.ack == 0`<br>*(hex)* `tcp.flags == 0x02`                                             |
| **ACK only**                      | `tcp.flags.ack == 1 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.flags.rst == 0`<br>*(hex)* `tcp.flags == 0x10` |
| **SYN-ACK**                       | `tcp.flags.syn == 1 && tcp.flags.ack == 1`<br>*(hex)* `tcp.flags == 0x12`                                             |
| **RST only**                      | `tcp.flags.reset == 1 && tcp.flags.ack == 0`<br>*(hex)* `tcp.flags == 0x04`                                           |
| **RST-ACK**                       | `tcp.flags.reset == 1 && tcp.flags.ack == 1`<br>*(hex)* `tcp.flags == 0x14`                                           |
| **FIN only**                      | `tcp.flags.fin == 1 && tcp.flags.ack == 0`<br>*(hex)* `tcp.flags == 0x01`                                             |


## Scan Patterns & Quick Wireshark Filters

1. TCP Connect Scan (nmap -sT)
Nature : full three-way handshake (non-root users).

Tell-tale signs : tcp.window_size > 1024 (expects data).

Traffic flow

Open : SYN → SYN/ACK → ACK

Closed :

SYN → SYN/ACK → ACK → RST/ACK, or

SYN → RST/ACK

Filter to surface candidates
#### tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size > 1024

2. TCP SYN (Half-Open) Scan (nmap -sS)
Nature : handshake not completed (root only).

Tell-tale signs : tcp.window_size ≤ 1024 (no payload expected).

Traffic flow

Open : SYN → SYN/ACK → RST

Closed : SYN → RST/ACK

Filter to surface candidates

#### tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024

3. UDP Scan (nmap -sU)
Nature : no handshake; open ports stay silent.

Closed-port clue : ICMP Destination Unreachable, Port Unreachable
(Type 3, Code 3), which embeds the original UDP probe.

Filter to catch closed-port replies
#### icmp.type == 3 && icmp.code == 3


### Tip: Expand the ICMP packet’s data section to view the encapsulated UDP header and pinpoint which probe triggered the error.

## ARP

    %% ---  CAPTURE & FILTER  ---
    A[PCAP / Live Capture] --> B[Filter ARP packets<br/>`arp`]

    %% ---  BASIC CLASSIFICATION  ---
    B --> C{Opcode?}
    C -->|1 = Request| D[Broadcast ARP request<br/>(Normal)]
    C -->|2 = Reply| E[Unicast ARP reply]

    %% ---  DUPLICATE-IP CHECK  ---
    E --> F{Duplicate IP-MAC<br/>detected?}
    F -->|Yes| G[⚠ Possible ARP spoof<br/>`arp.duplicate-address-*`]
    F -->|No| H[No conflict]

    %% ---  NULL MAC CHECK  ---
    B --> I[dst MAC = 00:00:00:00:00:00?<br/>`arp.dst.hw_mac == 00:00:00:00:00:00`]
    I -->|True| G

    %% ---  FLOODING CHECK  ---
    B --> J[Count ARP requests per MAC]
    J --> K{Rate > normal?}
    K -->|Yes| L[⚠ Possible ARP flood]

    %% ---  CORRELATE & IDENTIFY  ---
    G --> M[Correlate IP ↔ MAC pairs<br/>Build mapping table]
    L --> M
    H --> M

    %% ---  CROSS-PROTOCOL VALIDATION  ---
    M --> N[Inspect upper-layer traffic<br/>(e.g., HTTP dst MAC ≠ gateway)]
    N --> O[🎯 Confirm MITM / Attacker MAC]

## DHCP

    %% === CAPTURE START ===
    A[PCAP / Live Capture] --> B{{Protocol?}}

    %% === DHCP BRANCH ===
    B -->|DHCP / BOOTP| C[Filter<br/>`dhcp || bootp`]

    C --> D{Option 53<br/>(Message-type)}
    D -->|3 = Request| E[DHCP Request<br/>(`dhcp.option.dhcp == 3`)]
    D -->|5 = ACK| F[DHCP ACK<br/>(`dhcp.option.dhcp == 5`)]
    D -->|6 = NAK| G[DHCP NAK<br/>(`dhcp.option.dhcp == 6`)]

    E --> E1[Extract<br/>*Hostname (opt 12)*<br/>*Req. IP (opt 50)*<br/>*MAC (opt 61)*]
    F --> F1[Extract<br/>*Domain (opt 15)*<br/>*Lease (opt 51)*]
    G --> G1[Read opt 56<br/>(Reject reason)]

    %% === NBNS BRANCH ===
    B -->|NBNS| H[Filter<br/>`nbns`]
    H --> H1[Query frames →<br/>`nbns.name` to grab<br/>*<IP, TTL, Name>*]

    %% === KERBEROS BRANCH ===
    B -->|Kerberos| I[Filter<br/>`kerberos`]
    I --> J{CNameString}
    J -->|Ends with $| K[Host Account   ]
    J -->|No $ suffix| L[User Account]
    I --> I1[Other fields:<br/>`realm`, `sname`,<br/>`addresses`]

    %% === OUTPUT ===
    E1 & F1 & H1 & L & K & I1 --> Z[📋 Host / User Inventory]

| Goal                      | Display filter                                                 |   |         |
| ------------------------- | -------------------------------------------------------------- | - | ------- |
| **All DHCP/BOOTP**        | \`dhcp                                                         |   | bootp\` |
| - DHCP *Request*          | `dhcp.option.dhcp == 3`                                        |   |         |
| - DHCP *ACK*              | `dhcp.option.dhcp == 5`                                        |   |         |
| - DHCP *NAK*              | `dhcp.option.dhcp == 6`                                        |   |         |
| - Grab hostnames (opt 12) | `dhcp.option.hostname contains "keyword"`                      |   |         |
| **All NBNS**              | `nbns`                                                         |   |         |
| - Find queried name       | `nbns.name contains "keyword"`                                 |   |         |
| **All Kerberos**          | `kerberos`                                                     |   |         |
| - User accounts only      | `kerberos.CNameString && !(kerberos.CNameString contains "$")` |   |         |
| - Specific user/host      | `kerberos.CNameString contains "alice"`                        |   |         |
| - Kerberos realm filter   | `kerberos.realm contains ".corp"`                              |   |         |

%% ---------- DHCP ANALYSIS WORKFLOW ----------
graph TD
    %%  CAPTURE  -------------------------------------------------
    A[PCAP / Live Capture] --> B{{Filter<br/>`dhcp \|\| bootp`}}

    %%  MESSAGE-TYPE SPLIT  --------------------------------------
    B -->|opt 53 = 3| C[DHCP REQUEST]
    B -->|opt 53 = 5| D[DHCP ACK]
    B -->|opt 53 = 6| E[DHCP NAK]

    %%  REQUEST DETAILS  ----------------------------------------
    C --> C1[Hostname (opt 12)]
    C --> C2[Requested IP (opt 50)]
    C --> C3[Client MAC (opt 61)]

    %%  ACK DETAILS  -------------------------------------------
    D --> D1[Domain (opt 15)]
    D --> D2[Lease Time (opt 51)]

    %%  NAK DETAILS  -------------------------------------------
    E --> E1[Message (opt 56)]

    %%  INVENTORY BUILD  ---------------------------------------
    C1 & C2 & C3 & D1 & D2 & E1 --> Z[📋 Host / User Inventory]

%% ---------- QUICK WIRESHARK FILTERS ----------
%% All DHCP / BOOTP ..............  dhcp || bootp
%% DHCP Request (opt 53=3) ........ dhcp.option.dhcp == 3
%% DHCP ACK     (opt 53=5) ........ dhcp.option.dhcp == 5
%% DHCP NAK     (opt 53=6) ........ dhcp.option.dhcp == 6
%% Hostname contains “lab” ........ dhcp.option.hostname contains "lab"
%% Domain  contains “corp” ........ dhcp.option.domain_name contains "corp"
%% -------------------------------------------

## ICMP & DNS

%% ---------- ICMP & DNS TUNNEL-HUNT WORKFLOW ----------
graph TD
    %% ────────── CAPTURE INPUT ──────────
    A[PCAP / Live Capture] --> B{{Protocol?}}

    %% ────────── ICMP BRANCH ────────────
    B -->|ICMP| C[Filter<br/>`icmp`]
    C --> D{Packet size?}
    D -->|> 64 bytes| E[⚠ Suspicious ICMP payload<br/>(possible exfil/C2)]
    D -->|≤ 64 bytes| F[Likely normal echo / error]

    %% ────────── DNS BRANCH ─────────────
    B -->|DNS| G[Filter<br/>`dns`]
    G --> H{Query name length?}
    H -->|> 15 chars && not mDNS| I[⚠ Long/encoded sub-domain<br/>`dns.qry.name.len`]
    H -->|Normal| J[Likely benign]

    %% ────────── CROSS-CHECKS ───────────
    E & I --> K[Deep-dive payloads<br/>(grep for ssh/http/hex, entropy)]
    K --> L[📋 Report / Escalate]

%% ---------- QUICK WIRESHARK FILTERS ----------
%% All ICMP ..............................  icmp
%% ICMP payload > 64 bytes ...............  data.len > 64 && icmp
%% All DNS ...............................  dns
%% Long query & not mDNS .................  dns.qry.name.len > 15 && !mdns
%% dnscat / dns2tcp patterns .............  dns contains "dnscat" || dns contains "dns2tcp"

## FTP & Clear Text

%% ---------- FTP CLEAR-TEXT ANALYSIS WORKFLOW ----------
graph TD
    %% ─────────── CAPTURE INPUT ───────────
    A[PCAP / Live Capture] --> B[Filter<br/>`ftp`]

    %% ─────────── FTP RESPONSES ───────────
    B --> C{{Response&nbsp;code?}}

    C -->|1xx (Info)| C1[211 / 212 / 213<br/>System-Dir-File status]
    C -->|2xx (Conn)| C2[220 / 227–229<br/>Service ready / Passive modes]
    C -->|3xx (Auth)| C3[230 OK&nbsp;login<br/>331 Need PASS<br/>530 Login failed]

    %% ─────────── FTP COMMANDS ───────────
    B --> D{{Command?}}

    D -->|USER| D1[Grab usernames<br/>`ftp.request.command == "USER"`]
    D -->|PASS| D2[Grab passwords<br/>`ftp.request.command == "PASS"`]
    D -->|CWD, LIST …| D3[Directory ops & exfil clues]

    %% ─────────── ALERTING RULES ─────────
    C3 -->|530 floods| E[⚠ Bruteforce / Spray<br/>(many 530s per USER)]
    D2 -->|Fixed password| F[⚠ Password spray on multiple USERs]

    %% ─────────── OUTPUT ───────────
    C1 & C2 & C3 & D1 & D2 & D3 & E & F --> Z[📋 Credentials, Modes & Abnormalities]
    
%% ---------- QUICK WIRESHARK FILTERS ----------
%% All FTP ....................................  ftp
%% Response code 211 ...........................  ftp.response.code == 211
%% Passive-mode negotiation (227) ..............  ftp.response.code == 227
%% Successful login (230) ......................  ftp.response.code == 230
%% Login failure (530) .........................  ftp.response.code == 530
%% USER commands ...............................  ftp.request.command == "USER"
%% PASS commands ...............................  ftp.request.command == "PASS"
%% Spray for a single password "password" ......  ftp.request.command == "PASS" && ftp.request.arg == "password"


## HTTP & LOG4j

%% ---------- HTTP CLEAR-TEXT ANALYSIS WORKFLOW ----------
graph TD
    %% ─────────── CAPTURE INPUT ───────────
    A[PCAP / Live Capture] --> B[Filter<br/>`http || http2`]

    %% ─────────── REQUEST SIDE ───────────
    B --> C{{Request&nbsp;method?}}
    C -->|GET| C1[Static content fetch]
    C -->|POST| C2[Data upload / form<br/>&& payload inspection]
    C -->|Other| C3[PUT / DELETE / etc.]

    %% ─────────── RESPONSE SIDE ──────────
    B --> D{{Response&nbsp;code group}}
    D -->|2xx| D1[Success<br/>200 / 206]
    D -->|3xx| D2[Redirect<br/>301 / 302]
    D -->|4xx| D3[Client error<br/>401 / 403 / 404 / 405 / 408]
    D -->|5xx| D4[Server error<br/>500 / 503]

    %% ─────────── HEADER / PARAMS ────────
    B --> E[Inspect headers & params]
    E --> E1[User-Agent]
    E --> E2[URI / Host / Query]
    E --> E3[Server header]

    %% ─────────── USER-AGENT CHECK ───────
    E1 --> F{Suspicious?}
    F -->|Tools / typos / payload| F1[⚠ Scanner / C2 / exfil]

    %% ─────────── LOG4SHELL HUNT ─────────
    C2 --> L{Body / UA<br/>contains `jndi:`?}
    L -->|Yes| L1[⚠ Log4j exploit attempt]

    %% ─────────── OUTPUT ───────────
    C1 & C2 & C3 & D1 & D2 & D3 & D4 & F1 & L1 --> Z[📋 Web attack / Exfil report]

%% ---------- QUICK WIRESHARK FILTERS ----------
%% All HTTP / HTTP2 ...............................  http || http2
%% Only GET / POST ................................  http.request.method == "GET" ||
%%                                                  http.request.method == "POST"
%% All requests ...................................  http.request
%% Response codes 200 / 404 / 503 .................  http.response.code == 200 ||
%%                                                  http.response.code == 404 ||
%%                                                  http.response.code == 503
%% Suspicious UA (nmap, sqlmap, wfuzz, nikto) .....  http.user_agent matches "(?i)(nmap|sqlmap|wfuzz|nikto)"
%% Long or sensitive URI ..........................  http.request.uri contains "admin" ||
%%                                                  http.request.full_uri contains "token"
%% Log4j pattern hunt .............................  (frame contains "jndi:ldap") ||
%%                                                  (http.user_agent contains "$") ||
%%                                                  (http.user_agent contains "==")

### Hunt Cleartext Credentials!

Up to here, we discussed how to inspect the packets for specific conditions and spot anomalies. 
As mentioned in the first room, Wireshark is not an IDS, but it provides suggestions for some cases under the expert info. 
However, sometimes anomalies replicate the legitimate traffic, so the detection becomes harder. 
For example, in a cleartext credential hunting case, it is not easy to spot the multiple credential inputs and decide if there is a brute-force attack or if it is a standard user who mistyped their credentials.

As everything is presented at the packet level, it is hard to spot the multiple username/password entries at first glance. 
The detection time will decrease when an analyst can view the credential entries as a list. Wireshark has such a feature to help analysts who want to hunt cleartext credential entries.

Some Wireshark dissectors (FTP, HTTP, IMAP, pop and SMTP) are programmed to extract cleartext passwords from the capture file. 
You can view detected credentials using the "Tools --> Credentials" menu. This feature works only after specific versions of Wireshark (v3.1 and later).
Since the feature works only with particular protocols, it is suggested to have manual checks and not entirely rely on this feature to decide if there is a cleartext credential in the traffic.

Once you use the feature, it will open a new window and provide detected credentials. 
It will show the packet number, protocol, username and additional information. 
This window is clickable; clicking on the packet number will select the packet containing the password, and clicking on the username will select the packet containing the username info. 
The additional part prompts the packet number that contains the username.

### Actionable Results

You have investigated the traffic, detected anomalies and created notes for further investigation. What is next? Not every case investigation is carried out by a crowd team. As a security analyst, there will be some cases you need to spot the anomaly, identify the source and take action. 

Wireshark is not all about packet details; it can help you to create firewall rules ready to implement with a couple of clicks. You can create firewall rules by using the "Tools --> Firewall ACL Rules" menu. Once you use this feature, it will open a new window and provide a combination of rules (IP, port and MAC address-based) for different purposes. Note that these rules are generated for implementation on an outside firewall interface.

Currently, Wireshark can create rules for:

- Netfilter (iptables)
- Cisco IOS (standard/extended)
- IP Filter (ipfilter)
- IPFirewall (ipfw)
- Packet filter (pf)
- Windows Firewall (netsh new/old format)
