#### This repo will cover investigating packet-level details by synthesising the analyst knowledge and  Wireshark functionality for detecting anomalies and odd situations for a given case. // THM

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

flowchart TD
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


