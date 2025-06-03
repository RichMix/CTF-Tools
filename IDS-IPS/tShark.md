flowchart TD
    A[Capture file<br/>*.pcap / *.pcapng] --> B[capinfos<br/>summary]
    B --> C{{Need deep dive?}}

    C -->|Yes| D[TShark pass<br/>`tshark -r …`]
    D --> E[Display-filters<br/>`-Y/-R`]
    E --> F[Field mode<br/>`-T fields -e …`]
    F --> G[Pipe to UNIX tools]
    G --> G1[grep] & G2[cut] & G3[awk] & G4[sort | uniq]
    G --> H[Stats<br/>`tshark -z …`]
    H --> Z[📋 Findings / Scripts]

    C -->|No| Z

| Goal                         | Command                                                                           |
| ---------------------------- | --------------------------------------------------------------------------------- |
| **File summary**             | `capinfos capture.pcapng`                                                         |
| **List interfaces (live)**   | `tshark -D`                                                                       |
| **Live capture on eth0**     | `tshark -i eth0 -w out.pcap`                                                      |
| **Read file + basic info**   | `tshark -r capture.pcap -q -z io,stat,10`                                         |
| **Apply display filter**     | `tshark -r capture.pcap -Y "http.request && ip.dst==10.0.0.1"`                    |
| **Show one packet verbose**  | `tshark -r capture.pcap -c 1 -V`                                                  |
| **Export specific frames**   | `tshark -r capture.pcap -Y "tcp.port==443" -w tls_only.pcap`                      |
| **Field extraction**         | `tshark -r capture.pcap -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name` |
| **Statistics (top talkers)** | `tshark -r capture.pcap -z conv,ip -q`                                            |

## Top 10 visited hosts in an HTTP capture
tshark -r web.pcap -Y "http.request" \
      -T fields -e http.host | sort | uniq -c | sort -nr | head

## Count unique DNS queries >25 chars (possible tunnelling)
tshark -r traffic.pcap -Y dns \
      -T fields -e dns.qry.name |
  awk 'length($0)>25' | sort | uniq -c | sort -nr

| Utility           | Typical use in packet hunts                                      |
| ----------------- | ---------------------------------------------------------------- |
| `grep`, `egrep`   | Quick pattern match (IPs, malware tags).                         |
| `cut`, `awk`      | Column slicing, calculations (`awk '{sum+=$1} END{print sum}'`). |
| `sort`, `uniq -c` | Frequency analysis (ports, hosts, user-agents).                  |
| `sed`             | Inline re-write / cleanup (strip quotes, IPv6 brackets).         |
| `nl`              | Add line numbers for reference.                                  |

# ❶  Extract all user-agents
tshark -r traffic.pcap -Y "http.request" \
       -T fields -e http.user_agent | sort -u

# ❷  Find long-duration TCP streams (>5 min)
tshark -r capture.pcap -q -z conv,tcp | \
  awk '$8 > 300 {print $1,$2,$8}'  # columns: addr A, addr B, duration

# ❸  Build IOC CSV (src_ip,dst_ip,port)
tshark -r malware.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
       -T fields -e ip.src -e ip.dst -e tcp.dstport \
       | sort -u > syn_iocs.csv

### Tips

Think streaming: TShark turns packets into rows; UNIX tools turn rows into intel.

Stay modular: Wrap repeat tasks in tiny bash funcs or Makefile recipes for automation.

Preview early: Pipe into head first to sanity-check field order before full runs.


## CLI Cheat Sheet

| Parameter       | Purpose                                                                                           | Example                                    |
| --------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `-h`            | Show built-in help & exit                                                                         | `tshark -h`                                |
| `-v`            | Display version info                                                                              | `tshark -v`                                |
| `-D`            | List all capture interfaces (*needs sudo on Linux*)                                               | `sudo tshark -D`                           |
| `-i <iface/id>` | Capture live traffic on a specific interface<br/>• numeric *id* from `-D` <br/>• or explicit name | `sudo tshark -i 1`  `sudo tshark -i ens33` |
| *(no args)*     | Start capture on the first interface (`-i 1`)                                                     | `sudo tshark`                              |

### Quick Demos

# Version check
tshark -v

# Enumerate interfaces
sudo tshark -D
# 1. ens5
# 2. lo (Loopback)
# …

# Default capture (first interface)
sudo tshark
# Capturing on 'ens5'
#   1  0.000 192.0.2.10 → 203.0.113.5 TCP 3372→80 [SYN] …
# 100 packets captured

# Capture on loopback explicitly
sudo tshark -i 2
# Capturing on 'lo'

| Parameter       | Purpose                                                           | Typical use                     |
| --------------- | ----------------------------------------------------------------- | ------------------------------- |
| **`-r <file>`** | *Read* an existing capture (pcap/pcapng) instead of sniffing live | `tshark -r demo.pcapng`         |
| **`-c <N>`**    | Stop after *N* packets (works with live capture **or** `-r`)      | `tshark -c 10`                  |
| **`-w <file>`** | *Write* captured / filtered traffic to a new file                 | `tshark -w sample.pcap`         |
| **`-V`**        | Verbose: full “Packet Details-pane” dump for every frame          | `tshark -r demo.pcapng -c 1 -V` |
| **`-q`**        | Quiet: suppress per-packet output (handy with `-w` or stats)      | `tshark -i eth0 -q -w raw.pcap` |
| **`-x`**        | Show each packet’s bytes in hex + ASCII                           | `tshark -r write-demo.pcap -x`  |

| Goal                                      | One-liner                                                     |
| ----------------------------------------- | ------------------------------------------------------------- |
| **Read first 2 packets**                  | `tshark -r demo.pcapng -c 2`                                  |
| **Carve suspicious packet into new file** | `tshark -r demo.pcapng -Y "tcp.port==4444" -c 1 -w evil.pcap` |
| **Hex-dump that packet**                  | `tshark -r evil.pcap -x`                                      |
| **Verbose decode of a single frame**      | `tshark -r demo.pcapng -c 1 -V`                               |
| **Silent live capture to file**           | `sudo tshark -i 1 -q -c 100 -w live100.pcap`                  |


1 Capture Filters (-f) — think tcpdump
Simple, fast, cannot look inside fully-decoded protocol fields.

Example use-case	Filter string	Notes
Only HTTP/S	tcp port 80 or 443	Classic web scope
Just DNS	udp port 53	
Limit to one host	host 10.0.0.42	Matches src or dst
Inbound SMTP to server	dst port 25 and dst host 203.0.113.5	Directional

# Live capture on eth0, saving ONLY DNS into dns.pcap
sudo tshark -i eth0 -f "udp port 53" -w dns.pcap
2 Display Filters (-Y) — think Wireshark GUI
Rich, protocol-aware, can mix layers and fields.

Example question	Filter string	Reads like
See TCP handshake syns	tcp.flags.syn == 1 && tcp.flags.ack == 0	SYN only
Show 404 responses	http.response.code == 404	
Extract large DNS queries	dns.qry.name.len > 25	Potential tunnelling
Follow a single TCP stream	tcp.stream == 12	


# Post-capture drill-down: only 404s from a file
tshark -r full_capture.pcap -Y "http.response.code == 404"
Putting it together

# 1) Capture ONLY traffic to/from 192.168.1.100 on port 22
sudo tshark -i wlan0 -f "host 192.168.1.100 and port 22" -w ssh.pcap

# 2) Later, list every unique client algorithm seen in that SSH handshake
tshark -r ssh.pcap \
       -Y "ssh2.kex.algorithms" \
       -T fields -e ssh2.kex.algorithms | sort -u
Remember:
Capture filters keep the noise out of your PCAP; display filters let you surgically inspect what you already saved. Use both together for efficient CLI-based investigations.

Capture Filters

Wireshark's capture filter syntax is used here. The basic syntax for the Capture/BPF filter is shown below. You can read more on capture filter syntax here and here. Boolean operators can also be used in both types of filters. 

Qualifier	Details and Available Options
Type	
Target match type. You can filter IP addresses, hostnames, IP ranges, and port numbers. Note that if you don't set a qualifier, the "host" qualifier will be used by default.

host | net | port | portrange
Filtering a host
tshark -f "host 10.10.10.10"
Filtering a network range 
tshark -f "net 10.10.10.0/24"
Filtering a Port
tshark -f "port 80"
Filtering a port range
tshark -f "portrange 80-100"
Direction	
Target direction/flow. Note that if you don't use the direction operator, it will be equal to "either" and cover both directions.

src | dst
Filtering source address
tshark -f "src host 10.10.10.10"
Filtering destination address
tshark -f "dst host 10.10.10.10"
Protocol	
Target protocol.

arp | ether | icmp | ip | ip6 | tcp | udp
Filtering TCP
tshark -f "tcp"
Filtering MAC address
tshark -f "ether host F8:DB:C5:A2:5D:81"
You can also filter protocols with IP Protocol numbers assigned by IANA.
Filtering IP Protocols 1 (ICMP)
tshark -f "ip proto 1"
Assigned Internet Protocol Numbers
We need to create traffic noise to test and simulate capture filters. We will use the "terminator" terminal instance to have a split-screen view in a single terminal. The "terminator" will help you craft and sniff packets using a single terminal interface. Now, run the terminator command and follow the instructions using the new terminal instance. 

First, run the given TShark command in Terminal-1 to start sniffing traffic.
Then, run the given cURL command in Terminal-2 to create network noise.
View sniffed packets results in Terminal-1.
"Terminator" Terminal Emulator Application
Terminal-1
user@ubuntu$ tshark -f "host 10.10.10.10"
Capturing on 'ens5'
    1 0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 SACK_PERM=1 TSval=2045205701 TSecr=0 WS=128
    2 0.003452830  10.10.10.10 → YOUR-IP TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 Win=62643 Len=0 MSS=8961 SACK_PERM=1 TSval=744450747 TSecr=2045205701 WS=64
    3 0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 Win=62848 Len=0 TSval=2045205704 TSecr=744450747
    4 0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1
Terminal-2
user@ubuntu$ curl -v 10.10.10.10
*   Trying 10.10.10.10:80...
* TCP_NODELAY set
* Connected to 10.10.10.10 (10.10.10.10) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.10
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Accept-Ranges: bytes
< Content-Length: 1220
< Content-Type: text/html; charset=utf-8
Being comfortable with the command line and TShark filters requires time and practice. You can use the below table to practice TShark capture filters.

Capture Filter Category	Details
Host Filtering	
Capturing traffic to or from a specific host.

Traffic generation with cURL. This command sends a default HTTP query to a specified address.
curl tryhackme.com
TShark capture filter for a host
tshark -f "host tryhackme.com"
IP Filtering	
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for specific IP address
tshark -f "host 10.10.10.10"
Port Filtering	
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for port 4444
tshark -f "port 4444"
Protocol Filtering	
Capturing traffic to or from a specific protocol. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to use UDP, provide details (verbosity), and timeout is set to 5 seconds.
nc -u 10.10.10.10 4444 -vw 5
TShark capture filter for
tshark -f "udp"
Task 7TShark Fundamentals IV | Packet Filtering Options: Capture Filters
Capture Filters

Wireshark's capture filter syntax is used here. The basic syntax for the Capture/BPF filter is shown below. You can read more on capture filter syntax here and here. Boolean operators can also be used in both types of filters. 

Qualifier	Details and Available Options
Type	
Target match type. You can filter IP addresses, hostnames, IP ranges, and port numbers. Note that if you don't set a qualifier, the "host" qualifier will be used by default.

host | net | port | portrange
Filtering a host
tshark -f "host 10.10.10.10"
Filtering a network range 
tshark -f "net 10.10.10.0/24"
Filtering a Port
tshark -f "port 80"
Filtering a port range
tshark -f "portrange 80-100"
Direction	
Target direction/flow. Note that if you don't use the direction operator, it will be equal to "either" and cover both directions.

src | dst
Filtering source address
tshark -f "src host 10.10.10.10"
Filtering destination address
tshark -f "dst host 10.10.10.10"
Protocol	
Target protocol.

arp | ether | icmp | ip | ip6 | tcp | udp
Filtering TCP
tshark -f "tcp"
Filtering MAC address
tshark -f "ether host F8:DB:C5:A2:5D:81"
You can also filter protocols with IP Protocol numbers assigned by IANA.
Filtering IP Protocols 1 (ICMP)
tshark -f "ip proto 1"
Assigned Internet Protocol Numbers
We need to create traffic noise to test and simulate capture filters. We will use the "terminator" terminal instance to have a split-screen view in a single terminal. The "terminator" will help you craft and sniff packets using a single terminal interface. Now, run the terminator command and follow the instructions using the new terminal instance. 

First, run the given TShark command in Terminal-1 to start sniffing traffic.
Then, run the given cURL command in Terminal-2 to create network noise.
View sniffed packets results in Terminal-1.
"Terminator" Terminal Emulator Application
Terminal-1
user@ubuntu$ tshark -f "host 10.10.10.10"
Capturing on 'ens5'
    1 0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 SACK_PERM=1 TSval=2045205701 TSecr=0 WS=128
    2 0.003452830  10.10.10.10 → YOUR-IP TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 Win=62643 Len=0 MSS=8961 SACK_PERM=1 TSval=744450747 TSecr=2045205701 WS=64
    3 0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 Win=62848 Len=0 TSval=2045205704 TSecr=744450747
    4 0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1
Terminal-2
user@ubuntu$ curl -v 10.10.10.10
*   Trying 10.10.10.10:80...
* TCP_NODELAY set
* Connected to 10.10.10.10 (10.10.10.10) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.10
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Accept-Ranges: bytes
< Content-Length: 1220
< Content-Type: text/html; charset=utf-8
Being comfortable with the command line and TShark filters requires time and practice. You can use the below table to practice TShark capture filters.

Capture Filter Category	Details
Host Filtering	
Capturing traffic to or from a specific host.

Traffic generation with cURL. This command sends a default HTTP query to a specified address.
curl tryhackme.com
TShark capture filter for a host
tshark -f "host tryhackme.com"
IP Filtering	
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for specific IP address
tshark -f "host 10.10.10.10"
Port Filtering	
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for port 4444
tshark -f "port 4444"
Protocol Filtering	
Capturing traffic to or from a specific protocol. We will use the Netcat tool to create noise on specific ports.

Traffic generation with Netcat. Here Netcat is instructed to use UDP, provide details (verbosity), and timeout is set to 5 seconds.
nc -u 10.10.10.10 4444 -vw 5
TShark capture filter for
tshark -f "udp"
Answer the questions below
Run the commands from the above Terminator terminals on the target machine and answer the questions.

