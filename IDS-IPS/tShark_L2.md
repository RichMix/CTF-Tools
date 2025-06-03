## Tshark Statistics 

| Flag        | Role                                                    | Example                            |
| ----------- | ------------------------------------------------------- | ---------------------------------- |
| `--color`   | Colourised (Wireshark-like) packet list                 | `tshark -r file.pcap --color`      |
| `-z <stat>` | Invoke a statistics module                              | `tshark -r file.pcap -z io,phs -q` |
| `-q`        | Quiet mode—hide packets, show only the statistic output | *(used with most `-z` calls)*      |
| `-z help`   | List every available statistics string                  | `tshark -z help`                   |

tshark -r traffic.pcap --color

# All protocols
tshark -r demo.pcapng -z io,phs -q

# Focus on UDP only
tshark -r demo.pcapng -z io,phs,udp -q

## 1 Colourised Output
tshark -r traffic.pcap --color
Adds Wireshark’s green/blue/purple highlighting to terminal views; handy for quick eyeballing.

## 2 Protocol-Hierarchy Statistics
Understand protocol mix & byte share.

# All protocols
tshark -r demo.pcapng -z io,phs -q

# Focus on UDP only
tshark -r demo.pcapng -z io,phs,udp -q

##3 Packet-Length Tree
See distribution of frame sizes—great for spotting outliers/tunnelling.

tshark -r demo.pcapng -z plen,tree -q

## 4 Endpoints
Unique “talkers” and their byte/packet counts.

# IPv4
tshark -r demo.pcapng -z endpoints,ip -q

# Ethernet, IPv6, TCP, UDP, WLAN also accepted
## 5 Conversations
Flow statistics between two endpoints (A↔B).

tshark -r demo.pcapng -z conv,ip -q

6 Expert Info
Automatic anomaly notes—CLI mirror of Wireshark’s “Expert Info” pane.

tshark -r demo.pcapng -z expert -q
Quick-Reference Cheat Sheet
Task	Command
Protocol mix	tshark -r cap.pcap -z io,phs -q
Packet-size anomalies	tshark -r cap.pcap -z plen,tree -q
Top IPv4 endpoints	tshark -r cap.pcap -z endpoints,ip -q
Who talks to whom?	tshark -r cap.pcap -z conv,ip -q
Colourised live capture	sudo tshark -i eth0 --color
Suppress packets, show stats only	append -q to any -z call

### Use display filters (-Y) with any statistic:

# DNS-only protocol hierarchy
tshark -r cap.pcap -Y dns -z io,phs -q
Tip: TShark prints the module header first (e.g., Protocol Hierarchy Statistics), so you always know which stat you invoked—handy when pasting results into reports or scripts.


Command-Line Wireshark Features II – Protocol-Specific -z Statistics
The -z flag turns TShark into a stats engine.
Pair it with -q to suppress per-packet print-outs and with -Y (display filter) to scope the dataset first.

1 IP Protocol Mix
Goal	Command	What you get
IPv4 / IPv6 protocol breakdown	tshark -r cap.pcap -z ptype,tree -q	Counts & rates for TCP, UDP, ICMP…

2 IP Address Views
View	Flag combo	Notes
All IPs	-z ip_hosts,tree -q	Frequency of every IPv4 address
All IPv6s	-z ipv6_hosts,tree -q	Same for v6
Src / Dst pairs	-z ip_srcdst,tree -q	Separate source & destination stats
Outgoing ports	-z dests,tree -q	Dest IP → protocol → port hierarchy
(IPv6 equivalents)	-z ipv6_srcdst,tree / -z ipv6_dests,tree	

3 DNS Summary
bash
Copy
Edit
tshark -r cap.pcap -z dns,tree -q
Shows total DNS packets, opcodes, rcodes, query types, etc.

4 HTTP / HTTP2 Insights
Statistic	Command
Packet & status counter (HTTP 1.x)	-z http,tree -q
Packet & status counter (HTTP/2)	-z http2,tree -q
Load per server IP	-z http_srv,tree -q
Request methods & URIs	-z http_req,tree -q
Req/Resp sequence timing	-z http_seq,tree -q

5 IPv4 vs IPv6 Example Session
bash
Copy
Edit
# Narrow capture to internal subnet first
tshark -r big.pcap -Y "ip.addr == 10.0.0.0/8" \
       -z ip_hosts,tree -q
nginx
Copy
Edit
IPv4 Statistics/All Addresses:
 10.0.0.42     12 packets (57%)
 10.0.0.99      9 packets (43%)
6 Cheat-Sheet Table
Flag	Best for	Sample use
-z ptype,tree	Proto hierarchy	quick “what’s in here?” view
-z ip_hosts,tree / ipv6_hosts	Unique hosts	spot loud IPs
-z ip_srcdst,tree	Src vs Dst balance	detect outbound data pumps
-z dests,tree	Dest IP/Port matrix	service reconnaissance
-z dns,tree	DNS behaviour	tunnelling clues
-z http*,tree	Web traffic intel	C2 over HTTP, exfil URIs
--color	Highlight packets	Wireshark-style colours in CLI

Workflow tip:

Apply a display filter (-Y) to reduce scope.

Run the desired -z … -q statistic.

Drill deeper with standard TShark field extraction or save suspicious streams (-w).


Command-Line Wireshark Features III – Streams, Objects & Credentials
1 Follow Stream (-z follow)
Flag layout	Meaning
-z follow,<proto>,<view>,<stream#>	Follow a single stream
<proto>	tcp, udp, http, http2
<view>	ascii (printable text) | hex
<stream#>	Starts at 0 (see tcp.stream, udp.stream column in Wireshark/TShark)
Optional	Use -q to suppress regular packet lines

bash
Copy
Edit
# Follow TCP stream 1, show ASCII
tshark -r demo.pcapng -z follow,tcp,ascii,1 -q
2 Export Objects (--export-objects)
Extract transferred files from popular application protocols.

Syntax	Supported protocols
--export-objects <proto>,<output_dir>	http, dicom, imf, smb, tftp

bash
Copy
Edit
# Pull every HTTP object into ./loot
mkdir -p loot
tshark -r demo.pcapng --export-objects http,./loot -q
Files keep the original URI / object name where available.

3 Credential Harvest (-z credentials)
TShark can automatically list clear-text usernames & passwords seen in:

FTP

HTTP (Basic / form posts)

IMAP

POP

SMTP

bash
Copy
Edit
tshark -r creds.pcap -z credentials -q
diff
Copy
Edit
===================================================================
Packet  Protocol  Username      Info
72      FTP       admin         USER admin
80      FTP       admin         PASS ******* 
...
===================================================================
Tip: Combine with display filters to scope first, e.g.
-Y "ftp || http" then add -z credentials -q to shorten the hit list.

Quick Reference
Task	One-liner
Follow HTTP/2 stream 0	tshark -r cap.pcap -z follow,http2,ascii,0 -q
Dump all SMB-shared files	tshark -r smb.pcap --export-objects smb,./smbloot -q
List clear-text POP creds	tshark -r mail.pcap -Y pop -z credentials -q

Leverage these features to reproduce popular Wireshark GUI workflows entirely in the shell—ideal for headless servers or scripted investigations.

Advanced Filtering Options | Contains, Matches and Extract Fields

Accomplishing in-depth packet analysis sometimes ends up with a special filtering requirement that cannot be covered with default filters. TShark supports Wireshark's "contains" and "matches" operators, which are the key to the advanced filtering options. You can visit the Wireshark: Packet Operations room (Task 6) if you are unfamiliar with these filters. 

A quick recap from the Wireshark: Packet Operations room:

Filter	Details
Contains	
Search a value inside packets.
Case sensitive.
Similar to Wireshark's "find" option.
Matches	
Search a pattern inside packets.
Supports regex.
Case insensitive.
Complex queries have a margin of error.
Note: The "contains" and "matches" operators cannot be used with fields consisting of "integer" values.
Tip: Using HEX and regex values instead of ASCII always has a better chance of a match.


Extract Fields

This option helps analysts to extract specific parts of data from the packets. In this way, analysts have the opportunity to collect and correlate various fields from the packets. It also helps analysts manage the query output on the terminal. The query structure is explained in the table given below.

Main Filter	Target Field	Show Field Name
-T fields	-e <field name>	-E header=y
Note: You need to use the -e parameter for each field you want to display.

You can filter any field by using the field names as shown below.

-T fields -e ip.src -e ip.dst -E header=y
Extract fields
user@ubuntu$ tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5         
ip.src	ip.dst
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237
145.254.160.237	65.208.228.223
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237

Filter: "contains"

Filter
contains
Type	Comparison operator
Description	Search a value inside packets. It is case-sensitive and provides similar functionality to the "Find" option by focusing on a specific field.
Example	Find all "Apache" servers.
Workflow	List all HTTP packets where the "server" field contains the "Apache" keyword.
Usage	
http.server contains "Apache"

Contains filter
user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"'                          
   38   4.846969 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 

user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y
ip.src	ip.dst	http.server
65.208.228.223	145.254.160.237	Apache 

Filter: "matches"

Filter
matches
Type	Comparison operator
Description	Search a pattern of a regular expression. It is case-insensitive, and complex queries have a margin of error.
Example	Find all .php and .html pages.
Workflow	List all HTTP packets where the "request method" field matches the keywords "GET" or "POST".
Usage	
http.request.method matches "(GET|POST)"

Matches filter
user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'               
    4   0.911310 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1 
   18   2.984291 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&

user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e ip.src -e ip.dst -e http.request.method -E header=y
ip.src	ip.dst	http.request.method
145.254.160.237	65.208.228.223	GET
145.254.160.237	216.239.59.99	GET 

Advanced Filtering – contains, matches, & Field Extraction
1 contains (substring search)
Trait	Details
Case-sensitive	Literal substring match
Works on string fields only	Not for pure integers
Analogue to Wireshark Find	Good for quick keyword hunts

bash
Copy
Edit
# All HTTP responses whose Server header includes “Apache”
tshark -r demo.pcapng \
      -Y 'http.server contains "Apache"'
2 matches (regex search)
Trait	Details
Case-insensitive (PCRE)	Use full regex power
Accepts capture groups, anchors, etc.	`(GET
Slight chance of false-positives on complex patterns	Test first!

bash
Copy
Edit
# GET or POST requests
tshark -r demo.pcapng \
      -Y 'http.request.method matches "(GET|POST)"'
3 Extracting Specific Fields
Flag	Role
-T fields	Switch output to “column mode”
-e <field>	Add field; repeat for each column
-E header=y	Print header row (optional)

bash
Copy
Edit
# Show a 3-column CSV of SrcIP, DstIP, and User-Agent
tshark -r traffic.pcap \
      -Y 'http.request' \
      -T fields \
      -e ip.src -e ip.dst -e http.user_agent \
      -E header=y
python-repl
Copy
Edit
ip.src	ip.dst	http.user_agent
10.0.0.42	93.184.216.34	Mozilla/5.0 ...
...
4 Putting It All Together
bash
Copy
Edit
# Find outbound .php or .html downloads from 192.168.1.100
tshark -r big.pcap \
      -Y 'ip.src==192.168.1.100 && http.request.uri matches "\.(php|html)$"' \
      -T fields -e frame.time -e http.request.uri -E header=y
Result	Insight
contains	Fast literal hunts—good for brand names, malware strings, binaries in hex (contains 89504E47 for PNG)
matches	Flexible IOCs—URLs, file extensions, mixed GET/POST, user-agent anomalies
Field mode	Turns TShark into a CSV/JSON exporter → perfect for `sort 

Tip: Prefer hex + regex when ASCII might be encoded or obfuscated.









