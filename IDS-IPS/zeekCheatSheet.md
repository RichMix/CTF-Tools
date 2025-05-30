## CLI Kung-Fu Recall: Processing Zeek Logs

Graphical User Interfaces (GUI) are handy and good for accomplishing tasks and processing information quickly. There are multiple advantages of GUIs, especially when processing the information visually. However, when processing massive amounts of data, GUIs are not stable and as effective as the CLI (Command Line Interface) tools.

The critical point is: What if there is no "function/button/feature" for what you want to find/view/extract?

Having the power to manipulate the data at the command line is a crucial skill for analysts. Not only in this room but each time you deal with packets, you will need to use command-line tools, Berkeley Packet Filters (BPF) and regular expressions to find/view/extract the data you are looking for. This task provides quick cheat-sheet like information to help you write CLI queries for your event of interest.


Category
Command Purpose and Usage 
Category
Command Purpose and Usage 
Basics
View the command history:
ubuntu@ubuntu$ history

Execute the 10th command in history:
ubuntu@ubuntu$ !10

Execute the previous command:
ubuntu@ubuntu$ !!

Read File	


Read sample.txt file:
ubuntu@ubuntu$ cat sample.txt

Read the first 10 lines of the file:
ubuntu@ubuntu$ head sample.txt

Read the last 10 lines of the file:
ubuntu@ubuntu$ tail sample.txt

Find
&
Filter



Cut the 1st field:
ubuntu@ubuntu$ cat test.txt | cut -f 1

Cut the 1st column:
ubuntu@ubuntu$ cat test.txt | cut -c1

Filter specific keywords:
ubuntu@ubuntu$ cat test.txt | grep 'keywords'

Sort outputs alphabetically:
ubuntu@ubuntu$ cat test.txt | sort

Sort outputs numerically:
ubuntu@ubuntu$ cat test.txt | sort -n

Eliminate duplicate lines:
ubuntu@ubuntu$ cat test.txt | uniq

Count line numbers:
ubuntu@ubuntu$ cat test.txt | wc -l

Show line numbers
ubuntu@ubuntu$ cat test.txt | nl

Advanced


Print line 11:
ubuntu@ubuntu$ cat test.txt | sed -n '11p'

Print lines between 10-15:
ubuntu@ubuntu$ cat test.txt | sed -n '10,15p'

Print lines below 11:
ubuntu@ubuntu$ cat test.txt | awk 'NR < 11 {print $0}'

Print line 11:
ubuntu@ubuntu$ cat test.txt | awk 'NR == 11 {print $0}'

Special	
Filter specific fields of Zeek logs:
ubuntu@ubuntu$ cat signatures.log | zeek-cut uid src_addr dst_addr
Use Case	Description
sort | uniq

Remove duplicate values.
sort | uniq -c 

Remove duplicates and count the number of occurrences for each value.
sort -nr

Sort values numerically and recursively.
rev

Reverse string characters.
cut -f 1

Cut field 1.
cut -d '.' -f 1-2

Split the string on every dot and print keep the first two fields.
grep -v 'test'

Display lines that  don't match the "test" string.
grep -v -e 'test1' -e 'test2'

Display lines that don't match one or both "test1" and "test2" strings.
file 

View file information.
grep -rin Testvalue1 * | column -t | less -S

Search the "Testvalue1" string everywhere, organise column spaces and view the output with less.

Zeek Signatures

Zeek supports signatures to have rules and event correlations to find noteworthy activities on the network. Zeek signatures use low-level pattern matching and cover conditions similar to Snort rules. Unlike Snort rules, Zeek rules are not the primary event detection point. Zeek has a scripting language and can chain multiple events to find an event of interest. We focus on the signatures in this task, and then we will focus on Zeek scripting in the following tasks.


Zeek signatures are composed of three logical paths; signature id, conditions and action. The signature breakdown is shown in the table below;


Signature id	 Unique signature name.
Conditions	
Header: Filtering the packet headers for specific source and destination addresses, protocol and port numbers.
Content: Filtering the packet payload for specific value/pattern.
Action	
Default action: Create the "signatures.log" file in case of a signature match.

Additional action: Trigger a Zeek script.

Now let's dig more into the Zeek signatures. The below table provides the most common conditions and filters for the Zeek signatures.

Condition Field	Available Filters
Header	
src-ip: Source IP.
dst-ip: Destination IP.
src-port: Source port.
dst-port: Destination port.
ip-proto: Target protocol. Supported protocols; TCP, UDP, ICMP, ICMP6, IP, IP6
Content	payload: Packet payload.
http-request: Decoded HTTP requests.
http-request-header: Client-side HTTP headers.
http-request-body: Client-side HTTP request bodys.
http-reply-header: Server-side HTTP headers.
http-reply-body: Server-side HTTP request bodys.
ftp: Command line input of FTP sessions.
Context	same-ip: Filtering the source and destination addresses for duplication.
Action	event: Signature match message.
Comparison
Operators	==, !=, <, <=, >, >=
NOTE!	 Filters accept string, numeric and regex values.
Run
Zeek
with signature file
ubuntu@ubuntu$ zeek -C -r sample.pcap -s sample.sig

Zeek signatures use the ".sig" extension.
-C: Ignore checksum errors.
 -r: Read pcap file.
-s: Use signature file. 

Example | Cleartext Submission of Password

Let's create a simple signature to detect HTTP cleartext passwords.

View Signature
Remember, Zeek signatures support regex. Regex ".*" matches any character zero or more times. The rule will match when a "password" phrase is detected in the packet payload. Once the match occurs, Zeek will generate an alert and create additional log files (signatures.log and notice.log).

Signature Usage and Log Analysis
ubuntu@ubuntu$ zeek -C -r http.pcap -s http-password.sig 
ubuntu@ubuntu$ ls
clear-logs.sh  conn.log  files.log  http-password.sig  http.log  http.pcap  notice.log  packet_filter.log  signatures.log

ubuntu@ubuntu$ cat notice.log  | zeek-cut id.orig_h id.resp_h msg 
10.10.57.178	44.228.249.3	10.10.57.178: Cleartext Password Found!
10.10.57.178	44.228.249.3	10.10.57.178: Cleartext Password Found!

ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg 
10.10.57.178		http-password	10.10.57.178: Cleartext Password Found!
10.10.57.178		http-password	10.10.57.178: Cleartext Password Found!


As shown in the above terminal output, the signatures.log and notice.log provide basic details and the signature message. Both of the logs also have the application banner field. So it is possible to know where the signature match occurs. Let's look at the application banner!

# Log Analysis
ubuntu@ubuntu$ cat signatures.log | zeek-cut sub_msg
POST /userinfo.php HTTP/1.1\x0d\x0aHost: testphp.vulnweb.com\x0d\x0aUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/...

ubuntu@ubuntu$ cat notice.log  | zeek-cut sub
POST /userinfo.php HTTP/1.1\x0d\x0aHost: testphp.vulnweb.com\x0d\x0aUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/...
We will demonstrate only one log file output to avoid duplication after this point. You can practice discovering the event of interest by analysing notice.log and signatures.log.

Example | FTP Brute-force

Let's create another rule to filter FTP traffic. This time, we will use the FTP content filter to investigate command-line inputs of the FTP traffic. The aim is to detect FTP "admin" login attempts. This basic signature will help us identify the admin login attempts and have an idea of possible admin account abuse or compromise events.

### View Signature
Let's run the Zeek with the signature and investigate the signatures.log and notice.log.

FTP
Signature
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig
ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dst_addr event_msg sub_msg | sort -r| uniq
10.234.125.254	10.121.70.151	10.234.125.254: FTP Admin Login Attempt!	USER administrator
10.234.125.254	10.121.70.151	10.234.125.254: FTP Admin Login Attempt!	USER admin 
Our rule shows us that there are multiple logging attempts with account names containing the "admin" phrase. The output gives us great information to notice if there is a brute-force attempt for an admin account.
This signature can be considered a case signature. While it is accurate and works fine, we need global signatures to detect the "known threats/anomalies". We will need those case-based signatures for significant and sophistical anomalies like zero-days and insider attacks in the real-life environment. Having individual rules for each case will create dozens of logs and alerts and cause missing the real anomaly. The critical point is logging logically, not logging everything.

We can improve our signature by not limiting the focus only to an admin account. In that case, we need to know how the FTP protocol works and the default response codes. If you don't know these details, please refer to RFC documentation. 



Let's optimise our rule and make it detect all possible FTP brute-force attempts.


This signature will create logs for each event containing "FTP 530 response", which allows us to track the login failure events regardless of username. 

## View Signature
Zeek signature files can consist of multiple signatures. Therefore we can have one file for each protocol/situation/threat type. Let's demonstrate this feature in our global rule.

View Signature
Let's merge both of the signatures in a single file. We will have two different signatures, and they will generate alerts according to match status. The result will show us how we benefit from this action. Again, we will need the "CLI Kung-Fu" skills to extract the event of interest.

This rule should show us two types of alerts and help us to correlate the events by having "FTP Username Input" and "FTP Brute-force Attempt" event messages. Let's investigate the logs. We're grepping the logs in range 1001-1004 to demonstrate that the first rule matches two different accounts (admin and administrator). 

### FTP
Signature
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig
ubuntu@ubuntu$ cat notice.log | zeek-cut uid id.orig_h id.resp_h msg sub | sort -r| nl | uniq | sed -n '1001,1004p'
  1001	CeMYiaHA6AkfhSnd	10.234.125.254	10.121.70.151	10.234.125.254: FTP Username Input Found!	USER admin
  1002	CeMYiaHA6AkfhSnd	10.234.125.254	10.121.70.151	10.121.70.151: FTP Brute-force Attempt!	530 Login incorrect.
  1003	CeDTDZ2erDNF5w7dyf	10.234.125.254	10.121.70.151	10.234.125.254: FTP Username Input Found!	USER administrator
  1004	CeDTDZ2erDNF5w7dyf	10.234.125.254	10.121.70.151	10.121.70.151: FTP Brute-force Attempt!	530 Login incorrect.


### Snort Rules in Zeek?

While Zeek was known as Bro, it supported Snort rules with a script called snort2bro, which converted Snort rules to Bro signatures. However, after the rebranding, workflows between the two platforms have changed. The official Zeek document mentions that the script is no longer supported and is not a part of the Zeek distribution.

Zeek Scripts

Zeek has its own event-driven scripting language, which is as powerful as high-level languages and allows us to investigate and correlate the detected events. Since it is as capable as high-level programming languages, you will need to spend time on Zeek scripting language in order to become proficient. In this room, we will cover the basics of Zeek scripting to help you understand, modify and create basic scripts. Note that scripts can be used to apply a policy and in this case, they are called policy scripts.



Zeek has base scripts installed by default, and these are not intended to be modified.
These scripts are located in
 "/opt/zeek/share/zeek/base".
User-generated or modified scripts should be located in a specific path. 

These scripts are located in
"/opt/zeek/share/zeek/site".
Policy scripts are located in a specific path. 

These scripts are located in
 "/opt/zeek/share/zeek/policy".
Like Snort, to automatically load/use a script in live sniffing mode, you must identify the script in the Zeek configuration file. You can also use a script for a single run, just like the signatures. 

The configuration file is located in
 "/opt/zeek/share/zeek/site/local.zeek".
Zeek scripts use the ".zeek" extension.
Do not modify anything under the "zeek/base" directory. User-generated and modified scripts should be in the "zeek/site" directory.
You can call scripts in live monitoring mode by loading them with the command load @/script/path or load @script-name in local.zeek file. 
Zeek is event-oriented, not packet-oriented! We need to use/write scripts to handle the event of interest.
running
Zeek
with signature
ubuntu@ubuntu$ zeek -C -r sample.pcap -s sample.sig

GUI vs Scripts

Have you ever thought about automating tasks in Wireshark, tshark or tcpdump? Zeek provides that chance to us with its scripting power. Let's say we need to extract all available DHCP hostnames from a pcap file. In that case, we have several options like using tcpdump, Wireshark, tshark or Zeek. 

Zeek room - Wireshark hostnameLet's see Wireshark on the stage first. You can have the same information with Wireshark. However, while this information can be extracted using Wireshark is not easy to transfer the data to another tool for processing. Tcpdump and tshark are command-line tools, and it is easy to extract and transfer the data to another tool for processing and correlating.


extracting hostnames with tcpdump and tshark
ubuntu@ubuntu$ sudo tcpdump -ntr smallFlows.pcap port 67 or port 68 -e -vv | grep 'Hostname Option' | awk -F: '{print $2}' | sort -nr | uniq | nl
     1	 "vinlap01"
     2	 "student01-PC"
ubuntu@ubuntu$ tshark -V -r smallFlows.pcap -Y "udp.port==67 or udp.port==68" -T fields -e dhcp.option.hostname | nl | awk NF
     1	student01-PC
     2	vinlap01
Now let's see Zeek scripts in action. First, let's look at the components of the Zeek script. Here the first, second and fourth lines are the predefined syntaxes of the scripting language. The only part we created is the third line which tells Zeek to extract DHCP hostnames. Now compare this automation ease with the rest of the methods. Obviously, this four-line script is easier to create and use. While tcpdump and tshark can provide similar results, transferring uncontrolled data through multiple pipelines is not much preferred.

View Script
Now let's use the Zeek script and see the output.

extracting hostnames with tcpdump and tshark
ubuntu@ubuntu$ zeek -C -r smallFlows.pcap dhcp-hostname.zeek 
student01-PC
vinlap01
The provided outputs show that our script works fine and can extract the requested information. This should show why Zeek is helpful in data extraction and correlation. Note that Zeek scripting is a programming language itself, and we are not covering the fundamentals of Zeek scripting. In this room, we will cover the logic of Zeek scripting and how to use Zeek scripts. You can learn and practice the Zeek scripting language by using Zeek's official training platform for free.



There are multiple options to trigger conditions in Zeek. Zeek can use "Built-In Function" (Bif) and protocols to extract information from traffic data. You can find supported protocols and Bif either by looking in your setup or visiting the Zeek repo.

Customized script locations
/opt/zeek/share/zeek/base/bif
/opt/zeek/share/zeek/base/bif/plugins
/opt/zeek/share/zeek/base/protocols
Answer the questions below

