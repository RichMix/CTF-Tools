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
