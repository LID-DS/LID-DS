# Analysis EPS_CWE-434/test/normal_and_attack/angry_bassi_3067.zip
The analysis is split up into the analysis description, which would be sent out to a customer, and the note taking during the analysis, which highlights the information gathering and approach when confronted with the alert dictionary. 

## Analysis Description
#### Who is it about?
Internal host: 192.168.240.15

External involved host: 185.199.110.133

Involved users: root (local admin account on the internal host)

#### What happened?
The internal host serves a python application that has shown to convert files to differnt file types in the excerpt. Parts of that application have shown suspicious behaviour implying malicious remote code execution with administrative permissions, prompting the internal host to contact an external host.

#### When did it take place?
The recording has its initial trace dated at the start time of 2021-09-08 08:39:13 and the last trace at 2021-09-08 08:39:13.

#### Where did it take place?
As there is no documentation on "the customer", this can not be answered. It has to be noted that there is only one point of data in the recording that would enable an analyst to enrich the incident with data from the customer documentation (the internal IP), which might not be in the customer documentation.

#### Why did it happen?
Given that the application on the internal host serves the function of converting file types, contacting an external host via ICMP and HTTPS seems very suspicious. It is very likely that the application has been exploited by an attacker to induce remote code exection with malicious intend.


#### Technical description:
The recording contains twelve processes, which can be divided into four process trees given their parent process information:
```
1.  3793476(bash) --> 3793567(python3) --> 3796848(python3) --> 3796853(pstoedit) --> 3796854(sh)                            
                                    |----> 3796849(python3) --> 3796855(pstoedit) --> 3796856(sh)
2. 3796821(pstoedit)
3. 3796836(sh)
4. 3796837(gs) --> 3796846(sh) --> 3796847(sh)
```
While the first process tree is the most extensive, it does not seem to contain any malicious behaviour but gives context to the application that is most likely also being exploited. The python application converts files into different file types utilizing the programs pstoedit (converts PostScript and PDF files to other vector formats) and Ghostscript (interpreter of Adobe Systems PostScript and Portable Document Format(PDF) languages).

The fourth process tree contains the suspicious behaviour, where a potentially previously uploaded EPS file ("/service/upload/image_0501.eps") is read by Ghostscript (3796837), which is followed by spawning a shell process (3796846). This shell process makes use of the binary wget (Wget is a computer program that retrieves content from web servers), which by itself is not yet a malicious action. However, the shell process spawns another shell process (3796847), which contains amongs further usage of the wget binary, also connections to an external IP 185[.]199[.]111[.]133 via ICMP (port 0) and HTTPS (port 443). This external IP is flagged as malicious on Virustotal by five vendors and reverse DNS lookups reveal that it is part of the Github content delivery network (cdn-185-199-110-13[.]github[.]com). Within this shell process multiple files, binaries and connections have been engaged that are related to DNS, so a domain name has been used that resolves to the external IP rather than the bare IP. Unfortunately this domain can not be retrieved from the recording.
It is common behaviour to ping (ICMP) an external resource from a victim host with an internal network to test the network routing configurations.

As to what the attacker has retrieved from the external IP via HTTPS it can only be speculated due to lack of information. Amongst the files in the process there is a candidate that could be the retrieved file "/service/upload/main.py", as the application can write in the directory "/service/upload/", but should not normally allow Python files to be uploaded within the intended function of the application.

Furthermore the home directory of the root user has been accessed, so the victim can be considered fully compromised by the attacker.



### Note taking during the analysis in chronological order

Start Time: 2021-09-08 08:39:13

End Time: 2021-09-08 08:39:13

Process count: 12

### Process Overview (Ordered by ascending PID and parent information values from the dictionary)

| Process ID | Name |User |Parent |
| ------ | ------ | ------ | ------ |
|3793567|python3|0|("3793476(bash)","clone")|
|3796821|pstoedit|0|-|
|3796836|sh|0|-|
|3796837|gs|0|-|
|3796846|sh|0|("3796837(gs)","clone")|
|3796847|sh|0|("3796846(sh)","execve")|
|3796848|python3|0|("3793567(python3)","clone")|
|3796849|python3|0|("3793567(python3)","clone")|
|3796853|pstoedit|0|("3796848(pstoedit)","clone")|
|3796854|sh|0|("3796853(sh)","execve")|
|3796855|pstoedit|0|("3796849(pstoedit)","clone")|
|3796856|sh|0|("3796855(sh)","execve")|


### Process Trees with corrected parent information values:

```
3793476(bash) --> 3793567(python3) --> 3796848(python3) --> 3796853(pstoedit) --> 3796854(sh)
                                
                                |----> 3796849(python3) --> 3796855(pstoedit) --> 3796856(sh)

3796821(pstoedit)

3796836(sh)

3796837(gs) --> 3796846(sh) --> 3796847(sh)
```

**Intuition**: First big process tree is not too interesting, as it shows the same behaviour in terms of spawned processes. The three other shorter one should be first looked at with a higher chance of suspicous behaviour. Therefore looking at file descriptors for those first.

### Process file links for shorter process trees:

```
3796821(pstoedit)
/tmp/psinerw0YA
/tmp/psoutbbGNXR
/service/upload/image_0501.eps
```


```
3796836(sh)
/dev/pts/0 (dup - creates a copy of a file descriptor)
pts stands for pseudo terminal slave. A terminal (or console) is traditionally a keyboard/screen combination you sit and type at. Old UNIX boxes would have dozens of them hanging off the back, all connected with miles of cable. A pseudo terminal provides just the same facility only without the hardware. In other words, it's an xterm window or a konsole window, or whatever utility you use. They pop into life as you ask for them and get given sequential numbers: pts/0, then pts/1 and so on
```


```
3796837(gs)
/tmp/psoutbbGNXR
/tmp/psinerw0YA
/service/upload/image_0501.eps
/dev/urandom
gs command invokes Ghostscript, which is an interpreter of Adobe Systems PostScript and Portable Document Format(PDF) languages
3796846(sh)
/etc/ld.so.nohwcap
/etc/ld.so.preload
/etc/ld.so.cache
/etc/ld.so
/lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64
/service/upload
/usr/local/sbin/wget
3796847(sh)
...
```
--> Here it becomes obvious that this is a trace of suspicious behaviour due to wget and ping requests to an external malicious IP.

#### Bugs found within the alert dictionary created by the Alert Manager:
Process 3796856 (sh by 0) has the parent thread information "3796855(sh)","execve", however process 3796855 is not sh, but pstoedit in the dictionary.
Process 3796855 (pstoedit by 0) has the parent thread information "3796849(pstoedit)","clone", however process 3796849 is not pstoedit, but python3 in the dictionary. The alert manager is outputting correct parent process IDs, but wrong parent process names.

FD exstraction not on point, therefore duplicates ".(/service/upload)" and "/service/upload".