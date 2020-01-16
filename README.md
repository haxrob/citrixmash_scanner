# CVE-2019-19781 citrixmash scanner

A multithreaded scanner for Citrix appliances that are vulnerable to CVE-2019-19781.
The scanner does not attempt to compromise/exploit hosts and avoids downloading any sensitive content. A `HEAD` request is used to determine if a target is vulnerable. False positives are reduced by verifying a specific value in the content-length header response.

citrixsmash_scanner is capable of accepting both network ranges and accepting individual hosts. 

## Installation 
```
$ go get -u github.com/x1sec/citrixmash_scanner
```
Alternatively, compiled 64-bit executable files for Windows, Mac and Linux are available [here](https://github.com/x1sec/citrixmash_scanner/releases/)

## Usage
```
$ ./citrixsmash_scanner -h
  -e  Evade IDS with ASCII encoding (default true)
  -f string
      File containing list of hosts
  -n string
      Network in CIDR format (e.g. 192.168.0.0/24)
  -o string
      Write results to text file
  -t int
      HTTP timeout (seconds) (default 2)
  -u string
      Custom user agent string
  -v  Verbose
  -w int
      Number of concurrent workers (default 20)
```

Requests are concurrent with a default of 20 workers/threads. To speed up the scanning, increase workers (`-w`) and/or reduce the HTTP timeout (`-t`)

If either the `-n` or `f` parameters are omitted, citrixmash_scanner will accept input from stdin. 
For example, using subdomain enumeration with [assetfinder](https://github.com/tomnomnom/assetfinder):
```
$ assetfinder corp.com | ./citrixmash_scanner 
```

Targets can be mixed (http, https), and include networks in CIDR format. If `http` or `https` is ommitted, then `https` will be used. The following is a valid target list:
```
$ cat targets.txt
http://target1.com
https://target2.org
192.168.0.2
http://10.0.0.4
10.0.20.0/24
```

Use the `-o <filename`> option to write vulnerable hosts to a text file in addition to stdout

### Example usage:
Options: verbose info (`-v`), 50 parallel workers (`-w`), 1 second timeout (`-t`), scanning subnet (`-n`) and also including hosts from `target.txt` (`-f`):

```
$ ./citrixmash_scanner -v -t 1 -w 50 -n 192.168.10.0/24 -f targets.txt 

Citrix CVE-2019-19781 Scanner
Author: https://twitter.com/x1sec
Version: 0.4

[+] Testing 255 hosts with 20 concurrent workers ..

[!] https://192.168.10.5/ is vulnerable
[*] INFO: speed: 7 req/sec, sent: 106/255 reqs, vulnerable: 1
[!] https://10.10.0.8/ is vulnerable

[+] Done! 2 host(s) vulnerable
```

### Changelog:
| version | date | changes |
|:---|:---|:---|
| v0.4 | 16/01/20 | Accept targets from stdin, fixed exit issue with -v option, added -o option |
| v0.3 | 15/01/20 | Added evasion bypass (credit: [Fireeye](https://www.fireeye.com/blog/products-and-services/2020/01/rough-patch-promise-it-will-be-200-ok.html)  / [@itsreallynick](https://twitter.com/ItsReallyNick)) |
| v0.2 | 13/01/20 | Check content-length of smb.conf to reduce false positives |
| v0.1 | 13/01/20 | Initial release |


*Disclaimer: This tool is intended for legal activities such as penetration testing, bug bounty hunting on authorized assets and to help secure networks. The author holds no responsibility for it's use.*

