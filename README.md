# CVE-2019-19781 citrixmash concurrent scanner

A tool to scan for Citrix appliances that are vulnerable to CVE-2019-19781.
The software specifically does not attempt to compromise/exploit hosts. Only a `HEAD` request is sent to verify if a host is vulnerable. 

The tool is capable of accepting either enumerating a specified network range or accepting a list of targets.

## Usage
```
Citrix CVE-2019-19781 Scanner
Author: robert@x1sec.com

  -f string
    	File containing list of hosts
  -n string
    	Network in CIDR format (e.g. 192.168.0.0/24)
  -t int
    	HTTP timeout (seconds) (default 3)
  -v	Verbose
  -w int
    	Number of concurrent workers (default 20)

ERROR: Must specify either an input file [-f] or specify a network range [-n]
```
Note: Hosts specififed with the `-f` switch which do not have http or https prefixed will by default use https.

### Example:
Verbose, 50 workers, 1 second timeout for each requests:
```
$ ./citrixmash_scanner -w 50 -t 1 -v -n 192.168.10.0/24 

Citrix CVE-2019-19781 Scanner
Author: robert@x1sec.com

[*] Testing 254 hosts with 50 concurrent workers ..

[!] https://192.168.10.5/ is vulnerable
[*] INFO: speed: 51 req/sec, sent: 254/254 reqs, vulnerable: 1 

[*] Done! 1 host(s) vulnerable
```
