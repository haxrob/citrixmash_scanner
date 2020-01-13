/*
Concurrent scanner for the Citrix CVE-2019-19781
Author: robert@x1sec.com
License: MIT

Disclaimer: The scanner detects a vulnerable host by issuing only a HEAD request in order not to 'exploit' a system.
That said, the tool should only be used to test against assets you are legally permitted to do so against.
*/

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var verbose bool

const infoInterval = 15

func main() {

	var hostsList []string

	var workerCount int

	var requestCount uint64
	var vulnCount uint64

	flag.IntVar(&workerCount, "w", 20, "Number of concurrent workers")

	var networkRange string
	flag.StringVar(&networkRange, "n", "", "Network in CIDR format (e.g. 192.168.0.0/24)")

	var hostListFile string
	flag.StringVar(&hostListFile, "f", "", "File containing list of hosts")

	var timeout int
	flag.IntVar(&timeout, "t", 3, "HTTP timeout (seconds)")

	flag.BoolVar(&verbose, "v", false, "Verbose")

	flag.Parse()

	fmt.Println("\nCitrix CVE-2019-19781 Scanner")
	fmt.Println("Author: robert@x1sec.com")
	fmt.Println("Version: 0.2\n")

	if networkRange == "" && hostListFile == "" {
		flag.PrintDefaults()
		fmt.Println("\nERROR: Must specify either an input file [-f] or specify a network range [-n]\n")
		os.Exit(1)
	}


	// scanner go routine
	hosts := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			for host := range hosts {
				atomic.AddUint64(&requestCount, 1)
				formatFix(&host)
				if isVulnerable(host, timeout) {
					atomic.AddUint64(&vulnCount, 1)
				}
			}
			wg.Done()
		}()
	}

	// Verbose info go routine
	done := make(chan bool)
	ticker := time.NewTicker(time.Second * infoInterval)

	// status information if verbose flag is set
	if verbose {
		go func() {
			var prevReqCount float64
			for {

				select {
				case <-done:
					return
				case <-ticker.C:
					requests := atomic.LoadUint64(&requestCount)
					var delta float64
					delta = (float64(requests) - prevReqCount) / infoInterval

					
						fmt.Printf("[\033[93m*\033[0m] INFO: speed: %0.0f req/sec, sent: %d/%d reqs, vulnerable: %d \n", delta, requests, len(hostsList), atomic.LoadUint64(&vulnCount))
					
					prevReqCount = float64(requests)
				}

			}

		}()
	}
	
	// Options 
	if networkRange != "" {
		for _, ip := range netExpand(networkRange) {
			hostsList = append(hostsList, ip)
			//hosts <- ip
		}
	}

	if hostListFile != "" {
		file, err := os.Open(hostListFile)
		defer file.Close()
		if err != nil {
			log.Fatal(err)
		}

		hostsListScanner := bufio.NewScanner(file)
		for hostsListScanner.Scan() {
			hostsList = append(hostsList, hostsListScanner.Text())
			//hosts <- hostsListScanner.Text()
		}
	}

	fmt.Printf("[\033[92m+\033[0m] Testing %d hosts with %d concurrent workers ..\n\n", len(hostsList), workerCount)
	for _, host := range hostsList {
		hosts <- host
	}
	close(hosts)

	wg.Wait()
	ticker.Stop()
	done <- true
	fmt.Printf("\n[\033[92m+\033[0m] Done! %d host(s) vulnerable\n", atomic.LoadUint64(&vulnCount))
}

func formatFix(host *string) {
	if !strings.HasPrefix(*host, "http") {
		*host = fmt.Sprintf("https://%s", *host)
	}
	if !strings.HasSuffix(*host, "/") {
		*host = fmt.Sprintf("%s/", *host)
	}
}


func isVulnerable(host string, timeout int) bool {

	to := time.Duration(timeout) * time.Second
	url := fmt.Sprintf("%svpn/../vpns/cfg/smb.conf", host)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: to,
		}).DialContext,
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("HEAD", url, nil)
	req.Close = true
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36")
	resp, err := client.Do(req)
	
	if err == nil {

		defer resp.Body.Close()

		if resp.StatusCode == 200 && resp.ContentLength == 83 {
			fmt.Printf("[\033[91m!\033[0m] %s is \033[91mvulnerable\033[0m\n", host)
			return true
		}
		if resp.StatusCode == 403 {
			fmt.Printf("[\033[92m-\033[0m] %s might be a patched server\n", host)
			return false
		}

	} 
	return false

}

func netExpand(network string) []string {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal(err)
	}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
