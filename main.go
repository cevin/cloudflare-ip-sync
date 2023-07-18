package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

var (
	url = []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"}
)

func main() {
	forUse := flag.String("for", "nginx", "")
	ipset := flag.String("ipset", "fromcf", "set IPSET name for firewalld")
	zone := flag.String("zone", "fromcf", "set name as zone for firewalld")
	flag.Parse()

	var ips []string

	for _, u := range url {
		res, err := http.DefaultClient.Do(newReq(u))
		if err != nil {
			panic(err)
		}
		defer res.Body.Close()

		all, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}

		splits := strings.Split(string(all), "\n")
		for _, split := range splits {
			_, _, err := net.ParseCIDR(split)
			if err == nil {
				ips = append(ips, fmt.Sprintf("%s", split))
			}
		}
	}

	if *forUse == "nginx" {
		var rules []string
		for _, item := range ips {
			rules = append(rules, fmt.Sprintf("allow %s;", item))
		}
		rules = append(rules, "deny all;")

		fmt.Print(strings.Join(rules, "\n"))
	} else if *forUse == "firewalld" {
		firewalld("--reload")
		// check target zone exists
		var err error
		_, err = firewalld(fmt.Sprintf("--info-zone=%s", *zone))
		if err != nil {
			// 创建zone
			_, err = firewalld(fmt.Sprintf("--permanent --new-zone=%s", *zone))
			if err != nil {
				panic(err)
			}
			// 添加port
			firewalld(fmt.Sprintf("--permanent --zone=%s --add-port=80/tcp", *zone))
			firewalld(fmt.Sprintf("--permanent --zone=%s --add-port=443/tcp", *zone))
			firewalld(fmt.Sprintf("--permanent --zone=%s --add-port=443/udp", *zone))
		}
		// check ipset exists
		// ipv4
		_, err = firewalld(fmt.Sprintf("--info-ipset=%s", *ipset))
		if err != nil {
			// create ipset
			_, err = firewalld(fmt.Sprintf("--permanent --new-ipset=%s --type=hash:ip", *ipset))
			if err != nil {
				panic(err)
			}
		}
		// ipv6
		_, err = firewalld(fmt.Sprintf("--info-ipset=%sv6", *ipset))
		if err != nil {
			// create ipsetv6
			_, err = firewalld(fmt.Sprintf("--permanent --new-ipset=%sv6 --type=hash:net --option=family=inet6", *ipset))
			if err != nil {
				panic(err)
			}
		}

		//reload
		firewalld("--reload")

		// bind
		_, err = firewalld(fmt.Sprintf("--zone=%s --query-source=ipset:%s", *zone, *ipset))
		if err != nil {
			_, err = firewalld(fmt.Sprintf("--permanent --zone=%s --add-source=ipset:%s", *zone, *ipset))
			if err != nil {
				panic(err)
			}
		}
		_, err = firewalld(fmt.Sprintf("--zone=%s --query-source=ipset:%sv6", *zone, *ipset))
		if err != nil {
			_, err = firewalld(fmt.Sprintf("--permanent --zone=%s --add-source=ipset:%sv6", *zone, *ipset))
			if err != nil {
				panic(err)
			}
		}

		// remove all old rules
		entries, err := firewalld(fmt.Sprintf("--ipset=%s --get-entries", *ipset))
		splits := strings.Split(strings.Trim(entries, "\n"), "\n")
		if len(splits) > 0 {
			for _, item := range splits {
				_, err = firewalld(fmt.Sprintf("--permanent --ipset=%s --remove-entry=%s", *ipset, item))
				if err != nil {
					fmt.Print("fail")
				} else {
					fmt.Print("success")
				}
				fmt.Print("\n")
			}
		}

		entries, err = firewalld(fmt.Sprintf("--ipset=%sv6 --get-entries", *ipset))
		splits = strings.Split(strings.Trim(entries, "\n"), "\n")
		if len(splits) > 0 {
			for _, item := range splits {
				_, err = firewalld(fmt.Sprintf("--permanent --ipset=%sv6 --remove-entry=%s", *ipset, item))
				if err != nil {
					fmt.Print("fail")
				} else {
					fmt.Print("success")
				}
				fmt.Print("\n")
			}
		}

		// add new rule
		for _, item := range ips {
			var targetSet string
			if strings.Contains(item, ":") {
				targetSet = fmt.Sprintf("%sv6", *ipset)
			} else {
				targetSet = *ipset
			}

			firewalld(fmt.Sprintf("--permanent --ipset=%s --add-entry=%s", targetSet, item))
		}

		// --reload
		firewalld("--reload")
	}

}

func newReq(url string) *http.Request {
	req, _ := http.NewRequest("GET", url, nil)
	return req
}

func firewalld(cmd string) (string, error) {

	name := "/usr/bin/firewall-cmd"

	command := exec.Command(name, strings.Split(cmd, " ")...)

	fmt.Println(command.String())

	output, err := command.CombinedOutput()

	return string(output), err
}
