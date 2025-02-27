package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	domain      string
	hosts       string
	use         string
	exclude     string
	silent      bool
	delete      bool
	out         string
	resolve     bool
	thread      int
	parallel    bool
	version     = "2024-12-28"
	available   = []string{"wayback", "crt", "abuseipdb", "findomain", "subfinder", "amass", "assetfinder"}
)

func main() {
	flag.StringVar(&domain, "d", "", "Domain to enumerate")
	flag.StringVar(&hosts, "l", "", "List of domains")
	flag.StringVar(&use, "u", "", "Tools to be used (comma-separated)")
	flag.StringVar(&exclude, "e", "", "Tools to be excluded (comma-separated)")
	flag.StringVar(&out, "o", "", "Output file to save results")
	flag.BoolVar(&silent, "s", false, "Silent mode (only output found subdomains)")
	flag.BoolVar(&delete, "k", true, "Keep temporary files")
	flag.BoolVar(&resolve, "r", false, "Resolve subdomains")
	flag.IntVar(&thread, "t", 40, "Threads for httprobe")
	flag.BoolVar(&parallel, "p", false, "Use parallel processing")
	flag.Parse()

	if domain == "" && hosts == "" {
		fmt.Println("[-] Argument -d/--domain OR -l/--list is required!")
		usage()
		return
	}

	if use != "" && exclude != "" {
		fmt.Println("[-] You can use only one option: -e/--exclude OR -u/--use")
		usage()
		return
	}

	if !silent {
		fmt.Println(`
 ____        _     _____                       
/ ___| _   _| |__ | ____|_ __  _   _ _ __ ___  
\___ \| | | | '_ \|  _| | '_ \| | | | '_ \` + "`" + ` _ \\ 
 ___) | |_| | |_) | |___| | | | |_| | | | | | |
|____/ \__,_|_.__/|_____|_| |_|\__,_|_| |_| |_|
           Subdomains Enumeration Tool
              By: Kcoof (rewritten in Go)
`)
	}

	if hosts != "" {
		processList()
	} else {
		processDomain()
	}
}

func usage() {
	fmt.Println(`
Options:
    -d, --domain       Domain to enumerate
    -l, --list         List of domains
    -u, --use          Tools to be used (comma-separated)
    -e, --exclude      Tools to be excluded (comma-separated)
    -o, --output       Output file to save results
    -s, --silent       Silent mode (only output found subdomains)
    -k, --keep         Keep temporary files
    -r, --resolve      Resolve subdomains
    -t, --thread       Threads for httprobe (default: 40)
    -p, --parallel     Use parallel processing
    -h, --help         Display this help message
    -v, --version      Display version

Available Tools:
    wayback, crt, abuseipdb, findomain, subfinder, amass, assetfinder

Examples:
    - Use specific tools:
       Kcoof -d hackerone.com -u findomain,wayback,subfinder
    - Exclude specific tools:
       Kcoof -d hackerone.com -e amass,assetfinder
    - Use all tools:
       Kcoof -d hackerone.com
    - Run against a list of domains:
       Kcoof -l domains.txt
    - Use parallel processing:
       Kcoof -d target.com -p
`)
}

func processList() {
	file, err := os.Open(hosts)
	if err != nil {
		fmt.Printf("[-] Error opening file: %s\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain = scanner.Text()
		if !silent {
			fmt.Printf("\n[+] Domain: %s\n", domain)
		}
		processDomain()
	}
}

func processDomain() {
	fmt.Println("[*] Starting subdomain enumeration...") // Debug log
	var results []string
	var wg sync.WaitGroup

	tools := getTools()
	fmt.Printf("[*] Tools to run: %v\n", tools) // Debug log

	for _, tool := range tools {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			fmt.Printf("[*] Running tool: %s\n", t) // Debug log
			subdomains := runTool(t)
			fmt.Printf("[*] Tool %s found %d subdomains\n", t, len(subdomains)) // Debug log
			results = append(results, subdomains...)
		}(tool)
	}
	wg.Wait()

	results = unique(results)
	if !silent {
		fmt.Printf("[+] Total subdomains found: %d\n", len(results))
	}

	if out != "" {
		saveResults(results, out)
	} else {
		saveResults(results, fmt.Sprintf("%s-%s.txt", domain, time.Now().Format("2006-01-02")))
	}

	if resolve {
		resolveSubdomains(results)
	}
}

func getTools() []string {
	var tools []string
	if use != "" {
		tools = strings.Split(use, ",")
	} else if exclude != "" {
		excluded := strings.Split(exclude, ",")
		for _, tool := range available {
			if !contains(excluded, tool) {
				tools = append(tools, tool)
			}
		}
	} else {
		tools = available
	}
	return tools
}

func runTool(tool string) []string {
	switch tool {
	case "wayback":
		return wayback()
	case "crt":
		return crt()
	case "abuseipdb":
		return abuseipdb()
	case "findomain":
		return findomain()
	case "subfinder":
		return subfinder()
	case "amass":
		return amass()
	case "assetfinder":
		return assetfinder()
	default:
		return nil
	}
}

func wayback() []string {
	client := http.Client{Timeout: 10 * time.Second} // Add timeout
	resp, err := client.Get(fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s&output=txt&fl=original&collapse=urlkey&page=", domain))
	if err != nil {
		fmt.Printf("[-] Wayback error: %s\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	var subdomains []string
	for _, line := range lines {
		if line != "" {
			subdomains = append(subdomains, strings.Split(line, "/")[2])
		}
	}
	return subdomains
}

func crt() []string {
	resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain))
	if err != nil {
		fmt.Printf("[-] crt.sh error: %s\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var data []map[string]interface{}
	json.Unmarshal(body, &data)

	var subdomains []string
	for _, entry := range data {
		name := entry["name_value"].(string)
		subdomains = append(subdomains, strings.Split(name, "\n")...)
	}
	return subdomains
}

func abuseipdb() []string {
	resp, err := http.Get(fmt.Sprintf("https://www.abuseipdb.com/whois/%s", domain))
	if err != nil {
		fmt.Printf("[-] AbuseIPDB error: %s\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`<li>(\w.*)</li>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var subdomains []string
	for _, match := range matches {
		subdomains = append(subdomains, fmt.Sprintf("%s.%s", match[1], domain))
	}
	return subdomains
}

func findomain() []string {
	cmd := exec.Command("findomain", "-t", domain, "-q")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Findomain error: %s\n", err)
		return nil
	}
	return strings.Split(out.String(), "\n")
}

func subfinder() []string {
	cmd := exec.Command("subfinder", "-all", "-silent", "-d", domain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Subfinder error: %s\n", err)
		return nil
	}
	return strings.Split(out.String(), "\n")
}

func amass() []string {
	cmd := exec.Command("amass", "enum", "-passive", "-norecursive", "-d", domain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Amass error: %s\n", err)
		return nil
	}
	return strings.Split(out.String(), "\n")
}

func assetfinder() []string {
	cmd := exec.Command("assetfinder", "--subs-only", domain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Assetfinder error: %s\n", err)
		return nil
	}
	return strings.Split(out.String(), "\n")
}

func resolveSubdomains(subdomains []string) {
	var resolved []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, thread)

	for _, sub := range subdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			resp, err := http.Get(fmt.Sprintf("http://%s", s))
			if err == nil && resp.StatusCode < 400 {
				resolved = append(resolved, s)
			}
			<-sem
		}(sub)
	}
	wg.Wait()

	if !silent {
		fmt.Printf("[+] Resolved subdomains: %d\n", len(resolved))
	}
	saveResults(resolved, fmt.Sprintf("resolved-%s.txt", domain))
}

func saveResults(results []string, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("[-] Error creating file: %s\n", err)
		return
	}
	defer file.Close()

	for _, result := range results {
		file.WriteString(result + "\n")
	}
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
