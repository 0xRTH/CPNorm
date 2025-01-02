package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	SkipNoCacheHeaders  = "no_cache"
	SkipConnectionError = "connection_error"
	SkipFoundIssue      = "found_issue"
)

var (
	domainTimeouts sync.Map // tracks timeout counts per domain
	skippedURLs    sync.Map // tracks URLs that should be skipped and why
	verbose        *bool    // flag for error output
	veryVerbose    *bool    // flag for verbose output
	domainWorkers  *int     // flag for number of concurrent domain workers
)

var domainBlacklist = []string{
	"apple.com",
	"unpkg.com",
}

var payloads = []string{
	"cb#/../",
	"cb#%2f..%2f",
	"cb\\..\\",
	"cb#%2f..%2f",
	"cb;%2f..%2f",
	"cb$/../",
	"cb$%2f..%2f",
	"cb%0a/../",
	"cb%0a%2f..%2f",
	"cb%00/../",
	"cb%00%2f..%2f",
	"cb/../",
	"cb/./../",
	"cb%2fcb2/../",
	"cb／..／",
	"cb%5c..%5c",
	"cb\\%2e%2e\\",
	"cb/%2e%2e/",
	"cb%2f.%2f..%2f",
	"cb%c0%af..%c0%af",
	"cb%252fcb2%2f..%2f",
	"cb\\cb2/../",
	"cb%5ccb2/../",
	"cb/%2e%2e/../../",
	"cb%2f%2e%2e/../",
	"cb%2f%2e%2e%2f..%2f",
}

const maxBackoffDelay = 5 * time.Second

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func hasCacheHeaders(resp *fasthttp.Response) bool {
	headers := resp.Header.String()
	return strings.Contains(headers, "Age:") ||
		strings.Contains(headers, "HIT") ||
		strings.Contains(headers, "MISS") ||
		strings.Contains(headers, "DYNAMIC") ||
		strings.Contains(headers, "max-age") ||
		strings.Contains(headers, "TTL")
}

var consoleMutex sync.Mutex

func clearLine() {
	if !*veryVerbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Print("\r\033[K")
}

func printProgress(format string, args ...interface{}) {
	if !*veryVerbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Printf("\rMaking request to "+format, args...)
}

func printResult(format string, args ...interface{}) {
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Print("\r\033[K")
	fmt.Printf(format+"\n", args...)
}

func printVerbose(format string, args ...interface{}) {
	if !*veryVerbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func printError(format string, args ...interface{}) {
	if !*verbose && !*veryVerbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

func printStatus(format string, args ...interface{}) {
	if !*veryVerbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
}

func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr // return full URL if parsing fails
	}
	return u.Host
}

func extractTopLevelDomain(domain string) string {
	// Remove www. prefix if present
	domain = strings.TrimPrefix(domain, "www.")

	// Split domain into parts
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}

	// Handle special cases like co.uk, com.au, etc.
	if len(parts) >= 3 {
		tld := parts[len(parts)-1]
		sld := parts[len(parts)-2]
		if (tld == "uk" && sld == "co") ||
			(tld == "au" && sld == "com") ||
			(tld == "br" && sld == "com") {
			if len(parts) > 3 {
				return strings.Join(parts[len(parts)-3:], ".")
			}
			return domain
		}
	}

	// Return last two parts
	return strings.Join(parts[len(parts)-2:], ".")
}

func checkDomainTimeout(urlStr string, isError bool) bool {
	domain := extractDomain(urlStr)
	if isError {
		val, _ := domainTimeouts.LoadOrStore(domain, int64(0))
		count := val.(int64)
		count++
		domainTimeouts.Store(domain, count)

		if count >= 30 {
			if *verbose {
				printError("Too many errors on domain %s (%d), dropping further testing", domain, count)
			}
			skippedURLs.Store(domain, SkipConnectionError)
			return true
		}

		// Exponential backoff with jitter
		backoffDelay := time.Duration(count*count) * 100 * time.Millisecond
		if backoffDelay > maxBackoffDelay {
			backoffDelay = maxBackoffDelay
		}
		jitter := time.Duration(rand.Int63n(int64(backoffDelay) / 4))
		time.Sleep(backoffDelay + jitter)
		return false
	}
	// Reset error count on successful request
	domainTimeouts.Store(domain, int64(0))
	return false
}

func isDomainBlacklisted(domain string) bool {
	domain = extractTopLevelDomain(domain)
	for _, blacklisted := range domainBlacklist {
		if strings.HasSuffix(domain, blacklisted) {
			if *verbose {
				printVerbose("Skipping blacklisted domain: %s", domain)
			}
			return true
		}
	}
	return false
}

func makeRequest(client *fasthttp.Client, urlStr string) (int64, *fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseRequest(req)
	}()

	req.SetRequestURI(urlStr)
	req.Header.SetMethod("GET")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "")
	req.Header.Set("Sec-Ch-Ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	err := client.DoTimeout(req, resp, 10*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "EOF") ||
			strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "broken pipe") {
			if checkDomainTimeout(urlStr, true) {
				return 0, nil, fmt.Errorf("domain error limit exceeded")
			}
		}
		return 0, nil, err
	}

	checkDomainTimeout(urlStr, false)

	length := int64(resp.Header.ContentLength())
	if length <= 0 {
		length = int64(len(resp.Body()))
	}
	return length, resp, nil
}

func getRequiredDifference(bodySize int64) int64 {
	switch {
	case bodySize < 1000:
		return 50
	case bodySize < 10000:
		return 200
	default:
		return 1000
	}
}

func processPayload(client *fasthttp.Client, targetURL, newURL, payload string, len1 int64) bool {
	printProgress("%s", newURL)
	len2, resp2, err := makeRequest(client, newURL)
	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}
	clearLine()

	if err != nil {
		printError("Making request to %s: %v", newURL, err)
		return false
	}

	// First two requests must have exactly the same size
	if len1 == len2 {
		randomStr := randString(8)
		baseURL := newURL
		verifyURL := baseURL + "?zzz=" + randomStr

		printProgress("%s", verifyURL)
		len3, resp3, err := makeRequest(client, verifyURL)
		if resp3 != nil {
			defer fasthttp.ReleaseResponse(resp3)
		}
		clearLine()

		if err != nil {
			printError("Making verification request to %s: %v", verifyURL, err)
			return false
		}

		requiredDiff := getRequiredDifference(len2)
		if abs(len2-len3) > requiredDiff {
			// Make a request with the same cache buster but without the payload
			verifyNoPayloadURL := targetURL + "?zzz=" + randomStr
			printProgress("%s", verifyNoPayloadURL)
			lenVerifyNoPayload, respVerifyNoPayload, err := makeRequest(client, verifyNoPayloadURL)
			if respVerifyNoPayload != nil {
				defer fasthttp.ReleaseResponse(respVerifyNoPayload)
			}
			clearLine()

			if err != nil {
				printError("Making verification request to %s: %v", verifyURL, err)
			} else {
				if abs(len3-lenVerifyNoPayload) <= requiredDiff/2 {
					printResult("[HIGH_PROBABILITY] Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d (required diff: %d)", targetURL, payload, len1, len2, len3, requiredDiff)
					skippedURLs.Store(targetURL, SkipFoundIssue)
					return true
				}
			}

			randomStrVerify := randString(8)
			verifyURL = baseURL + "?zzz=" + randomStrVerify
			printProgress("%s (verification)", verifyURL)
			len3Verify, resp3Verify, err := makeRequest(client, verifyURL)
			if resp3Verify != nil {
				defer fasthttp.ReleaseResponse(resp3Verify)
			}
			clearLine()

			if err != nil {
				printError("Making verification request to %s: %v", verifyURL, err)
			} else if abs(len2-len3Verify) > requiredDiff {
				printResult("Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d (required diff: %d)", targetURL, payload, len1, len2, len3, requiredDiff)
				skippedURLs.Store(targetURL, SkipFoundIssue)
				return true
			}

			if *verbose {
				printVerbose("Issue not verified for %s, continuing with other payloads", targetURL)
			}
		}
	}
	return false
}

func processURL(client *fasthttp.Client, targetURL, payload string) {
	if reason, found := skippedURLs.Load(targetURL); found {
		if *verbose {
			printVerbose("Skipping %s: %s", targetURL, reason)
		}
		return
	}

	domain := extractDomain(targetURL)
	if val, ok := domainTimeouts.Load(domain); ok && val.(int64) >= 30 {
		if *verbose {
			printVerbose("Skipping %s due to too many errors on domain", targetURL)
		}
		return
	}

	newURL := ""
	if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
		if idx <= len("https://") {
			newURL = targetURL + "/" + payload
		} else {
			base := targetURL[:idx+1]
			path := targetURL[idx+1:]
			newURL = base + payload + path
		}
	} else {
		newURL = targetURL + "/" + payload
	}

	printProgress("%s", targetURL)
	body1, resp1, err := makeRequest(client, targetURL)
	clearLine()

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			checkDomainTimeout(targetURL, true)
		} else if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server closed connection") {
			if *verbose {
				printError("Connection error for %s: %v", targetURL, err)
			}
			skippedURLs.Store(targetURL, SkipConnectionError)
			return
		}
		if *verbose {
			printError("Error making initial request to %s: %v", targetURL, err)
		}
		return
	}

	checkDomainTimeout(targetURL, false)

	func() {
		defer fasthttp.ReleaseResponse(resp1)

		if !hasCacheHeaders(resp1) {
			if *verbose {
				printVerbose("No cache headers found for %s, skipping", targetURL)
			}
			skippedURLs.Store(targetURL, SkipNoCacheHeaders)
			return
		}

		len1 := body1
		processPayload(client, targetURL, newURL, payload, len1)
	}()
}

// Add connection wrapper type and methods
type connWrapper struct {
	net.Conn
}

func (c *connWrapper) Write(b []byte) (n int, err error) {
	s := string(b)
	if strings.Contains(s, "GET ") && strings.Contains(s, " HTTP/1.1") {
		lines := strings.Split(s, "\r\n")
		if len(lines) > 0 {
			requestLine := lines[0]
			parts := strings.SplitN(requestLine, " ", 3)
			if len(parts) == 3 {
				// Extract the path and handle # character
				path := parts[1]
				if strings.Contains(path, "cb%23") {
					path = strings.Replace(path, "cb%23", "cb#", -1)
					lines[0] = fmt.Sprintf("%s %s %s", parts[0], path, parts[2])
					s = strings.Join(lines, "\r\n")
					return c.Conn.Write([]byte(s))
				}
			}
		}
	}
	return c.Conn.Write(b)
}

func main() {
	useProxy := flag.Bool("proxy", false, "Use local proxy (127.0.0.1:8080)")
	verbose = flag.Bool("v", false, "Show errors only")
	veryVerbose = flag.Bool("vv", false, "Show all logging (current verbose)")
	domainWorkers = flag.Int("t", 10, "Number of concurrent domain workers")
	flag.Parse()

	if *veryVerbose {
		*verbose = true
	}

	client := &fasthttp.Client{
		DisablePathNormalizing:   true,
		NoDefaultUserAgentHeader: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},
		ReadTimeout:         20 * time.Second,
		WriteTimeout:        20 * time.Second,
		MaxIdleConnDuration: 15 * time.Second,
		MaxConnDuration:     60 * time.Second,
		MaxConnsPerHost:     10,
		MaxConnWaitTimeout:  15 * time.Second,
		ReadBufferSize:      64 * 1024,
		WriteBufferSize:     32 * 1024,
		MaxResponseBodySize: 20 * 1024 * 1024,
		RetryIf: func(req *fasthttp.Request) bool {
			return false
		},
		DialDualStack: false,
		Dial: func(addr string) (net.Conn, error) {
			// Parse host and port
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Resolve IPv4 address only
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, err
			}

			var ipv4 net.IP
			for _, ip := range ips {
				if ip.To4() != nil {
					ipv4 = ip
					break
				}
			}

			if ipv4 == nil {
				return nil, fmt.Errorf("no IPv4 address found for %s", host)
			}

			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 60 * time.Second,
			}

			// Connect with timeout
			conn, err := dialer.Dial("tcp4", net.JoinHostPort(ipv4.String(), port))
			if err != nil {
				return nil, err
			}

			// Set TCP keep-alive
			tcpConn := conn.(*net.TCPConn)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(60 * time.Second)
			tcpConn.SetNoDelay(true)

			return conn, nil
		},
		MaxIdemponentCallAttempts:     1,
		DisableHeaderNamesNormalizing: true,
		StreamResponseBody:            false,
	}

	if *useProxy {
		client.Dial = func(addr string) (net.Conn, error) {
			proxyConn, err := net.Dial("tcp", "127.0.0.1:8080")
			if err != nil {
				printError("Proxy connection error: %v", err)
				return nil, err
			}

			host := addr
			fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)

			br := bufio.NewReader(proxyConn)
			res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
			if err != nil {
				proxyConn.Close()
				printError("Proxy response error: %v", err)
				return nil, err
			}
			if res.StatusCode != 200 {
				proxyConn.Close()
				printError("Proxy error: %s", res.Status)
				return nil, fmt.Errorf("proxy error: %s", res.Status)
			}

			if strings.HasSuffix(addr, ":443") {
				tlsConn := tls.Client(proxyConn, &tls.Config{
					ServerName:         strings.Split(addr, ":")[0],
					InsecureSkipVerify: true,
				})
				if err := tlsConn.Handshake(); err != nil {
					proxyConn.Close()
					printError("TLS handshake error: %v", err)
					return nil, err
				}
				return tlsConn, nil
			}

			return proxyConn, nil
		}
	}

	cleanup := time.NewTicker(60 * time.Second)
	defer cleanup.Stop()
	go func() {
		for range cleanup.C {
			client.CloseIdleConnections()
		}
	}()

	printStatus("Starting to read URLs from stdin...")
	var allURLs []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr == "" {
			continue
		}
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			if *verbose {
				printError("Invalid URL (missing scheme): %s", urlStr)
			}
			continue
		}
		allURLs = append(allURLs, urlStr)
	}
	if err := scanner.Err(); err != nil {
		printError("Error reading input: %v", err)
		os.Exit(1)
	}
	printStatus("Finished reading %d URLs", len(allURLs))

	domainURLs := make(map[string][]string)
	for _, urlStr := range allURLs {
		domain := extractDomain(urlStr)
		topDomain := extractTopLevelDomain(domain)
		domainURLs[topDomain] = append(domainURLs[topDomain], urlStr)
	}

	for _, payload := range payloads {
		printStatus("Testing payload: %s", payload)

		var domainWg sync.WaitGroup
		domainSem := make(chan struct{}, *domainWorkers) // Use flag value here

		for domain, urls := range domainURLs {
			if val, ok := domainTimeouts.Load(domain); ok && val.(int64) >= 20 {
				if *verbose {
					printVerbose("Skipping domain %s due to too many timeouts", domain)
				}
				continue
			}

			if isDomainBlacklisted(domain) {
				continue
			}

			domainSem <- struct{}{} // Acquire semaphore
			domainWg.Add(1)
			go func(domain string, urls []string) {
				defer func() {
					<-domainSem // Release semaphore
					domainWg.Done()
				}()

				urlChan := make(chan string, len(urls))
				var wg sync.WaitGroup

				domainWorkers := 5
				for i := 0; i < domainWorkers; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for targetURL := range urlChan {
							if _, found := skippedURLs.Load(targetURL); found {
								continue
							}

							processURL(client, targetURL, payload)

							time.Sleep(200 * time.Millisecond)
						}
					}()
				}

				go func() {
					for _, url := range urls {
						urlChan <- url
					}
					close(urlChan)
				}()

				wg.Wait()
			}(domain, urls)
		}

		domainWg.Wait()
		time.Sleep(500 * time.Millisecond)
	}

	client.CloseIdleConnections()
}
