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

var (
	verbose        *bool
	veryVerbose    *bool
	domainTimeouts sync.Map // tracks timeout counts per domain
	foundIssues    sync.Map // tracks URLs where issues were found
)

var domainBlacklist = []string{
	"apple.com",
	"unpkg.com",
}

var payloads = []string{
	"cb#/../",
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
		strings.Contains(headers, "TTL")
}

// Add new function for direct TCP requests
func makeDirectRequest(urlStr string, useProxy bool) (int64, *fasthttp.Response, error) {
	// Parse URL just to get host and scheme
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return 0, nil, err
	}

	// Get host and port
	host := parsedURL.Host
	port := "80"
	if parsedURL.Scheme == "https" {
		port = "443"
	}
	if !strings.Contains(host, ":") {
		host = host + ":" + port
	}

	var conn net.Conn

	if useProxy {
		// Connect through proxy
		proxyConn, proxyErr := net.Dial("tcp", "127.0.0.1:8080")
		if proxyErr != nil {
			return 0, nil, proxyErr
		}
		defer proxyConn.Close()

		// Send CONNECT request to proxy
		fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)

		// Read proxy response
		br := bufio.NewReader(proxyConn)
		res, proxyErr := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if proxyErr != nil {
			return 0, nil, proxyErr
		}
		if res.StatusCode != 200 {
			return 0, nil, fmt.Errorf("proxy error: %s", res.Status)
		}
		conn = proxyConn
	} else {
		// Direct connection with timeout
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		directConn, dialErr := dialer.Dial("tcp", host)
		if dialErr != nil {
			return 0, nil, dialErr
		}
		defer directConn.Close()
		conn = directConn
	}

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Upgrade to TLS if needed
	if parsedURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         strings.Split(host, ":")[0],
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			return 0, nil, err
		}
		conn = tlsConn
	}

	// Extract path and query from original URL
	pathAndQuery := strings.TrimPrefix(urlStr, parsedURL.Scheme+"://"+parsedURL.Host)
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}

	// Send the raw HTTP request
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: close\r\n"+
		"Cache-Control: no-cache\r\n"+
		"Pragma: no-cache\r\n"+
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"+
		"Accept: */*\r\n"+
		"Accept-Language: en-US,en;q=0.9\r\n"+
		"Accept-Encoding: identity\r\n"+
		"Sec-Ch-Ua: \"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"\r\n"+
		"Sec-Ch-Ua-Mobile: ?0\r\n"+
		"Sec-Ch-Ua-Platform: \"macOS\"\r\n"+
		"Sec-Fetch-Dest: document\r\n"+
		"Sec-Fetch-Mode: navigate\r\n"+
		"Sec-Fetch-Site: none\r\n"+
		"Sec-Fetch-User: ?1\r\n"+
		"Upgrade-Insecure-Requests: 1\r\n"+
		"\r\n", pathAndQuery, parsedURL.Host)

	// Create a response object
	resp := fasthttp.AcquireResponse()

	// Read and parse the response with larger buffer and no size limit
	br := bufio.NewReaderSize(conn, 64*1024)
	err = resp.Read(br)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return 0, nil, err
	}

	// Get content length
	length := int64(resp.Header.ContentLength())
	if length <= 0 {
		length = int64(len(resp.Body()))
	}

	return length, resp, nil
}

func makeRequest(client *fasthttp.Client, urlStr string, useProxy bool) (int64, *fasthttp.Response, error) {
	// For URLs containing #, use direct TCP connection immediately
	if strings.Contains(urlStr, "#") {
		return makeDirectRequest(urlStr, useProxy)
	}

	// Use regular fasthttp for other URLs
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseRequest(req)
		// Response will be released by the caller
	}()

	req.SetRequestURI(urlStr)
	req.Header.SetMethod("GET")
	req.Header.Set("Connection", "close")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
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
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			if checkDomainTimeout(urlStr, true) {
				return 0, nil, fmt.Errorf("domain timeout limit exceeded")
			}
		}
		return 0, nil, err
	}

	// Reset timeout counter on successful request
	checkDomainTimeout(urlStr, false)

	// Get content length from header or body length
	length := int64(resp.Header.ContentLength())
	if length <= 0 {
		length = int64(len(resp.Body()))
	}
	return length, resp, nil
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
	// Clear current line first, then print with newline
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

func checkDomainTimeout(urlStr string, isTimeout bool) bool {
	domain := extractDomain(urlStr)
	if isTimeout {
		// Get current count or initialize
		val, _ := domainTimeouts.LoadOrStore(domain, int64(0))
		count := val.(int64)
		count++
		domainTimeouts.Store(domain, count)

		if count >= 20 {
			printError("Too many timeouts on domain %s, dropping further testing", domain)
			return true
		}
	} else {
		// Reset count on successful request
		domainTimeouts.Store(domain, int64(0))
	}
	return false
}

func isDomainBlacklisted(domain string) bool {
	// Clean the domain first (remove any www. prefix)
	domain = strings.TrimPrefix(domain, "www.")

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

func main() {
	useProxy := flag.Bool("proxy", false, "Use local proxy (127.0.0.1:8080)")
	verbose = flag.Bool("v", false, "Enable error output")
	veryVerbose = flag.Bool("vv", false, "Enable verbose output")
	workers := flag.Int("t", 20, "Number of concurrent workers")
	flag.Parse()

	// If -vv is set, automatically enable -v as well
	if *veryVerbose {
		*verbose = true
	}

	// Setup fasthttp client with optional proxy
	client := &fasthttp.Client{
		DisablePathNormalizing:   true,
		NoDefaultUserAgentHeader: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnDuration:     60 * time.Second,
		MaxConnsPerHost:     10,
		MaxConnWaitTimeout:  30 * time.Second,
		ReadBufferSize:      64 * 1024,
		WriteBufferSize:     32 * 1024,
		MaxResponseBodySize: -1,
		RetryIf: func(req *fasthttp.Request) bool {
			return false
		},
		DialDualStack:                 true,
		MaxIdemponentCallAttempts:     1,
		DisableHeaderNamesNormalizing: true,
		StreamResponseBody:            true,
	}

	// Configure proxy if needed
	if *useProxy {
		client.Dial = func(addr string) (net.Conn, error) {
			proxyConn, err := net.Dial("tcp", "127.0.0.1:8080")
			if err != nil {
				printError("Proxy connection error: %v", err)
				return nil, err
			}

			// Send CONNECT request to proxy
			host := addr
			fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)

			// Read proxy response
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

			// Upgrade to TLS if needed
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
	} else {
		client.Dial = func(addr string) (net.Conn, error) {
			// Custom dialer with keep-alive settings
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}
			conn, err := dialer.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}

			// Upgrade to TLS if needed
			if strings.HasSuffix(addr, ":443") {
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         strings.Split(addr, ":")[0],
					InsecureSkipVerify: true,
				})
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			}

			return conn, nil
		}
	}

	// Create a cleanup ticker to close idle connections periodically
	cleanup := time.NewTicker(60 * time.Second)
	defer cleanup.Stop()
	go func() {
		for range cleanup.C {
			client.CloseIdleConnections()
		}
	}()

	// Read all URLs first
	printStatus("Starting to read URLs from stdin...")
	var allURLs []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		allURLs = append(allURLs, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		printError("Error reading input: %v", err)
		os.Exit(1)
	}
	printStatus("Finished reading %d URLs", len(allURLs))

	// Process each payload against all URLs
	for _, payload := range payloads {
		printStatus("Testing payload: %s", payload)
		// Create channels for this payload's processing
		urls := make(chan string)
		results := make(chan error)
		var wg sync.WaitGroup

		// Start worker pool for this payload
		for i := 0; i < *workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for targetURL := range urls {
					// Skip if we already found an issue for this URL
					if _, found := foundIssues.Load(targetURL); found {
						continue
					}

					// Check if domain should be skipped due to timeouts
					domain := extractDomain(targetURL)

					// Skip if domain is blacklisted
					if isDomainBlacklisted(domain) {
						continue
					}

					if val, ok := domainTimeouts.Load(domain); ok && val.(int64) >= 20 {
						continue // Skip this URL
					}

					// Check if this URL will use # - if so, skip initial request
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

					if strings.Contains(newURL, "#") {
						// For URLs that will contain #, make initial request normally
						printProgress("%s", targetURL)
						body1, resp1, err := makeRequest(client, targetURL, *useProxy)
						clearLine()

						if err != nil {
							// Check if it's a timeout error
							if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
								if checkDomainTimeout(targetURL, true) {
									continue // Skip to next URL if too many timeouts
								}
							}
							if *verbose {
								printError("Error making initial request to %s: %v", targetURL, err)
							}
							continue
						}

						// Reset timeout counter on successful request
						checkDomainTimeout(targetURL, false)

						// Use a closure to ensure defer runs
						func() {
							defer fasthttp.ReleaseResponse(resp1)

							// Check for cache headers
							if !hasCacheHeaders(resp1) {
								if *verbose {
									printVerbose("No cache headers found for %s, skipping", targetURL)
								}
								return
							}

							len1 := body1
							// Process payload with the initial length for comparison
							processPayload(client, targetURL, newURL, payload, len1, *useProxy)
						}()
						continue
					}

					// Make initial request once for this URL
					printProgress("%s", targetURL)
					body1, resp1, err := makeRequest(client, targetURL, *useProxy)
					clearLine()

					if err != nil {
						// Check if it's a timeout error
						if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
							if checkDomainTimeout(targetURL, true) {
								continue // Skip to next URL if too many timeouts
							}
						}
						if *verbose {
							printError("Error making initial request to %s: %v", targetURL, err)
						}
						continue
					}

					// Reset timeout counter on successful request
					checkDomainTimeout(targetURL, false)

					// Use a closure to ensure defer runs
					func() {
						defer fasthttp.ReleaseResponse(resp1)

						// Check for cache headers
						if !hasCacheHeaders(resp1) {
							if *verbose {
								printVerbose("No cache headers found for %s, skipping", targetURL)
							}
							return
						}

						len1 := body1

						// Find the last slash in the URL without parsing
						if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
							// Check if this is just the scheme separator
							if idx <= len("https://") {
								// This is just the scheme separator, append payload to root
								newURL := targetURL + "/" + payload
								processPayload(client, targetURL, newURL, payload, len1, *useProxy)
							} else {
								// Normal case - inject payload before last path segment
								base := targetURL[:idx+1]
								path := targetURL[idx+1:]
								newURL := base + payload + path
								processPayload(client, targetURL, newURL, payload, len1, *useProxy)
							}
						} else {
							// No slash found at all, append to root
							newURL := targetURL + "/" + payload
							processPayload(client, targetURL, newURL, payload, len1, *useProxy)
						}
					}()
				}
			}()
		}

		// Feed URLs to workers for this payload
		go func() {
			for _, url := range allURLs {
				urls <- url
			}
			close(urls)
		}()

		// Wait for all workers to finish with this payload
		go func() {
			wg.Wait()
			close(results)
		}()

		// Process results for this payload
		for err := range results {
			if err != nil {
				printError("Error: %v", err)
			}
		}

		// Small delay between payloads to avoid overwhelming servers
		time.Sleep(500 * time.Millisecond)
	}

	// Cleanup connections before exit
	client.CloseIdleConnections()
}

// Helper function to determine required difference based on response size
func getRequiredDifference(bodySize int64) int64 {
	switch {
	case bodySize < 1000:
		return 50
	case bodySize < 10000:
		return 150
	default:
		return 300
	}
}

// Helper function to process a single payload
func processPayload(client *fasthttp.Client, targetURL, newURL, payload string, len1 int64, useProxy bool) bool {
	// Make second request with injected payload
	printProgress("%s", newURL)
	len2, resp2, err := makeRequest(client, newURL, useProxy)
	if resp2 != nil {
		defer fasthttp.ReleaseResponse(resp2)
	}
	clearLine()
	if err != nil {
		printError("Making request to %s: %v", newURL, err)
		return false
	}
	if len1 != len2 {
		if *verbose {
			printVerbose("Lengths differ for %s, continuing to next payload", newURL)
		}
		return false
	}

	// For the third request with query parameters
	baseURL := newURL // Use the URL with payload
	newParams := make([]string, 0)

	// If URL has existing query parameters, keep them unchanged
	if idx := strings.Index(targetURL, "?"); idx != -1 {
		// Keep the payload part of newURL and only strip its query params
		if qIdx := strings.Index(newURL, "?"); qIdx != -1 {
			baseURL = newURL[:qIdx]
		}
		query := targetURL[idx+1:]
		newParams = strings.Split(query, "&")
	}

	// Add our custom parameter
	randomStr := randString(8)
	newParams = append(newParams, "zzz="+randomStr)
	finalURL := baseURL + "?" + strings.Join(newParams, "&")

	// Make third request
	printProgress("%s", finalURL)
	body3, resp3, err := makeRequest(client, finalURL, useProxy)
	if resp3 != nil {
		defer fasthttp.ReleaseResponse(resp3)
	}
	clearLine()
	if err != nil {
		printError("Making request to %s: %v", finalURL, err)
		return false
	}

	len3 := body3
	if len2 != len3 {
		// Get required difference based on response size
		requiredDiff := getRequiredDifference(len2)
		if abs(len2-len3) > requiredDiff {
			if *verbose {
				printVerbose("Verifying potential issue for %s", targetURL)
			}

			// Make a request with the same cache buster but without the payload
			baseURLWithoutPayload := targetURL
			if qIdx := strings.Index(baseURLWithoutPayload, "?"); qIdx != -1 {
				baseURLWithoutPayload = baseURLWithoutPayload[:qIdx]
			}
			// Ensure baseURLWithoutPayload ends with /
			if !strings.HasSuffix(baseURLWithoutPayload, "/") {
				baseURLWithoutPayload += "/"
			}
			verifyURL := strings.TrimSuffix(baseURLWithoutPayload, "/") + "/?zzz=" + randomStr
			printProgress("%s (no-payload verification)", verifyURL)
			lenVerifyNoPayload, respVerifyNoPayload, err := makeRequest(client, verifyURL, useProxy)
			if respVerifyNoPayload != nil {
				defer fasthttp.ReleaseResponse(respVerifyNoPayload)
			}
			clearLine()

			if err != nil {
				printError("Making verification request to %s: %v", verifyURL, err)
			} else {
				// If the response with cache buster but no payload is similar to the response with payload and cache buster,
				// this indicates the size difference is not due to the payload
				if abs(len3-lenVerifyNoPayload) <= requiredDiff/2 {
					// High probability - the size difference is due to the payload
					printResult("[HIGH_PROBABILITY] Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d (required diff: %d)", targetURL, payload, len1, len2, len3, requiredDiff)
					foundIssues.Store(targetURL, true)
					return true
				}
			}

			// Recheck with a different random parameter
			randomStrVerify := randString(8)
			verifyURL = baseURL + "?zzz=" + randomStrVerify
			printProgress("%s (verification)", verifyURL)
			len3Verify, resp3Verify, err := makeRequest(client, verifyURL, useProxy)
			if resp3Verify != nil {
				defer fasthttp.ReleaseResponse(resp3Verify)
			}
			clearLine()

			if err != nil {
				printError("Making verification request to %s: %v", verifyURL, err)
			} else if abs(len2-len3Verify) > requiredDiff {
				printResult("Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d (required diff: %d)", targetURL, payload, len1, len2, len3, requiredDiff)
				foundIssues.Store(targetURL, true)
				return true
			}

			if *verbose {
				printVerbose("Issue not verified for %s, continuing with other payloads", targetURL)
			}
		}
	}
	return false
}
