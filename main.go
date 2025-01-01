package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var verbose *bool

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
		strings.Contains(headers, "MISS")
}

func makeRequest(client *fasthttp.Client, url string) (int64, *fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer func() {
		fasthttp.ReleaseRequest(req)
		// Response will be released by the caller
	}()

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", "\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	err := client.DoTimeout(req, resp, 5*time.Second)
	if err != nil {
		return 0, nil, err
	}

	// Get content length from header or body length
	length := int64(resp.Header.ContentLength())
	if length <= 0 {
		// If Content-Length header is not present or invalid, fall back to body length
		length = int64(len(resp.Body()))
	}
	return length, resp, nil
}

var consoleMutex sync.Mutex

func clearLine() {
	if !*verbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	// Only clear the current line
	fmt.Print("\r\033[K")
}

func printProgress(format string, args ...interface{}) {
	if !*verbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	// Print on same line without newline
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
	if !*verbose {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func printError(format string, args ...interface{}) {
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

func main() {
	useProxy := flag.Bool("proxy", false, "Use local proxy (127.0.0.1:8080)")
	verbose = flag.Bool("v", false, "Enable verbose output")
	workers := flag.Int("t", 20, "Number of concurrent workers")
	payloadWorkers := flag.Int("p", 3, "Number of payload workers per URL")
	flag.Parse()

	// Setup fasthttp client with optional proxy
	client := &fasthttp.Client{
		DisablePathNormalizing:   true,
		NoDefaultUserAgentHeader: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		},
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
		MaxIdleConnDuration: 30 * time.Second, // Increased for better connection reuse
		MaxConnDuration:     60 * time.Second, // Increased to allow more reuse before forcing close
		MaxConnsPerHost:     50,               // Balanced for connection pooling
		MaxConnWaitTimeout:  10 * time.Second, // Increased wait time for connection availability
		ReadBufferSize:      64 * 1024,
		WriteBufferSize:     64 * 1024,
		MaxResponseBodySize: 10 * 1024 * 1024,
		RetryIf: func(req *fasthttp.Request) bool {
			return false
		},
		DialDualStack: true,
		Dial: func(addr string) (net.Conn, error) {
			// Custom dialer with keep-alive settings
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}
			return dialer.Dial("tcp", addr)
		},
	}

	// Create a cleanup ticker to close idle connections periodically
	cleanup := time.NewTicker(60 * time.Second) // Increased interval for better connection reuse
	defer cleanup.Stop()
	go func() {
		for range cleanup.C {
			client.CloseIdleConnections()
		}
	}()

	// Initialize connection pool by pre-warming
	if *verbose {
		printVerbose("Initializing connection pool...")
	}
	warmupDone := make(chan bool)
	go func() {
		// Pre-warm connections to common ports
		ports := []string{":80", ":443"}
		var warmupWg sync.WaitGroup
		for i := 0; i < 10; i++ { // Create some initial connections
			warmupWg.Add(1)
			go func() {
				defer warmupWg.Done()
				for _, port := range ports {
					conn, err := client.Dial("example.com" + port)
					if err == nil {
						conn.Close()
					} else {
						printError("Connection pool warmup error: %v", err)
					}
				}
			}()
		}
		warmupWg.Wait()
		warmupDone <- true
	}()

	// Wait for connection pool warmup with timeout
	select {
	case <-warmupDone:
		if *verbose {
			printVerbose("Connection pool initialized")
		}
	case <-time.After(5 * time.Second):
		if *verbose {
			printVerbose("Connection pool warmup timed out")
		}
	}

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

			return proxyConn, nil
		}
	}

	payloads := []string{
		"cb\\..\\",
		"cb/../",
		"cb/./../",
		"cb%2fcb2/../",
		"cb／..／",
		"cb%5c..%5c",
		"cb\\%2e%2e\\",
		"cb/%2e%2e/",
		"cb%5c%2e%2e%5c",
		"cb%2f..%2f",
		"cb%2f.%2f..%2f",
		"cb%5C%252e%252e%5C",
		"cb%252f.%252f..%252f",
		"cb%EF%BC%8F..%EF%BC%8F",
		"cb%c0%af..%c0%af",
		"cb%252fcb2%2f..%2f",
		"cb\\cb2/../",
		"cb%5ccb2/../",
		"cb%255ccb2%2f..%2f",
		"cb/%2e%2e/../../",
		"cb%2f%2e%2e/../",
		"cb%2f%2e%2e%2f..%2f",
	}

	// Create channels for work distribution
	urls := make(chan string)
	results := make(chan error)
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range urls {
				// Make initial request once for this URL
				printProgress("%s", targetURL)
				body1, resp1, err := makeRequest(client, targetURL)
				clearLine()
				if err != nil {
					if *verbose {
						fmt.Printf("Error making initial request to %s: %v\n", targetURL, err)
					}
					continue
				}
				defer fasthttp.ReleaseResponse(resp1)

				// Check for cache headers
				if !hasCacheHeaders(resp1) {
					if *verbose {
						fmt.Printf("No cache headers found for %s, skipping\n", targetURL)
					}
					continue
				}

				len1 := body1

				// Create channels for payload distribution
				payloadChan := make(chan string)
				payloadResults := make(chan bool)
				var payloadWg sync.WaitGroup
				foundIssue := false

				// Start payload workers
				for j := 0; j < *payloadWorkers; j++ {
					payloadWg.Add(1)
					go func() {
						defer payloadWg.Done()
						for payload := range payloadChan {
							if foundIssue {
								continue // Skip if we already found an issue
							}

							// Find the last slash in the URL without parsing
							if idx := strings.LastIndex(targetURL, "/"); idx != -1 {
								// Check if this is just the scheme separator
								if idx <= len("https://") {
									// This is just the scheme separator, append payload to root
									newURL := targetURL + "/" + payload
									// Only add trailing slash if there's no path at all
									if !strings.Contains(targetURL[idx+1:], "/") {
										newURL += "/"
									}

									// Process payload...
									if processPayload(client, targetURL, newURL, payload, len1) {
										foundIssue = true
										payloadResults <- true
										return
									}
								} else {
									// Normal case - inject payload before last path segment
									base := targetURL[:idx+1]
									path := targetURL[idx+1:]

									newURL := base + payload + path
									// Process payload...
									if processPayload(client, targetURL, newURL, payload, len1) {
										foundIssue = true
										payloadResults <- true
										return
									}
								}
							} else {
								// No slash found at all, append to root
								newURL := targetURL + "/" + payload
								// Only add trailing slash if there's no path at all
								if !strings.Contains(targetURL, "/") {
									newURL += "/"
								}

								// Process payload...
								if processPayload(client, targetURL, newURL, payload, len1) {
									foundIssue = true
									payloadResults <- true
									return
								}
							}
						}
					}()
				}

				// Feed payloads to workers
				go func() {
					for _, payload := range payloads {
						if foundIssue {
							break
						}
						payloadChan <- payload
					}
					close(payloadChan)
				}()

				// Wait for payload workers to finish or until an issue is found
				go func() {
					payloadWg.Wait()
					close(payloadResults)
				}()

				// Check if any worker found an issue
				for range payloadResults {
					// If we get here, an issue was found
					break
				}
			}
		}()
	}

	// Read URLs from stdin and send to workers
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls <- scanner.Text()
		}
		close(urls)
		if err := scanner.Err(); err != nil {
			results <- fmt.Errorf("error reading input: %v", err)
		}
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	for err := range results {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}

	// Cleanup connections before exit
	client.CloseIdleConnections()
}

// Helper function to process a single payload
func processPayload(client *fasthttp.Client, targetURL, newURL, payload string, len1 int64) bool {
	// Make second request with injected payload
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
	body3, resp3, err := makeRequest(client, finalURL)
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
		// Only report if difference is more than 30 chars
		if abs(len2-len3) > 30 {
			if *verbose {
				printVerbose("Verifying potential issue for %s", targetURL)
			}

			// Make a request with the same cache buster but without the payload
			baseURLWithoutPayload := targetURL
			if qIdx := strings.Index(baseURLWithoutPayload, "?"); qIdx != -1 {
				baseURLWithoutPayload = baseURLWithoutPayload[:qIdx]
			}
			verifyURL := baseURLWithoutPayload + "?zzz=" + randomStr
			printProgress("%s (no-payload verification)", verifyURL)
			lenVerifyNoPayload, respVerifyNoPayload, err := makeRequest(client, verifyURL)
			if respVerifyNoPayload != nil {
				defer fasthttp.ReleaseResponse(respVerifyNoPayload)
			}
			clearLine()

			if err != nil {
				printError("Making verification request to %s: %v", verifyURL, err)
			} else {
				// If the response with cache buster but no payload is similar to the response with payload and cache buster,
				// this indicates the size difference is not due to the payload
				if abs(len3-lenVerifyNoPayload) <= 30 {
					// High probability - the size difference is due to the payload
					printResult("[HIGH_PROBABILITY] Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d", targetURL, payload, len1, len2, len3)
					return true
				}
			}

			// Recheck with a different random parameter
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
			} else if abs(len2-len3Verify) > 30 {
				printResult("Potential issue at %s with payload '%s' - len1=%d len2=%d len3=%d", targetURL, payload, len1, len2, len3)
				return true
			}

			if *verbose {
				printVerbose("Issue not verified for %s, continuing with other payloads", targetURL)
			}
		}
	}
	return false
}
