package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var customTransport = http.DefaultTransport

func extractCredentials(authHeader string) (string, string, bool) {
	if authHeader == "" {
		return "", "", false
	}

	// Assuming the format is "Basic base64(username:password)"
	credentials, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return "", "", false
	}

	// Split the decoded credentials into username and password
	pair := strings.SplitN(string(credentials), ":", 2)
	if len(pair) != 2 {
		return "", "", false
	}

	return pair[0], pair[1], true
}

func authenticateRequest(r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok {
		// Try to extract credentials from Proxy-Authorization header
		proxyAuthHeader := r.Header.Get("Proxy-Authorization")
		username, password, ok = extractCredentials(proxyAuthHeader)
	}

	if !ok {
		authHeader := r.Header.Get("Authorization")
		username, password, ok = extractCredentials(authHeader)
	}
	// Here can custom logic or use env variables
	// Check for valid credentials
	validUsername := os.Getenv("PROXY_USERNAME")
	if len(validUsername) == 0 {
		validUsername = "primewalker"
	}
	validPassword := os.Getenv("PROXY_PASSWORD")
	if len(validPassword) == 0 {
		validPassword = "primewalker"
	}
	return username == validUsername && password == validPassword
}

func init() {
	//Here can custom transport
	customTransport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,

		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL
	startTime := time.Now()

	if !authenticateRequest(r) {
		// If authentication fails, send a 401 Unauthorized response
		log.Printf("[%s] Unauthorized request from %s\n", time.Since(startTime), r.RemoteAddr)
		w.Header().Set("Proxy-Authenticate", `Basic realm="login"`)
		http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
		return
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		log.Printf("[%s] Error creating proxy request: %v\n", time.Since(startTime), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	// Handle HTTPS requests
	if r.Method == http.MethodConnect {
		handleConnect(w, proxyReq, startTime)
		return
	}

	resp, err := customTransport.RoundTrip(proxyReq)
	if err != nil {
		log.Printf("[%s] Error proxy in round trip request: %v\n", time.Since(startTime), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleConnect(w http.ResponseWriter, r *http.Request, startTime time.Time) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[%s] Error hijacking connection: %v\n", time.Since(startTime), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Establish tunnel
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("[%s] Error establishing tunnel: %v\n", time.Since(startTime), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer targetConn.Close()

	// Respond to the client that the tunnel is established
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// Copy data between client and target
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)

	// Log the request
	log.Printf("[%s] %s %s %s 200\n", time.Since(startTime), r.RemoteAddr, r.Method, r.Host)
}

func getPort() string {
	serverPort, serverPortExists := os.LookupEnv("PROXY_SERVER_PORT")
	if !serverPortExists || len(serverPort) == 0 {
		serverPort = "3030"
	}
	return serverPort
}

func main() {
	server := http.Server{
		Addr:    ":" + getPort(),
		Handler: http.HandlerFunc(handleRequest),
	}

	log.Println("Starting proxy server on port " + getPort())
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal("Error starting proxy server", err)
	}
}
