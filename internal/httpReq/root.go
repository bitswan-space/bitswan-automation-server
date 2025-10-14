package httpReq
/*
   This package patches the golang DNS resolver to resolve *.localhost to localhost just as many other linux resolvers work.
 */

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
    "context"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

// NewRequestWithLocalhostResolution creates an HTTP request that automatically
// resolves .localhost domains to 127.0.0.1
func NewRequest(method, url string, body io.Reader) (*http.Request, error) {
    // Create the standard request
    req, err := http.NewRequest(method, url, body)
    if err != nil {
        return nil, err
    }

    // No need to store the client in context - this function just returns the request
    return req, nil
}

// loadMkcertCA loads the mkcert CA certificate if available
func loadMkcertCA() (*x509.CertPool, error) {
    // Try to get mkcert CA root using mkcert -CAROOT command
    cmd := exec.Command("mkcert", "-CAROOT")
    output, err := cmd.Output()
    if err != nil {
        // mkcert is not installed or not available
        return nil, fmt.Errorf("mkcert not available: %w", err)
    }
    
    // Get the CA root path from mkcert output
    caRootPath := strings.TrimSpace(string(output))
    if caRootPath == "" {
        return nil, fmt.Errorf("mkcert returned empty CA root path")
    }
    
    caCertPath := filepath.Join(caRootPath, "rootCA.pem")
    
    // Check if mkcert CA exists
    if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
        return nil, fmt.Errorf("mkcert CA not found at %s", caCertPath)
    }
    
    // Read the CA certificate
    caCert, err := os.ReadFile(caCertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read mkcert CA certificate: %w", err)
    }
    
    // Create a certificate pool and add the mkcert CA
    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return nil, fmt.Errorf("failed to parse mkcert CA certificate")
    }
    
    return caCertPool, nil
}

// ExecuteRequestWithLocalhostResolution executes a request with .localhost resolution
func ExecuteRequestWithLocalhostResolution(req *http.Request) (*http.Response, error) {
    // Load mkcert CA if available
    var caCertPool *x509.CertPool
    if mkcertCA, mkcertErr := loadMkcertCA(); mkcertErr == nil {
        caCertPool = mkcertCA
    }

    // Create a transport with custom dialing for .localhost domains
    transport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
            if err != nil {
                return nil, err
            }

            if strings.HasSuffix(host, ".localhost") {
                // Force localhost resolution for .localhost domains
                return net.Dial(network, net.JoinHostPort("127.0.0.1", port))
            }

            // Use normal resolution for other domains
            return (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext(ctx, network, addr)
        },
    }

    // Configure TLS based on whether we have mkcert CA and if it's a .localhost domain
    if strings.HasSuffix(req.URL.Hostname(), ".localhost") && caCertPool != nil {
        // For .localhost domains with mkcert CA available, use the mkcert CA
        transport.TLSClientConfig = &tls.Config{
            RootCAs: caCertPool,
        }
    } else {
        // For other domains or when mkcert CA is not available, use system default TLS config
        transport.TLSClientConfig = &tls.Config{}
    }

    // Create a client with our custom transport
    client := &http.Client{Transport: transport}

    // Execute the request with our custom client
    return client.Do(req)
}

