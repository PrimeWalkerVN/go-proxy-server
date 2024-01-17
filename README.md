# Simple Proxy Server in Go

This is a basic proxy server implemented in Go that supports HTTP and HTTPS traffic.

## Features

- Supports HTTP and HTTPS traffic using the CONNECT method.
- Basic authentication for proxy access.
- Handles HTTP requests and establishes a tunnel for HTTPS requests.

## Usage

1. **Clone the repository:**
   
   ```bash
   git clone https://github.com/yourusername/proxy-server.git

2. Navigate to the project directory:
   ```bash
   cd proxy-server

3. Build the proxy server:
   ```
   go build main.go
   ```
4. Run the proxy server:
   ```
   ./main
   ```
5. Use a client to connect through the proxy. For example, using cURL:
   ```
   curl -x http://localhost:3030 http://example.com
   ```

## Security Considerations
- This is a basic example and may not be suitable for production use.
- Consider implementing proper certificate validation for HTTPS traffic.
- Use strong and secure authentication mechanisms for production use.

## Configuration and Environment Variables

The following environment variables can be used to configure the proxy server:

- **PROXY_SERVER_PORT:** The port on which the proxy server will listen. Defaults to `3030`.

- **PROXY_USERNAME:** The username required for proxy authentication. Defaults to `primewalker`.

- **PROXY_PASSWORD:** The password required for proxy authentication. Defaults to `primewalker`.

### Example Usage:

```bash
export PROXY_SERVER_PORT=3030
export PROXY_USERNAME=myuser
export PROXY_PASSWORD=mypassword
./main






