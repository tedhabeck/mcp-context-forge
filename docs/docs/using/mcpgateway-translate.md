# MCP Gateway Transport Bridge (`mcpgateway.translate`)

`mcpgateway.translate` is a powerful command-line tool that bridges Model Context Protocol (MCP) servers across different transport protocols. It enables seamless communication between stdio/JSON-RPC, HTTP/SSE, and streamable HTTP protocols, making MCP servers accessible from various clients and environments.

## Overview

The transport bridge solves a common problem in MCP deployments: protocol incompatibility. Many MCP servers communicate via stdio (standard input/output), while web applications need HTTP-based protocols. This tool provides bidirectional bridging between:

- **Standard I/O (stdio)**: Traditional command-line MCP servers
- **Server-Sent Events (SSE)**: Real-time streaming for web browsers
- **Streamable HTTP**: Modern HTTP-based MCP protocol with session management

## Transport Modes

### 1. StdIO → SSE

Expose a local stdio-based MCP server over HTTP with Server-Sent Events.

**Use case**: Making command-line MCP servers accessible to web browsers.

```bash
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-git" \
  --expose-sse \
  --port 9000
```

**Endpoints**:
- `GET /sse` - SSE stream for receiving messages
- `POST /message` - Send JSON-RPC requests
- `GET /healthz` - Health check

### 2. SSE → StdIO

Connect to a remote SSE endpoint and bridge to local stdio process.

**Use case**: Integrating remote MCP servers with local CLI tools.

```bash
python3 -m mcpgateway.translate \
  --connect-sse "https://api.example.com/sse" \
  --stdioCommand "uvx mcp-client" \
  --oauth2Bearer "your-token"
```

### 3. StdIO → Streamable HTTP

Expose a local stdio MCP server via the streamable HTTP protocol.

**Use case**: Modern HTTP API with session management and flexible response modes.

```bash
# Stateful mode with SSE streaming
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-filesystem" \
  --expose-streamable-http \
  --port 9000

# Stateless mode with JSON responses
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-git" \
  --expose-streamable-http \
  --port 9000 \
  --stateless \
  --jsonResponse
```

**Endpoints**:
- `POST /mcp` - Handle MCP requests
- `GET /mcp` - SSE stream (when not in JSON response mode)
- `GET /healthz` - Health check

### 4. Streamable HTTP → StdIO

Bridge a remote streamable HTTP endpoint to local stdio.

**Use case**: Connecting cloud-hosted MCP servers to local development tools.

```bash
python3 -m mcpgateway.translate \
  --connect-streamable-http "https://api.example.com/mcp" \
  --stdioCommand "uvx mcp-client" \
  --oauth2Bearer "your-token"
```

### 5. Multi-Protocol Server (New!)

Expose a single stdio server via multiple protocols simultaneously.

**Use case**: Maximum compatibility - different clients can connect using their preferred protocol.

```bash
# Expose via both SSE and Streamable HTTP
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-time" \
  --expose-sse \
  --expose-streamable-http \
  --port 9000
```

## Features

| Feature | Description |
|---------|-------------|
| **Multi-protocol bridging** | Seamlessly convert between stdio, SSE, and streamable HTTP |
| **Bidirectional communication** | Full duplex message flow in all modes |
| **Session management** | Stateful sessions with event replay (streamable HTTP) |
| **Flexible response modes** | Choose between SSE streams or JSON responses |
| **Keep-alive support** | Automatic keepalive frames prevent connection timeouts |
| **CORS configuration** | Enable cross-origin requests for web applications |
| **Authentication** | OAuth2 Bearer token support for secure connections |
| **Health monitoring** | Built-in health check endpoint for container orchestration |
| **Graceful shutdown** | Clean process termination on SIGINT/SIGTERM |
| **Retry logic** | Automatic reconnection with exponential backoff |

## Installation

```bash
# Install from PyPI
pip install mcp-contextforge-gateway
```

## Command-Line Reference

### Basic Syntax

```bash
python3 -m mcpgateway.translate [TRANSPORT] [OPTIONS]
```

### Transport Options

#### Local Server (stdio)

##### `--stdio <command>`
Start a local process that communicates via stdio.

**Example**: `--stdio "uvx mcp-server-git"`

#### Exposure Options (use with --stdio)

##### `--expose-sse`
Expose the stdio server via Server-Sent Events protocol.

##### `--expose-streamable-http`
Expose the stdio server via streamable HTTP protocol.

**Note**: You can use both `--expose-sse` and `--expose-streamable-http` together to expose via multiple protocols simultaneously.

#### Remote Connection Options

##### `--connect-sse <url>`
Connect to a remote SSE endpoint.

**Example**: `--connect-sse "https://api.example.com/sse"`

##### `--connect-streamable-http <url>`
Connect to a remote streamable HTTP endpoint.

**Example**: `--connect-streamable-http "https://api.example.com/mcp"`

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--port <number>` | HTTP server port (local modes) | 8000 |
| `--host <address>` | Bind address (local modes) | 127.0.0.1 |
| `--cors <origins...>` | CORS allowed origins (space-separated) | None |
| `--oauth2Bearer <token>` | Bearer token for remote authentication | None |
| `--logLevel <level>` | Logging verbosity (debug/info/warning/error/critical) | info |
| `--stdioCommand <command>` | Local command for remote→stdio bridging | None |

### Streamable HTTP Options

| Option | Description | Default |
|--------|-------------|---------|
| `--stateless` | Use stateless mode (no session management) | False |
| `--jsonResponse` | Return JSON instead of SSE streams | False |

### SSE Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ssePath <path>` | SSE endpoint path | /sse |
| `--messagePath <path>` | Message POST endpoint path | /message |
| `--keepAlive <seconds>` | Keepalive interval | 30 |

## API Documentation

### SSE Mode Endpoints

#### `GET /sse`

Establishes an SSE connection for receiving MCP messages.

**Response**: Server-Sent Events stream

**Events**:
- `endpoint`: Initial bootstrap with unique message URL
- `message`: JSON-RPC responses from the MCP server
- `keepalive`: Periodic keepalive signals

**Example**:
```javascript
const evtSource = new EventSource('http://localhost:9000/sse');
evtSource.addEventListener('message', (event) => {
  const response = JSON.parse(event.data);
  console.log('MCP Response:', response);
});
```

#### `POST /message`

Send JSON-RPC requests to the MCP server.

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

**Response**: 202 Accepted or 400 Bad Request

### Streamable HTTP Mode Endpoints

#### `POST /mcp`

Handle MCP protocol requests.

**Stateless Mode Request**:
```bash
curl -X POST http://localhost:9000/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'
```

**Stateful Mode**: Includes session management headers

#### `GET /mcp`

Establish SSE stream for stateful sessions (when not using JSON response mode).

### Common Endpoints

#### `GET /healthz`

Health check endpoint for monitoring and orchestration.

**Response**: `200 OK` with body `"ok"`

## Complete Examples

### Web Application Integration

Expose a local MCP server for browser access:

```bash
# Start the bridge
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-filesystem --directory ./docs" \
  --expose-sse \
  --port 9000 \
  --cors "http://localhost:3000" "https://myapp.com"

# In your web app
const response = await fetch('http://localhost:9000/message', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'resources/list'
  })
});
```

### Corporate Proxy Setup

Bridge internal MCP servers to external clients:

```bash
# On proxy server
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-internal" \
  --expose-streamable-http \
  --port 443 \
  --host 0.0.0.0 \
  --stateless \
  --cors "*"

# From external client
python3 -m mcpgateway.translate \
  --connect-streamable-http "https://proxy.corp.com/mcp" \
  --oauth2Bearer "$CORP_TOKEN" \
  --stdioCommand "local-mcp-client"
```

### Development Environment

Quick setup for testing MCP servers:

```bash
# Terminal 1: Start server bridge
python3 -m mcpgateway.translate \
  --stdio "uvx mcp-server-git" \
  --expose-sse \
  --port 9001 \
  --logLevel debug

# Terminal 2: Test with curl
curl -X POST http://localhost:9001/message \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Terminal 3: Watch SSE stream
curl -N http://localhost:9001/sse
```

### Container Deployment

```dockerfile
FROM python:3.11-slim
RUN pip install mcpgateway mcp
EXPOSE 8000
HEALTHCHECK CMD curl -f http://localhost:8000/healthz || exit 1
CMD ["python", "-m", "mcpgateway.translate", \
     "--stdio", "uvx mcp-server-sqlite", \
     "--expose-streamable-http", \
     "--port", "8000", \
     "--host", "0.0.0.0", \
     "--stateless"]
```

## Protocol Comparison

| Feature | SSE | Streamable HTTP |
|---------|-----|-----------------|
| **Streaming** | ✅ Yes | ✅ Optional |
| **Bidirectional** | ✅ Via backchannel | ✅ Native |
| **Session Management** | ❌ No | ✅ Optional |
| **Event Replay** | ❌ No | ✅ Yes |
| **JSON Response Mode** | ❌ No | ✅ Yes |
| **Browser Support** | ✅ Native EventSource | ✅ Fetch API |
| **Complexity** | Simple | Moderate |

## Troubleshooting

### Common Issues

#### "MCP server components are required"
**Solution**: Install the MCP library
```bash
pip install mcp
```

#### Connection timeouts with SSE
**Solution**: Adjust keepalive interval
```bash
--keepAlive 15  # More frequent keepalives
```

#### CORS errors in browser
**Solution**: Configure allowed origins
```bash
--cors "http://localhost:3000" "https://yourapp.com"
```

#### Authentication failures
**Solution**: Verify token format
```bash
--oauth2Bearer "Bearer your-token"  # Note: Include "Bearer" prefix if required
```

### Debug Mode

Enable detailed logging to troubleshoot issues:

```bash
python3 -m mcpgateway.translate \
  --stdio "your-mcp-server" \
  --port 9000 \
  --logLevel debug
```

## Performance Considerations

### Stateless vs Stateful

- **Stateless** (`--stateless`): Better for high-volume, short-lived connections
- **Stateful**: Better for long-running sessions with context preservation

### JSON vs SSE Responses

- **JSON** (`--jsonResponse`): Lower latency, simpler client implementation
- **SSE**: Real-time streaming, better for continuous updates

### Connection Pooling

When bridging to remote endpoints, connections are reused with automatic retry:
- Initial retry delay: 1 second
- Exponential backoff: Up to 30 seconds
- Maximum retries: 5 (configurable in code)

## Security Best Practices

1. **Bind to localhost** by default (`--host 127.0.0.1`)
2. **Use CORS restrictions** to limit allowed origins
3. **Enable authentication** with `--oauth2Bearer` for remote endpoints
4. **Run with minimal privileges** in production
5. **Use HTTPS** when exposing to public networks (reverse proxy recommended)

## Integration with MCP Gateway

This tool complements the full MCP Gateway by providing:
- Lightweight alternative for simple bridging needs
- Development and testing utility
- Protocol conversion without full gateway features

For production deployments requiring:
- Multiple server management
- Persistent configuration
- Advanced routing
- Admin UI

Consider using the full [MCP Gateway](../overview/index.md).

## Advanced Configuration

### Environment Variables

All command-line options can be set via environment variables:

```bash
export MCPGATEWAY_PORT=9000
export MCPGATEWAY_LOG_LEVEL=debug
export MCPGATEWAY_CORS_ORIGINS="http://localhost:3000"
python3 -m mcpgateway.translate --stdio "mcp-server"
```

### Custom Headers

For advanced authentication scenarios, modify the code to add custom headers:

```python
headers = {
    "Authorization": f"Bearer {token}",
    "X-API-Key": api_key,
    "X-Request-ID": request_id
}
```

## Notes

- **Protocol Support**: All three protocols (stdio, SSE, streamable HTTP) are fully implemented
- **Dependencies**: Streamable HTTP requires `pip install mcp`
- **Bidirectional Flow**: Use `--stdioCommand` for remote→local bridging
- **Performance**: Stateless mode recommended for high-traffic scenarios
- **Compatibility**: Works with all MCP-compliant servers and clients

## Related Documentation

- [MCP Gateway Overview](../overview/index.md)
- [MCP Protocol Specification](https://modelcontextprotocol.io)
- [Transport Protocols](../architecture/index.md#system-architecture)
- [Authentication Guide](../manage/securing.md)

## Support

For issues, feature requests, or contributions:
- GitHub: [mcp-context-forge](https://github.com/contingentai/mcp-context-forge)
- Issues: [Report bugs](https://github.com/contingentai/mcp-context-forge/issues)
