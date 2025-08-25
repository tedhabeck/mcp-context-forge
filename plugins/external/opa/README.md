# OPAPluginFilter for Context Forge MCP Gateway

An OPA plugin that enforces rego policies on requests and allows/denies requests as per policies.


## Installation

To install dependencies with dev packages (required for linting and testing):

```bash
make install-dev
```

Alternatively, you can also install it in editable mode:

```bash
make install-editable
```

## Setting up the development environment

1. Copy .env.template .env
2. Enable plugins in `.env`

## Testing

Test modules are created under the `tests` directory.

To run all tests, use the following command:

```bash
make test
```

**Note:** To enable logging, set `log_cli = true` in `tests/pytest.ini`.

## Code Linting

Before checking in any code for the project, please lint the code.  This can be done using:

```bash
make lint-fix
```

## Runtime (server)

This project uses [chuck-mcp-runtime](https://github.com/chrishayuk/chuk-mcp-runtime) to run external plugins as a standardized MCP server.

To build the container image:

```bash
make build
```

To run the container:

```bash
make start
```

To stop the container:

```bash
make stop
```
