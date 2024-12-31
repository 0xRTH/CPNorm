# CPNorm - Cache Poisoning Normalization Testing Tool

A Go-based tool for testing web cache poisoning vulnerabilities through path normalization.

## Features

- Tests multiple path normalization techniques
- Supports concurrent URL testing
- Automatic cache header detection
- Verification of potential issues
- Connection pooling and reuse
- Proxy support

## Installation

```bash
go install github.com/0xRTH/CPNorm@latest
```

## Usage

```bash
# Basic usage
cat urls.txt | CPNorm

# With verbose output
cat urls.txt | CPNorm -v

# With proxy (e.g., Burp Suite)
cat urls.txt | CPNorm -proxy

# Configure workers
cat urls.txt | CPNorm -t 20 -p 3
```

### Options

- `-v`: Enable verbose output
- `-proxy`: Use local proxy (127.0.0.1:8080)
- `-t`: Number of concurrent URL workers (default: 20)
- `-p`: Number of payload workers per URL (default: 3)

## Input

The tool reads URLs from stdin, one per line.

## Output

When potential issues are found, the tool outputs them in the format:
```
Potential issue at [URL] with payload '[PAYLOAD]' - len1=[LENGTH1] len2=[LENGTH2] len3=[LENGTH3]
``` 