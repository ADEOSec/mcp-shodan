# Shodan MCP Server

A Model Context Protocol (MCP) server that provides access to Shodan's powerful API capabilities. This server allows you to perform various network intelligence operations including host information lookup, DNS resolution, reverse DNS lookup, and domain information retrieval.

## Features

- **Host Information**: Get detailed information about any IP address including open ports, services, and location data
- **DNS Lookup**: Resolve hostnames to IP addresses
- **Reverse DNS**: Look up hostnames for IP addresses
- **Domain Information**: Retrieve DNS entries and subdomains for any domain

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Shodan API Key ([Get one here](https://account.shodan.io/))

## Installation

1. Clone the repository
2. Install dependencies:
```bash
cd shodan-mcp-server
npm install
```

3. Create a `.env` file in the root directory and add your Shodan API key:
```bash
SHODAN_API_KEY=your_api_key_here
```

## Building

```bash
npm run build
```

## Running the Server

You can run the server using one of the following methods:

### Development Mode
```bash
npm run dev -- --api-key YOUR_API_KEY
```

### Production Mode
```bash
npm run build
npm start -- --api-key YOUR_API_KEY
```

## Available Tools

### 1. Host Information
Get detailed information about a specific IP address.

Parameters:
- `ip` (required): IP address to look up
- `history` (optional): Include historical information (default: false)
- `minify` (optional): Return only basic host information (default: false)

### 2. DNS Lookup
Resolve hostnames to IP addresses.

Parameters:
- `hostnames` (required): Comma-separated list of hostnames (e.g., 'google.com,facebook.com')

### 3. Reverse DNS
Look up hostnames for IP addresses.

Parameters:
- `ips` (required): Comma-separated list of IP addresses (e.g., '8.8.8.8,1.1.1.1')

### 4. Domain Information
Get DNS entries and subdomains for a domain.

Parameters:
- `domain` (required): Domain name to look up (e.g., 'example.com')

### 5. Hello
Test if the Shodan MCP server is working.

## Technical Details

- Built with TypeScript
- Uses the Model Context Protocol SDK
- Implements proper error handling and rate limiting
- Supports ES modules
- Includes type definitions for all Shodan API responses

## License

MIT

## Author

Halil Ozturkci
