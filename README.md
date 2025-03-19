# Shodan MCP Server

A Model Context Protocol (MCP) server that provides access to Shodan's powerful API capabilities. This server allows you to perform various network intelligence operations including host information lookup, DNS operations, network scanning, alerts management, and account management.

## Features

### MCP Capabilities
- **Tools**: Execute various Shodan API operations through standardized tools
- **Resources**: Access Shodan data through URI-based resources
- **Prompts**: Use pre-defined templates for security analysis

### Host Information & DNS Operations
- **Host Information**: Get detailed information about any IP address including open ports, services, and location data
- **DNS Lookup**: Resolve hostnames to IP addresses
- **Reverse DNS**: Look up hostnames for IP addresses
- **Domain Information**: Retrieve DNS entries and subdomains for any domain

### Search Capabilities
- **Host Search**: Search Shodan's database using powerful filters and facets
- **Search Count**: Get the number of results for a search query without consuming credits
- **Search Facets**: List and use available facets for summarizing data
- **Search Filters**: Access all available search filters
- **Query Analysis**: Break down search queries into tokens for analysis

### Network Scanning
- **Port List**: View all ports that Shodan is actively scanning
- **Protocol List**: Access available protocols for Internet scanning
- **On-Demand Scanning**: Request scans of specific IPs or networks
- **Scan Management**: Track and manage your scan requests

### Network Alerts
- **Alert Creation**: Set up monitoring for specific IPs and ports
- **Alert Management**: View, edit, and delete network alerts
- **Trigger List**: Access available alert triggers
- **Alert Status**: Monitor the status of your alerts

### Directory Services
- **Saved Queries**: List and search through saved Shodan queries
- **Query Tags**: View popular tags for saved queries
- **Query Management**: Access and organize your saved searches

### Account Management
- **Profile Information**: View your account details
- **API Status**: Check your API subscription and usage
- **Billing Information**: Access your billing profile

### Utility Tools
- **HTTP Headers**: View your client's HTTP headers
- **IP Address**: Check your current Internet-facing IP

### CVEDB Tools
13. **cve-lookup**
    - Get detailed information about a specific CVE
    - Parameters:
      - `cve` (required): CVE ID to look up (e.g., CVE-2021-44228)

14. **cpe-vuln-search**
    - Search for vulnerabilities by CPE
    - Parameters:
      - `cpe` (required): CPE 2.3 string to search for
      - `minCvss` (optional): Minimum CVSS score (0-10)
      - `maxResults` (optional): Maximum number of results to return

15. **latest-vulns**
    - Get latest published vulnerabilities
    - Parameters:
      - `days` (optional): Number of days to look back
      - `minEpss` (optional): Minimum EPSS score (0-1)
      - `kevOnly` (optional): Show only Known Exploited Vulnerabilities

16. **product-vuln-analysis**
    - Analyze vulnerabilities for a product
    - Parameters:
      - `vendor` (required): Vendor name
      - `product` (required): Product name
      - `version` (optional): Product version
      - `timeframe` (optional): Days to look back

17. **cpe-search**
    - Search for CPE 2.3 entries
    - Parameters:
      - `query` (required): Product name to search for
      - `maxResults` (optional): Maximum number of results to return

## CVEDB API Integration

The Shodan MCP Server now includes integration with the CVEDB API (https://cvedb.shodan.io), providing enhanced vulnerability analysis capabilities:

### Features
- Detailed CVE information lookup with CVSS and EPSS scores
- CPE-based vulnerability searching
- Latest vulnerability monitoring
- Product-specific vulnerability analysis
- CPE dictionary search functionality

### Key Concepts
- **CVSS**: Common Vulnerability Scoring System
- **EPSS**: Exploit Prediction Scoring System
- **KEV**: Known Exploited Vulnerabilities
- **CPE**: Common Platform Enumeration

### Example Usage

1. Looking up a specific CVE:
```bash
cve-lookup --cve CVE-2021-44228
```

2. Searching vulnerabilities for a CPE:
```bash
cpe-vuln-search --cpe "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" --minCvss 7.0
```

3. Getting latest vulnerabilities:
```bash
latest-vulns --days 7 --minEpss 0.5 --kevOnly true
```

4. Analyzing product vulnerabilities:
```bash
product-vuln-analysis --vendor apache --product log4j --version 2.0
```

5. Searching CPE dictionary:
```bash
cpe-search --query "nginx" --maxResults 20
```

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

## Available Resources

### Host Information Resource
- **URI Template**: `shodan://host/{ip}`
- **Description**: Get detailed host information including open ports, services, and vulnerabilities
- **Response Format**: JSON
- **Example**: `shodan://host/8.8.8.8`

### Domain Information Resource
- **URI Template**: `shodan://domain/{domain}`
- **Description**: Get DNS entries and subdomains for a domain
- **Response Format**: JSON
- **Example**: `shodan://domain/example.com`

### Search Results Resource
- **URI Template**: `shodan://search/{query}`
- **Description**: Get search results for a specific Shodan query
- **Response Format**: JSON
- **Example**: `shodan://search/apache%20country:DE`

### Network Alerts Resource
- **URI Template**: `shodan://alerts/{id}`
- **Description**: Get information about network alerts (use "all" for all alerts)
- **Response Format**: JSON
- **Example**: `shodan://alerts/all`

### Scan Status Resource
- **URI Template**: `shodan://scan/{id}`
- **Description**: Get the status and results of a specific network scan
- **Response Format**: JSON
- **Example**: `shodan://scan/SCAN_ID`

### Query Directory Resource
- **URI Template**: `shodan://queries/{type}`
- **Description**: Access saved queries and tags (type can be "list" or "tags")
- **Response Format**: JSON
- **Example**: `shodan://queries/tags`

### API Status Resource
- **URI Template**: `shodan://api/status`
- **Description**: Get information about the current API key's status and usage
- **Response Format**: JSON
- **Example**: `shodan://api/status`

## Available Prompts

### Security Assessment Prompt
- **Name**: `security-assessment`
- **Description**: Analyze the security posture of an IP or domain
- **Arguments**:
  - `target` (required): IP address or domain to analyze
  - `depth` (optional): Analysis depth (basic, standard, deep)

### Vulnerability Analysis Prompt
- **Name**: `vuln-analysis`
- **Description**: Analyze vulnerabilities for a specific target
- **Arguments**:
  - `target` (required): IP address to analyze
  - `timeframe` (optional): History timeframe to consider

### Enhanced Vulnerability Assessment Prompt
- **Name**: `enhanced-vuln-assessment`
- **Description**: Perform detailed vulnerability assessment with severity filtering
- **Arguments**:
  - `target` (required): IP address or domain to analyze
  - `severityThreshold` (optional): Minimum severity level to include (low, medium, high, critical)
  - `priorityLevel` (optional): Priority level for remediation (low, medium, high)

### Network Topology Analysis Prompt
- **Name**: `network-topology`
- **Description**: Analyze network topology and suggest visualizations
- **Arguments**:
  - `target` (required): IP range or domain to analyze
  - `scanType` (optional): Type of scan (basic, detailed, comprehensive)
  - `compareWithPrevious` (optional): Compare with previous scan results (true/false)

### IoT Device Discovery Prompt
- **Name**: `iot-discovery`
- **Description**: Discover and analyze IoT devices in the network
- **Arguments**:
  - `target` (required): Network range to scan for IoT devices
  - `deviceType` (optional): Specific type of IoT device to look for
  - `manufacturer` (optional): Specific manufacturer to filter by
  - `protocol` (optional): Specific protocol to search for

### Security Posture Evaluation Prompt
- **Name**: `security-posture`
- **Description**: Evaluate security posture against compliance frameworks
- **Arguments**:
  - `target` (required): Target network or domain to evaluate
  - `complianceFramework` (optional): Compliance framework to evaluate against (NIST, ISO, etc.)
  - `includeRemediation` (optional): Include detailed remediation steps (true/false)

### Threat Intelligence Integration Prompt
- **Name**: `threat-intel`
- **Description**: Analyze threat intelligence and provide risk assessment
- **Arguments**:
  - `target` (required): IP or domain to analyze
  - `threatSource` (optional): Specific threat intelligence source to use
  - `riskLevel` (optional): Minimum risk level to include (low, medium, high)

## Available Tools

### Host Information & DNS
1. **host-info**
   - Get detailed information about a host
   - Parameters:
     - `ip` (required): IP address to look up
     - `history` (optional): Include historical information
     - `minify` (optional): Return only basic host information

2. **dns-lookup**
   - Resolve hostnames to IP addresses
   - Parameters:
     - `hostnames` (required): Comma-separated list of hostnames

3. **reverse-dns**
   - Look up hostnames for IP addresses
   - Parameters:
     - `ips` (required): Comma-separated list of IP addresses

4. **domain-info**
   - Get DNS entries and subdomains for a domain
   - Parameters:
     - `domain` (required): Domain name to look up

### Search Tools
5. **search-host**
   - Search Shodan's database
   - Parameters:
     - `query` (required): Shodan search query
     - `facets` (optional): Properties for summary information
     - `page` (optional): Results page number

6. **search-host-count**
   - Get number of results for a search
   - Parameters:
     - `query` (required): Search query
     - `facets` (optional): Summary properties

7. **list-search-facets**
   - List available search facets
   - No parameters required

8. **list-search-filters**
   - List available search filters
   - No parameters required

9. **search-tokens**
   - Analyze search query structure
   - Parameters:
     - `query` (required): Query to analyze

### Network Scanning
10. **list-ports**
    - List ports Shodan is scanning
    - No parameters required

11. **list-protocols**
    - List available scanning protocols
    - No parameters required

12. **request-scan**
    - Request a network scan
    - Parameters:
      - `ips` (required): IPs/networks to scan

13. **get-scan-status**
    - Check scan progress
    - Parameters:
      - `id` (required): Scan ID

14. **list-scans**
    - List all submitted scans
    - No parameters required

### Network Alerts
15. **list-triggers**
    - List available alert triggers
    - No parameters required

16. **create-alert**
    - Create a network alert
    - Parameters:
      - `name` (required): Alert name
      - `filters` (required): IP/port filters
      - `expires` (optional): Expiration time

17. **get-alert-info**
    - Get alert details
    - Parameters:
      - `id` (required): Alert ID

18. **delete-alert**
    - Delete an alert
    - Parameters:
      - `id` (required): Alert ID

19. **edit-alert**
    - Modify an alert
    - Parameters:
      - `id` (required): Alert ID
      - `name` (optional): New name
      - `filters` (optional): New filters

20. **list-alerts**
    - List all active alerts
    - No parameters required

### Directory Methods
21. **list-queries**
    - List saved searches
    - Parameters:
      - `page` (optional): Page number
      - `sort` (optional): Sort by votes/timestamp
      - `order` (optional): Sort order

22. **search-queries**
    - Search saved queries
    - Parameters:
      - `query` (required): Search term
      - `page` (optional): Page number

23. **list-query-tags**
    - List popular query tags
    - Parameters:
      - `size` (optional): Number of tags

### Account Management
24. **get-profile**
    - Get account information
    - No parameters required

25. **get-api-info**
    - Get API subscription details
    - No parameters required

26. **get-billing**
    - Get billing information
    - No parameters required

### Utility Tools
27. **get-http-headers**
    - View your HTTP headers
    - No parameters required

28. **get-my-ip**
    - Get your current IP
    - No parameters required

29. **hello**
    - Test server connection
    - No parameters required

## Technical Details

- Built with TypeScript
- Uses the Model Context Protocol SDK
- Implements proper error handling and rate limiting
- Supports ES modules
- Includes comprehensive type definitions
- Markdown-formatted output
- Proper error handling for all API calls
- Supports Resources, Tools, and Prompts capabilities

## Credit Usage

- Host lookups: 1 credit per lookup
- Search queries: 1 credit per page after first page
- On-demand scans: 1 credit per IP
- Network alerts: Credits vary by alert type

## License

MIT

## Author

Halil Ozturkci
