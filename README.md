# Shodan MCP Server

> Developed by ADEO Cybersecurity Services

A Model Context Protocol (MCP) server that provides access to Shodan's powerful API capabilities. This server, developed and maintained by ADEO Cybersecurity Services, enables cybersecurity analysts to perform network intelligence operations including host information lookup, DNS operations, vulnerability analysis, network scanning, and alerts management through a collection of tools and prompt templates.

## About ADEO Cybersecurity Services

ADEO Cybersecurity Services specializes in providing advanced security solutions and tools for cybersecurity professionals. This Shodan MCP Server is part of our commitment to enhancing cybersecurity capabilities through innovative tools and integrations with industry-leading security data sources.

## Features

### Host Information & DNS Operations
- Detailed information about IP addresses including open ports, services, and location data
- DNS lookup and reverse DNS operations
- Domain information retrieval including subdomains

### Search Capabilities
- Search Shodan's database using powerful filters and facets
- Statistical analysis of search results
- Token-based query analysis

### Network Scanning
- On-demand scanning of specific IPs or networks
- Scan status monitoring and management
- Access to Shodan's scanning protocols and ports

### Network Alerts
- Set up and manage network monitoring alerts
- Configure alert triggers and notifications
- Track and manage security events

### Vulnerability Analysis
- Search for specific vulnerabilities (CVEs)
- Check vulnerability details and analysis
- Hunt for vulnerable systems

### Account Management
- View profile information and API usage
- Check subscription status

## Available Tools

### Host & DNS Tools
1. **host-info**
   - Get detailed information about a host from Shodan
   - Parameters:
     - `ip` (required): IP address to look up
     - `history` (optional): Include historical information
     - `minify` (optional): Return only basic host information

2. **dns-lookup**
   - Resolve hostnames to IP addresses
   - Parameters:
     - `hostnames` (required): Comma-separated list of hostnames to resolve

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
   - Search Shodan for hosts matching specific criteria
   - Parameters:
     - `query` (required): Shodan search query
     - `facets` (optional): Comma-separated list of properties for summary information
     - `page` (optional): Page number for results

6. **search-host-count**
   - Search Shodan without results (just count and facets)
   - Parameters:
     - `query` (required): Shodan search query
     - `facets` (optional): Comma-separated list of facets

7. **list-search-facets**
   - List all available search facets

8. **list-search-filters**
   - List all filters that can be used when searching

9. **search-tokens**
   - Break the search query into tokens for analysis
   - Parameters:
     - `query` (required): Shodan search query to analyze

### Network Scanning Tools
10. **list-ports**
    - List all ports that Shodan is crawling on the Internet

11. **list-protocols**
    - List all protocols that can be used for scanning

12. **request-scan**
    - Request Shodan to scan an IP/network
    - Parameters:
      - `ips` (required): Comma-separated list of IPs or networks in CIDR notation

13. **get-scan-status**
    - Get the status of a scan request
    - Parameters:
      - `id` (required): The unique scan ID returned by request-scan

14. **list-scans**
    - Get list of all submitted scans

### Network Alert Tools
15. **list-triggers**
    - List available triggers for network alerts

16. **create-alert**
    - Create a network alert for monitoring
    - Parameters:
      - `name` (required): Name of the alert
      - `filters` (required): Filters to apply (can include IP addresses and ports)
      - `expires` (optional): Number of seconds the alert should be active

17. **get-alert-info**
    - Get information about a specific alert
    - Parameters:
      - `id` (required): Alert ID to get information about

18. **delete-alert**
    - Delete a network alert
    - Parameters:
      - `id` (required): Alert ID to delete

19. **edit-alert**
    - Edit an existing alert
    - Parameters:
      - `id` (required): Alert ID to edit
      - `name` (optional): New name for the alert
      - `filters` (optional): New filters to apply

20. **list-alerts**
    - List all active alerts

### Directory Tools
21. **list-queries**
    - List saved search queries
    - Parameters:
      - `page` (optional): Page number of results
      - `sort` (optional): Sort queries by (votes or timestamp)
      - `order` (optional): Sort order (asc or desc)

22. **search-queries**
    - Search through saved queries
    - Parameters:
      - `query` (required): Search term to find queries
      - `page` (optional): Page number of results

23. **list-query-tags**
    - List popular tags for saved queries
    - Parameters:
      - `size` (optional): Number of tags to return

### Account Tools
24. **get-profile**
    - Get account profile information

25. **get-api-info**
    - Get API subscription information

26. **get-billing**
    - Get billing profile information

27. **get-http-headers**
    - View the HTTP headers that you're sending in requests

28. **get-my-ip**
    - View your current IP address

### Vulnerability Tools
29. **cve-lookup**
    - Get detailed information about a CVE
    - Parameters:
      - `cve` (required): CVE ID to look up (e.g., CVE-2021-44228)

30. **cpe-vuln-search**
    - Search for vulnerabilities by CPE
    - Parameters:
      - `cpe` (required): CPE 2.3 string to search for
      - `minCvss` (optional): Minimum CVSS score (0-10)
      - `maxResults` (optional): Maximum number of results to return

## Consolidated Analysis Prompts

The server provides streamlined prompt templates for comprehensive cybersecurity analysis workflows:

### 1. Asset Discovery and Reconnaissance
- **Name**: `asset-discovery`
- **Description**: Discover and analyze internet-facing assets and infrastructure
- **Arguments**:
  - `target` (required): Domain, IP address, or organization name to analyze
  - `depth` (optional): Depth of reconnaissance ("basic" or "comprehensive")
- **Example**:
  ```
  @shodan asset-discovery target=acme.com depth=comprehensive
  ```

### 2. Vulnerability Assessment
- **Name**: `vulnerability-assessment`
- **Description**: Find vulnerabilities in internet-connected systems
- **Arguments**:
  - `target_type` (required): Type of target to analyze ("host", "domain", "cpe", "cve")
  - `target` (required): Target identifier (IP, domain, CPE string, or CVE ID)
  - `severity_threshold` (optional): Minimum severity threshold ("all", "medium", "high", "critical")
- **Example**:
  ```
  @shodan vulnerability-assessment target_type=host target=192.168.1.1 severity_threshold=high
  ```

### 3. Internet Search
- **Name**: `internet-search`
- **Description**: Search for specific internet-connected systems or services
- **Arguments**:
  - `query` (required): Shodan search query to execute
  - `facets` (optional): Optional facets for statistical breakdown (comma-separated)
  - `page_limit` (optional): Maximum number of results pages to retrieve
- **Example**:
  ```
  @shodan internet-search query="apache country:US port:443" facets="org,os"
  ```

### 4. Security Monitoring
- **Name**: `security-monitoring`
- **Description**: Setup and manage network security monitoring alerts
- **Arguments**:
  - `action` (required): Alert management action ("create", "review", "modify", "delete")
  - `target_type` (optional): Type of target to monitor ("ip", "service", "vulnerability", "custom")
  - `target` (optional): Target to monitor (IP, service name, or vulnerability)
  - `alert_id` (optional): Alert ID for modification or review
- **Example**:
  ```
  @shodan security-monitoring action=create target_type=ip target=8.8.8.8
  ```

### 5. ICS Analysis
- **Name**: `ics-analysis`
- **Description**: Analyze exposed industrial control systems and SCADA devices
- **Arguments**:
  - `target_type` (required): Type of target to analyze ("ip", "network", "product", "country")
  - `target` (required): Target identifier (IP, network range, product name, or country code)
  - `protocol` (optional): Optional specific protocol to focus on
- **Example**:
  ```
  @shodan ics-analysis target_type=country target=US protocol=modbus
  ```

### 6. DNS Intelligence
- **Name**: `dns-intelligence`
- **Description**: Analyze DNS information for domains and IP addresses
- **Arguments**:
  - `target_type` (required): Type of target to analyze ("domain", "ip", "hostname")
  - `target` (required): Domain name, IP address, or hostname to analyze
  - `include_history` (optional): Include historical information if available ("yes", "no")
- **Example**:
  ```
  @shodan dns-intelligence target_type=domain target=example.com
  ```

### 7. Service Exposure Analysis
- **Name**: `service-exposure`
- **Description**: Analyze specific service types exposed on the internet
- **Arguments**:
  - `service_type` (required): Type of service to analyze ("database", "webcam", "industrial", "remote-access", "custom")
  - `target_scope` (required): Scope of analysis ("global", "country", "organization", "ip-range")
  - `target` (optional): Target value based on scope (country code, org name, IP range)
  - `custom_query` (optional): Custom query for the 'custom' service type
- **Example**:
  ```
  @shodan service-exposure service_type=database target_scope=country target=US
  ```

### 8. Account Status
- **Name**: `account-status`
- **Description**: Analyze account information and API usage status
- **Arguments**:
  - `info_type` (required): Type of account information to retrieve ("profile", "api", "usage", "all")
- **Example**:
  ```
  @shodan account-status info_type=all
  ```

### 9. Scan Management
- **Name**: `scan-management`
- **Description**: Manage and analyze on-demand network scans
- **Arguments**:
  - `action` (required): Scan action to perform ("initiate", "check", "list")
  - `target` (optional): Target IPs or networks to scan (comma-separated)
  - `scan_id` (optional): Scan ID for checking status
- **Example**:
  ```
  @shodan scan-management action=initiate target=192.168.1.0/24
  ```

### 10. Search Analytics
- **Name**: `search-analytics`
- **Description**: Analyze Shodan search capabilities and patterns
- **Arguments**:
  - `action` (required): Type of search analysis to perform ("analyze-query", "explore-facets", "examine-filters", "saved-queries")
  - `query` (optional): Query to analyze (for analyze-query action)
- **Example**:
  ```
  @shodan search-analytics action=analyze-query query="apache country:DE port:443"
  ```

### 11. Vulnerability Hunting
- **Name**: `vulnerability-hunting`
- **Description**: Hunt for specific vulnerabilities across the internet
- **Arguments**:
  - `vuln_type` (required): Type of vulnerability to hunt ("cve", "product", "service", "custom")
  - `target` (required): Vulnerability target (CVE ID, product name, service type)
  - `scope` (optional): Scope of the search ("global", "regional", "industry")
  - `scope_value` (optional): Value for scope (country, industry)
- **Example**:
  ```
  @shodan vulnerability-hunting vuln_type=cve target=CVE-2021-44228 scope=regional scope_value=US
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

## Example Usage Scenarios

### Cybersecurity Reconnaissance Workflow
1. Start with asset discovery for a target organization:
   ```
   @shodan asset-discovery target=targetcompany.com depth=comprehensive
   ```

2. Perform DNS intelligence on discovered domains:
   ```
   @shodan dns-intelligence target_type=domain target=targetcompany.com
   ```

3. Analyze specific hosts for vulnerabilities:
   ```
   @shodan vulnerability-assessment target_type=host target=192.168.1.1 severity_threshold=high
   ```

4. Set up monitoring for critical assets:
   ```
   @shodan security-monitoring action=create target_type=ip target=192.168.1.1
   ```

### Vulnerability Research Workflow
1. Hunt for a specific CVE across the internet:
   ```
   @shodan vulnerability-hunting vuln_type=cve target=CVE-2021-44228
   ```

2. Analyze which industries are most affected:
   ```
   @shodan internet-search query="vuln:CVE-2021-44228" facets="country,org,industry"
   ```

3. Check details of the specific vulnerability:
   ```
   @shodan cve-lookup cve=CVE-2021-44228
   ```

### Industrial System Security Analysis
1. Identify ICS systems in a specific country:
   ```
   @shodan ics-analysis target_type=country target=DE
   ```

2. Analyze specific industrial protocols:
   ```
   @shodan ics-analysis target_type=product target=siemens protocol=s7
   ```

3. Set up alerts for newly discovered industrial systems:
   ```
   @shodan security-monitoring action=create target_type=service target=modbus
   ```

## Limitations

- API rate limits apply based on your Shodan subscription
- Some operations consume query credits
- On-demand scanning consumes scan credits

## Contact & Support

For issues, feature requests, or questions about this Shodan MCP Server, please contact:

**ADEO Cybersecurity Services**  
Email: info@adeosecurity.com  
Website: [https://www.adeosecurity.com](https://www.adeosecurity.com)

---

Copyright © 2025 ADEO Cybersecurity Services. All rights reserved.
