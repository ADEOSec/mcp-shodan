# ADEO CTI MCP Server

> Developed by ADEO Cybersecurity Services

A Model Context Protocol (MCP) server that provides access to both Shodan and VirusTotal APIs for comprehensive security analysis and threat intelligence. This server, developed and maintained by ADEO Cybersecurity Services, enables cybersecurity analysts to perform network intelligence operations including host information lookup, DNS operations, vulnerability analysis, network scanning, and alerts management through a collection of tools and prompt templates.

## About ADEO Cybersecurity Services

ADEO Cybersecurity Services specializes in providing advanced security solutions and tools for cybersecurity professionals. This ADEO CTI MCP Server is part of our commitment to enhancing cybersecurity capabilities through innovative tools and integrations with industry-leading security data sources.

## Features

### Shodan Capabilities
- Detailed information about IP addresses including open ports, services, and location data
- DNS lookup and reverse DNS operations
- Domain information retrieval including subdomains
- Advanced search capabilities with facets and filters
- On-demand network scanning
- Network alerts and monitoring
- Vulnerability analysis and CVE tracking
- Account and API management
- Historical data access

### VirusTotal Integration
- Malware analysis and detection
- URL scanning and reputation checking
- IP address reputation analysis
- Domain threat intelligence
- File hash analysis
- Comprehensive threat reports

### Combined Analysis Features
- Unified security analysis using both platforms
- Correlated threat intelligence
- Integrated vulnerability assessment
- Cross-platform data enrichment

### Enhanced Functionality
- Rich data formatting and presentation
- Intelligent workflow automation
- Pre-built analysis templates
- Custom search filters
- Batch processing capabilities
- Real-time monitoring

## Tools

### Shodan Tools

#### Host Information
1. **host-info**
   - Get detailed information about a host from Shodan
   - Parameters:
     - `ip` (required): IP address to look up
     - `history` (optional): Include historical information
     - `minify` (optional): Return only basic host information
   - Example:
     ```
     @shodan host-info ip="8.8.8.8" history=true
     ```

#### DNS Operations
2. **dns-lookup**
   - Resolve hostnames to IP addresses
   - Parameters:
     - `hostnames` (required): Comma-separated list of hostnames to resolve
   - Example:
     ```
     @shodan dns-lookup hostnames="google.com,facebook.com"
     ```

3. **reverse-dns**
   - Look up hostnames for IP addresses
   - Parameters:
     - `ips` (required): Comma-separated list of IP addresses
   - Example:
     ```
     @shodan reverse-dns ips="8.8.8.8,1.1.1.1"
     ```

4. **domain-info**
   - Get DNS entries and subdomains for a domain
   - Parameters:
     - `domain` (required): Domain name to look up
   - Example:
     ```
     @shodan domain-info domain="example.com"
     ```

#### Search Operations
5. **search-host**
   - Search Shodan for hosts matching specific criteria
   - Parameters:
     - `query` (required): Shodan search query
     - `facets` (optional): Comma-separated list of properties for summary information
     - `page` (optional): Page number for results
   - Example:
     ```
     @shodan search-host query="apache country:DE" facets="org,port"
     ```

6. **search-host-count**
   - Get count of matching results without full details
   - Parameters:
     - `query` (required): Shodan search query
     - `facets` (optional): Comma-separated list of facets
   - Example:
     ```
     @shodan search-host-count query="product:nginx"
     ```

#### Search Utilities
7. **list-search-facets**
   - List all available search facets
   - No parameters required

8. **list-search-filters**
   - List all filters that can be used when searching
   - No parameters required

9. **search-tokens**
   - Analyze and break down search query components
   - Parameters:
     - `query` (required): Shodan search query to analyze
   - Example:
     ```
     @shodan search-tokens query="apache port:80 country:DE"
     ```

#### Network Information
10. **list-ports**
    - List all ports that Shodan is actively scanning
    - No parameters required

11. **list-protocols**
    - List all protocols available for scanning
    - No parameters required

#### Scanning Operations
12. **request-scan**
    - Request Shodan to scan specific targets
    - Parameters:
      - `ips` (required): Comma-separated list of IPs or networks in CIDR notation
    - Example:
      ```
      @shodan request-scan ips="192.168.1.0/24"
      ```

13. **get-scan-status**
    - Check the status of a submitted scan
    - Parameters:
      - `id` (required): The unique scan ID
    - Example:
      ```
      @shodan get-scan-status id="SCAN_ID"
      ```

14. **list-scans**
    - View all your submitted scans
    - No parameters required

#### Alert Management
15. **list-triggers**
    - List available network alert triggers
    - No parameters required

16. **create-alert**
    - Set up network monitoring alerts
    - Parameters:
      - `name` (required): Alert name
      - `filters` (required): Alert filters
      - `expires` (optional): Expiration time in seconds
    - Example:
      ```
      @shodan create-alert name="My Alert" filters={"ip":["8.8.8.8"],"port":[80,443]}
      ```

17. **get-alert-info**
    - Get details about a specific alert
    - Parameters:
      - `id` (required): Alert ID
    - Example:
      ```
      @shodan get-alert-info id="ALERT_ID"
      ```

18. **delete-alert**
    - Remove an existing alert
    - Parameters:
      - `id` (required): Alert ID to delete

19. **edit-alert**
    - Modify an existing alert
    - Parameters:
      - `id` (required): Alert ID
      - `name` (optional): New alert name
      - `filters` (optional): Updated filters

20. **list-alerts**
    - View all active alerts
    - No parameters required

#### Query Management
21. **list-queries**
    - View saved search queries
    - Parameters:
      - `page` (optional): Results page number
      - `sort` (optional): Sort by "votes" or "timestamp"
      - `order` (optional): "asc" or "desc"

22. **search-queries**
    - Search through saved queries
    - Parameters:
      - `query` (required): Search term
      - `page` (optional): Page number

23. **list-query-tags**
    - View popular query tags
    - Parameters:
      - `size` (optional): Number of tags to return

#### Account Management
24. **get-profile**
    - View account information
    - No parameters required

25. **get-api-info**
    - Check API subscription status
    - No parameters required

26. **get-billing**
    - View billing information
    - No parameters required

27. **get-http-headers**
    - Check your request headers
    - No parameters required

28. **get-my-ip**
    - View your current IP address
    - No parameters required

#### Vulnerability Analysis
29. **cve-lookup**
    - Get CVE details
    - Parameters:
      - `cve` (required): CVE ID (e.g., CVE-2021-44228)
    - Example:
      ```
      @shodan cve-lookup cve="CVE-2021-44228"
      ```

30. **cpe-vuln-search**
    - Search vulnerabilities by CPE
    - Parameters:
      - `cpe` (required): CPE 2.3 string
      - `minCvss` (optional): Minimum CVSS score
      - `maxResults` (optional): Result limit
    - Example:
      ```
      @shodan cpe-vuln-search cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" minCvss=7.0
      ```

### VirusTotal Tools

#### URL Analysis
1. **virustotal-url-analysis**
   - Analyze URLs for security threats
   - Parameters:
     - `url` (required): Target URL
   - Example:
     ```
     @shodan virustotal-url-analysis url="https://example.com"
     ```

#### File Analysis
2. **virustotal-file-analysis**
   - Check file hashes for malware
   - Parameters:
     - `hash` (required): MD5/SHA-1/SHA-256 hash
   - Example:
     ```
     @shodan virustotal-file-analysis hash="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
     ```

#### IP Analysis
3. **virustotal-ip-analysis**
   - Check IP reputation
   - Parameters:
     - `ip` (required): Target IP address
   - Example:
     ```
     @shodan virustotal-ip-analysis ip="8.8.8.8"
     ```

#### Domain Analysis
4. **virustotal-domain-analysis**
   - Analyze domain reputation
   - Parameters:
     - `domain` (required): Target domain
   - Example:
     ```
     @shodan virustotal-domain-analysis domain="example.com"
     ```

## MCP Server Prompts

The server provides a set of intelligent prompts for comprehensive cybersecurity analysis workflows:

### Asset Discovery
- **Name**: `asset-discovery`
- **Description**: Discover and analyze internet-facing assets and infrastructure
- **Parameters**:
  - `target` (required): Domain, IP address, or organization name to analyze
  - `depth` (optional): Depth of reconnaissance ("basic" or "comprehensive")
- **Example**:
  ```
  @shodan asset-discovery target=example.com depth=comprehensive
  ```

### Vulnerability Assessment
- **Name**: `vulnerability-assessment`
- **Description**: Find vulnerabilities in internet-connected systems
- **Parameters**:
  - `target_type` (required): Type of target to analyze ("host", "domain", "cpe", "cve")
  - `target` (required): Target identifier (IP, domain, CPE string, or CVE ID)
  - `severity_threshold` (optional): Minimum severity threshold ("all", "medium", "high", "critical")
  - `include_vt_analysis` (optional): Include VirusTotal security analysis ("yes" or "no")
- **Example**:
  ```
  @shodan vulnerability-assessment target_type=host target=192.168.1.1 severity_threshold=high
  ```

### Internet Search
- **Name**: `internet-search`
- **Description**: Search for specific internet-connected systems or services
- **Parameters**:
  - `search_type` (required): Type of search ("service", "product", "vulnerability", "organization", "custom")
  - `query` (required): Search terms or Shodan query string
  - `filters` (optional): Additional Shodan filters to apply
- **Example**:
  ```
  @shodan internet-search search_type=product query="nginx" filters="country:US port:443"
  ```

### Network Monitoring
- **Name**: `network-monitoring`
- **Description**: Set up network monitoring and alerts
- **Parameters**:
  - `target` (required): IP, network range, or domain to monitor
  - `monitor_type` (required): Type of changes to monitor ("new-service", "vulnerability", "certificate", "custom")
  - `notification_threshold` (optional): Minimum severity for notifications ("all", "high", "critical")
- **Example**:
  ```
  @shodan network-monitoring target=192.168.0.0/24 monitor_type=vulnerability notification_threshold=high
  ```

### ICS Analysis
- **Name**: `ics-analysis`
- **Description**: Analyze exposed industrial control systems and SCADA devices
- **Parameters**:
  - `target_type` (required): Type of target to analyze ("ip", "network", "product", "country")
  - `target` (required): Target identifier (IP, network range, product name, or country code)
  - `protocol` (optional): Specific protocol to focus on
- **Example**:
  ```
  @shodan ics-analysis target_type=country target=US protocol=modbus
  ```

### DNS Intelligence
- **Name**: `dns-intelligence`
- **Description**: Analyze DNS information for domains and IP addresses
- **Parameters**:
  - `target_type` (required): Type of target to analyze ("domain", "ip", "hostname")
  - `target` (required): Domain name, IP address, or hostname to analyze
  - `include_history` (optional): Include historical information ("yes" or "no")
  - `include_vt_analysis` (optional): Include VirusTotal security analysis ("yes" or "no")
- **Example**:
  ```
  @shodan dns-intelligence target_type=domain target=example.com include_vt_analysis=yes
  ```

### Service Exposure Analysis
- **Name**: `service-exposure`
- **Description**: Analyze specific service types exposed on the internet
- **Parameters**:
  - `service_type` (required): Type of service ("database", "webcam", "industrial", "remote-access", "custom")
  - `target_scope` (required): Scope of analysis ("global", "country", "organization", "ip-range")
  - `target` (optional): Target value based on scope
  - `custom_query` (optional): Custom query for the 'custom' service type
  - `include_vt_analysis` (optional): Include VirusTotal analysis ("yes" or "no")
- **Example**:
  ```
  @shodan service-exposure service_type=database target_scope=country target=US
  ```

### Account Status
- **Name**: `account-status`
- **Description**: Analyze account information and API usage status
- **Parameters**:
  - `info_type` (required): Type of information to retrieve ("profile", "api", "usage", "all")
- **Example**:
  ```
  @shodan account-status info_type=all
  ```

### Scan Management
- **Name**: `scan-management`
- **Description**: Manage and analyze on-demand network scans
- **Parameters**:
  - `action` (required): Scan action to perform ("initiate", "check", "list")
  - `target` (optional): Target IPs or networks to scan (comma-separated)
  - `scan_id` (optional): Scan ID for checking status
- **Example**:
  ```
  @shodan scan-management action=initiate target=192.168.1.0/24
  ```

### Search Analytics
- **Name**: `search-analytics`
- **Description**: Analyze Shodan search capabilities and patterns
- **Parameters**:
  - `action` (required): Type of analysis ("analyze-query", "explore-facets", "examine-filters", "saved-queries")
  - `query` (optional): Query to analyze (for analyze-query action)
- **Example**:
  ```
  @shodan search-analytics action=analyze-query query="apache country:DE port:443"
  ```

### Vulnerability Hunting
- **Name**: `vulnerability-hunting`
- **Description**: Hunt for specific vulnerabilities across the internet
- **Parameters**:
  - `vuln_type` (required): Type of vulnerability to hunt ("cve", "product", "service", "custom")
  - `target` (required): Vulnerability target (CVE ID, product name, service type)
  - `scope` (optional): Scope of the search ("global", "regional", "industry")
  - `scope_value` (optional): Value for scope (country, industry)
- **Example**:
  ```
  @shodan vulnerability-hunting vuln_type=cve target=CVE-2021-44228 scope=regional scope_value=US
  ```

### Malware Analysis
- **Name**: `malware-analysis`
- **Description**: Analyze files and URLs for malware and security threats
- **Parameters**:
  - `target_type` (required): Type of target to analyze ("file" or "url")
  - `target` (required): File hash (MD5/SHA1/SHA256) or URL to analyze
  - `include_relationships` (optional): Include relationship data ("yes" or "no")
- **Example**:
  ```
  @shodan malware-analysis target_type=file target=a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
  ```

### Infrastructure Analysis
- **Name**: `infrastructure-analysis`
- **Description**: Analyze network infrastructure using combined Shodan and VirusTotal data
- **Parameters**:
  - `target_type` (required): Type of target to analyze ("ip" or "domain")
  - `target` (required): IP address or domain to analyze
  - `depth` (optional): Analysis depth ("basic" or "comprehensive")
  - `include_vt_analysis` (optional): Include VirusTotal analysis ("yes" or "no")
- **Example**:
  ```
  @shodan infrastructure-analysis target_type=domain target=example.com depth=comprehensive
  ```

### Threat Hunting
- **Name**: `threat-hunting`
- **Description**: Hunt for threats across multiple data sources using combined intelligence
- **Parameters**:
  - `indicator_type` (required): Type of indicator ("ip", "domain", "url", "file")
  - `indicator` (required): Indicator value to investigate
  - `include_vt_analysis` (optional): Include VirusTotal analysis ("yes" or "no")
- **Example**:
  ```
  @shodan threat-hunting indicator_type=ip indicator=8.8.8.8 include_vt_analysis=yes
  ```

## Environment Setup

1. Set required environment variables:
   ```bash
   SHODAN_API_KEY=your_shodan_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

4. Start the server:
   ```bash
   npm start
   ```

## API Rate Limits

- Respect Shodan API limits based on your subscription
- VirusTotal API has separate rate limits
- Use batch operations when possible
- Implement appropriate delay between requests

## Error Handling

The server handles various error scenarios:
- Invalid API keys
- Rate limiting
- Network issues
- Invalid parameters
- Missing permissions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

Copyright © 2024 ADEO Cybersecurity Services. All rights reserved.
