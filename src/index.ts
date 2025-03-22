/**
 * ADEO CTI MCP Server Implementation
 * This file implements a Model Context Protocol (MCP) server that provides access to CTI functionality.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import * as dotenv from "dotenv";
import axios from "axios";
import { 
  ShodanHostInfo, 
  ShodanDNSResolution, 
  ShodanReverseDNS, 
  ShodanDomainInfo, 
  ShodanSearchResult, 
  ShodanSearchFacets, 
  ShodanSearchFilters, 
  ShodanSearchTokens, 
  ShodanPorts, 
  ShodanProtocols, 
  ShodanScanResult, 
  ShodanScanStatus, 
  ShodanScanList, 
  ShodanTriggerList, 
  ShodanAlert, 
  ShodanAlertInfo, 
  ShodanAlertList, 
  ShodanQueryList, 
  ShodanQueryTags, 
  ShodanAccount, 
  ShodanApiStatus, 
  ShodanBillingProfile, 
  ShodanHTTPHeaders, 
  ShodanMyIP,
  CVEDBVulnerability,
  CVEDBVulnerabilityList,
  CPEDictionaryEntry,
  CPEDictionaryList,
  VirusTotalResponse,
  VirusTotalUrlAnalysis,
  VirusTotalFileAnalysis,
  VirusTotalIpAnalysis,
  VirusTotalDomainAnalysis
} from "./types.js";

// Load environment variables (SHODAN_API_KEY)
dotenv.config();

/**
 * Parse command line arguments to get the API keys
 * @returns {Object} Object containing both API keys
 * @throws {Error} If required API keys are not provided
 */
function parseArgs() {
  const args = process.argv.slice(2);
  let shodanApiKey = '';
  let virusTotalApiKey = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--shodan-api-key' && i + 1 < args.length) {
      shodanApiKey = args[i + 1];
      i++; // Skip next argument as it's the value
    }
    if (args[i] === '--virustotal-api-key' && i + 1 < args.length) {
      virusTotalApiKey = args[i + 1];
      i++; // Skip next argument as it's the value
    }
  }

  if (!shodanApiKey) {
    console.error("❌ --shodan-api-key parameter is required");
    console.error("Usage: npm start -- --shodan-api-key YOUR_SHODAN_API_KEY --virustotal-api-key YOUR_VIRUSTOTAL_API_KEY");
    process.exit(1);
  }

  if (!virusTotalApiKey) {
    console.warn("⚠️ --virustotal-api-key parameter is not provided. VirusTotal tools will be unavailable.");
  }

  return { shodanApiKey, virusTotalApiKey };
}

const { shodanApiKey, virusTotalApiKey } = parseArgs();
const API_BASE_URL = "https://api.shodan.io";

// CVEDB API base URL
const CVEDB_API_BASE_URL = "https://cvedb.shodan.io";

// VirusTotal API configuration
const VIRUSTOTAL_API_BASE_URL = "https://www.virustotal.com/api/v3";

// Create an MCP server instance with metadata
const server = new McpServer({
  name: "ADEO CTI MCP Server",
  version: "1.0.0",
  capabilities: {
    resources: {},  // Enable resources capability
    tools: {},      // Keep existing tools capability
    prompts: {}     // Enable prompts capability
  }
});

/**
 * Resource Handlers
 * Implement resource capabilities for the MCP server
 */

// Define resources for the server
server.resource(
  "threat-hunting-guide",
  "guide://threat-hunting",
  {
    name: "How to Threat Hunting",
    description: "A comprehensive guide on threat hunting using ADEO CTI MCP Server tools"
  },
  async (uri) => {
    return {
      contents: [{
        uri: uri.href,
        mimeType: "text/markdown",
        text: `# ADEO CTI Threat Hunting Guide

## Introduction

This guide provides best practices for threat hunting using the ADEO CTI MCP Server tools. Threat hunting is a proactive cybersecurity approach that focuses on searching for malicious activities and threats that have evaded existing security solutions.

## Available Tools for Threat Hunters

### Reconnaissance & Intelligence Gathering

1. **DNS Lookup** (dns-lookup)
   - Use this tool to resolve domain names to IP addresses
   - Helpful for identifying infrastructure connected to suspicious domains
   - Example: Investigating domains from phishing emails or suspicious communications

2. **Reverse DNS** (reverse-dns)
   - Maps IP addresses back to hostnames
   - Useful for understanding the ownership and purpose of suspicious IPs
   - Can reveal patterns in attacker infrastructure

3. **Domain Information** (domain-info)
   - Provides comprehensive information about domains including subdomains
   - Essential for understanding the attack surface of a target
   - Can reveal potential entry points for attackers

### Vulnerability Assessment

1. **Host Information** (host-info)
   - Provides detailed information about internet-facing systems
   - Reveals open ports, running services, and potential vulnerabilities
   - Critical for understanding exposure and attack vectors

2. **CVE Lookup** (cve-lookup)
   - Search for specific vulnerabilities by CVE ID
   - Provides detailed information about known vulnerabilities
   - Essential for understanding the severity and exploit potential

### Threat Analysis

1. **Search** (search-host)
   - Search for specific internet-connected devices, services, or vulnerabilities
   - Perfect for finding patterns across multiple targets
   - Use Shodan query syntax to create precise searches

2. **Search Count** (search-host-count)
   - Get statistics about search results without the full details
   - Great for understanding the scale of a threat or exposure

3. **Search Tokens** (search-tokens)
   - Understand how search queries are interpreted
   - Helps in refining and optimizing complex searches

### Monitoring & Alerting

1. **Create Alert** (create-alert)
   - Set up continuous monitoring for new threats or vulnerabilities
   - Get notified when new systems matching your criteria appear
   - Essential for ongoing threat hunting operations

2. **List/Get/Delete Alerts** (list-alerts, get-alert-info, delete-alert)
   - Manage your monitoring operations
   - Review and refine your alert criteria

### Malware Analysis

1. **VirusTotal URL Analysis** (vt-url-analysis)
   - Check if URLs are associated with malicious activities
   - View detailed reports from multiple security engines
   - Perfect for validating suspicious links

2. **VirusTotal File Analysis** (vt-file-analysis)
   - Analyze suspicious files for malware signatures
   - Get comprehensive reports from multiple antivirus engines
   - Essential for malware investigation

3. **VirusTotal Domain/IP Analysis** (vt-domain-analysis, vt-ip-analysis)
   - Investigate domains and IPs for malicious associations
   - Understand historical reputation and threat intelligence
   - Critical for infrastructure analysis

## Workflow Examples

### Investigating a Suspicious Domain

1. Start with dns-lookup to find associated IP addresses
2. Use host-info on those IPs to identify services and vulnerabilities
3. Check domain reputation with vt-domain-analysis
4. Set up an alert to monitor for changes

### Proactive Vulnerability Scanning

1. Use search-host with specific vulnerability filters
2. Investigate interesting findings with host-info
3. Look up specific vulnerabilities with cve-lookup
4. Monitor critical assets with create-alert

### Malware Campaign Analysis

1. Analyze suspicious URLs with vt-url-analysis
2. Expand investigation to linked domains using domain-info
3. Check IP infrastructure with vt-ip-analysis
4. Create alerts for related indicators using create-alert

## Best Practices

1. **Document Your Process** - Maintain clear records of your hunting activities
2. **Focus on Patterns** - Look for connections between seemingly unrelated indicators
3. **Validate Findings** - Confirm suspicious activity with multiple tools
4. **Continuous Monitoring** - Set up alerts for ongoing surveillance
5. **Update Knowledge** - Stay current on new threat tactics and techniques

## Conclusion

Effective threat hunting combines the powerful tools in the ADEO CTI MCP Server with analytical thinking and security expertise. By following the workflows and best practices in this guide, threat hunters can proactively identify and mitigate potential security risks before they become incidents.
`
      }]
    };
  }
);

// Define Shodan tools resource
server.resource(
  "shodan-tools-guide",
  "guide://shodan-tools",
  {
    name: "Shodan Tools Guide",
    description: "Comprehensive guide on using Shodan tools within the ADEO CTI MCP Server"
  },
  async (uri) => {
    return {
      contents: [{
        uri: uri.href,
        mimeType: "text/markdown",
        text: `# Shodan Tools Guide

## Introduction

This guide provides detailed information on using the Shodan tools available within the ADEO CTI MCP Server. Shodan is a search engine for Internet-connected devices, allowing security professionals to discover, monitor, and analyze internet-facing systems and their vulnerabilities.

## Available Shodan Tools

### Host Information (host-info)

**Purpose**: Retrieve comprehensive information about a specific IP address.

**Parameters**:
- \`ip\`: IP address to look up (required)
- \`history\`: Include historical information (default: false)
- \`minify\`: Return only basic host information (default: false)

**Usage Example**:
\`\`\`
host-info:
  ip: "8.8.8.8"
  history: true
\`\`\`

**Output**: Detailed JSON containing information about the host, including open ports, services, vulnerabilities, location data, and ownership information.

**Use Cases**:
- Investigating suspicious IP addresses
- Understanding the attack surface of a system
- Verifying security configurations of internet-facing devices
- Gathering intelligence on infrastructure

### DNS Lookup (dns-lookup)

**Purpose**: Resolve domain names to their corresponding IP addresses.

**Parameters**:
- \`hostnames\`: Comma-separated list of domain names to resolve

**Usage Example**:
\`\`\`
dns-lookup:
  hostnames: "example.com,google.com"
\`\`\`

**Output**: JSON mapping of domain names to their IP addresses.

**Use Cases**:
- Identifying the hosting infrastructure of suspicious domains
- Tracking domain infrastructure changes
- Correlating domains with known malicious IP addresses
- Initial reconnaissance during security assessments

### Reverse DNS (reverse-dns)

**Purpose**: Look up hostnames associated with specific IP addresses.

**Parameters**:
- \`ips\`: Comma-separated list of IP addresses

**Usage Example**:
\`\`\`
reverse-dns:
  ips: "8.8.8.8,1.1.1.1"
\`\`\`

**Output**: JSON mapping of IP addresses to their associated hostnames.

**Use Cases**:
- Identifying services and purposes of IP addresses
- Discovering related infrastructure
- Enhancing IP intelligence with additional context
- Validating legitimate services

### Domain Information (domain-info)

**Purpose**: Retrieve all available DNS information for a domain.

**Parameters**:
- \`domain\`: Domain name to analyze

**Usage Example**:
\`\`\`
domain-info:
  domain: "example.com"
\`\`\`

**Output**: Comprehensive DNS details including subdomains, DNS record types, and IP addresses associated with the domain.

**Use Cases**:
- Mapping domain infrastructure and subdomains
- Discovering potential entry points and attack surfaces
- Understanding domain ownership and structure
- Tracking domain changes and new subdomains

### Search Shodan (search-host)

**Purpose**: Search for internet-connected devices matching specific criteria.

**Parameters**:
- \`query\`: Shodan search query using Shodan's search syntax
- \`facets\`: Optional comma-separated list of properties to get summary information
- \`page\`: Optional page number for paginating through large result sets

**Usage Example**:
\`\`\`
search-host:
  query: "apache country:DE port:443"
  facets: "org,os"
\`\`\`

**Output**: JSON with matching hosts and result metadata.

**Use Cases**:
- Finding vulnerable systems
- Discovering misconfigured services
- Identifying devices running specific software
- Tracking exposure of organizational assets

### Search Count (search-host-count)

**Purpose**: Get the number of results for a search query without retrieving actual results.

**Parameters**:
- \`query\`: Shodan search query
- \`facets\`: Optional comma-separated list of properties to get summary information

**Usage Example**:
\`\`\`
search-host-count:
  query: "nginx country:US"
  facets: "org,os"
\`\`\`

**Output**: JSON with count statistics and facet information.

**Use Cases**:
- Understanding the scale of vulnerabilities
- Getting statistical overviews of exposed services
- Quick validation of search queries
- Tracking exposure trends over time

### List Search Facets (list-search-facets)

**Purpose**: List all available facets for search aggregation.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-search-facets
\`\`\`

**Output**: JSON list of available facet properties.

**Use Cases**:
- Discovering data aggregation options
- Understanding available search dimensions
- Building more effective search queries

### List Search Filters (list-search-filters)

**Purpose**: List all available search filters.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-search-filters
\`\`\`

**Output**: JSON list of available search filters and their descriptions.

**Use Cases**:
- Learning available search filtering options
- Building more effective search queries
- Understanding search syntax capabilities

### Search Tokens (search-tokens)

**Purpose**: Analyze a search query to understand how it's interpreted.

**Parameters**:
- \`query\`: Search query to analyze

**Usage Example**:
\`\`\`
search-tokens:
  query: "apache country:DE port:443"
\`\`\`

**Output**: JSON breakdown of how each part of the query is tokenized and interpreted.

**Use Cases**:
- Debugging complex search queries
- Verifying query syntax
- Optimizing search effectiveness

### List Ports (list-ports)

**Purpose**: Get a list of ports that Shodan is currently scanning.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-ports
\`\`\`

**Output**: JSON list of port numbers.

**Use Cases**:
- Understanding coverage of Shodan's scanning
- Planning security assessments
- Evaluating potential visibility of services

### List Protocols (list-protocols)

**Purpose**: List all protocols that can be used for scanning.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-protocols
\`\`\`

**Output**: JSON object mapping protocol names to descriptions.

**Use Cases**:
- Discovering specialized protocol scanners
- Planning comprehensive security assessments
- Understanding available data collection methods

### Request Scan (request-scan)

**Purpose**: Request Shodan to scan specific IP addresses or networks.

**Parameters**:
- \`ips\`: Comma-separated list of IPs or networks in CIDR notation

**Usage Example**:
\`\`\`
request-scan:
  ips: "8.8.8.8,1.1.1.1/24"
\`\`\`

**Output**: JSON with scan information and credits used.

**Use Cases**:
- On-demand scanning of systems
- Validating security changes
- Tracking new exposures in real-time
- Investigating emerging threats

### Get Scan Status (get-scan-status)

**Purpose**: Check the status of a previously submitted scan.

**Parameters**:
- \`id\`: The unique scan ID returned by request-scan

**Usage Example**:
\`\`\`
get-scan-status:
  id: "xxxxxxx"
\`\`\`

**Output**: JSON with scan status information.

**Use Cases**:
- Tracking progress of on-demand scans
- Verifying completion of scanning requests
- Planning follow-up analysis

### List Scans (list-scans)

**Purpose**: Get a list of all submitted scans.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-scans
\`\`\`

**Output**: JSON list of all scan requests and their statuses.

**Use Cases**:
- Managing scan operations
- Reviewing scan history
- Tracking scanning credits usage

## Alerts Management Tools

Shodan's alert tools allow you to monitor for changes to internet-facing assets.

### List Triggers (list-triggers)

**Purpose**: List available triggers for network alerts.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-triggers
\`\`\`

**Output**: JSON list of trigger types and their descriptions.

### Create Alert (create-alert)

**Purpose**: Create a network alert for monitoring specific criteria.

**Parameters**:
- \`name\`: Name of the alert
- \`filters\`: Object containing filters (IP addresses, ports)
- \`expires\`: Optional number of seconds the alert should be active

**Usage Example**:
\`\`\`
create-alert:
  name: "Critical Infrastructure Monitoring"
  filters: {"ip": ["8.8.8.8"], "port": [443, 80]}
\`\`\`

**Output**: JSON with alert information.

### Get Alert Info (get-alert-info)

**Purpose**: Get information about a specific alert.

**Parameters**:
- \`id\`: Alert ID to get information about

**Usage Example**:
\`\`\`
get-alert-info:
  id: "XXXXXXXX"
\`\`\`

**Output**: JSON with detailed alert information.

### Delete Alert (delete-alert)

**Purpose**: Delete a network alert.

**Parameters**:
- \`id\`: Alert ID to delete

**Usage Example**:
\`\`\`
delete-alert:
  id: "XXXXXXXX"
\`\`\`

**Output**: Confirmation of alert deletion.

### Edit Alert (edit-alert)

**Purpose**: Edit an existing alert.

**Parameters**:
- \`id\`: Alert ID to edit
- \`name\`: Optional new name for the alert
- \`filters\`: Optional new filters

**Usage Example**:
\`\`\`
edit-alert:
  id: "XXXXXXXX"
  name: "Updated Critical Infrastructure Monitoring"
  filters: {"ip": ["8.8.8.8", "8.8.4.4"], "port": [443, 80, 22]}
\`\`\`

**Output**: JSON with updated alert information.

### List Alerts (list-alerts)

**Purpose**: List all active alerts.

**Parameters**: None required

**Usage Example**:
\`\`\`
list-alerts
\`\`\`

**Output**: JSON list of all active alerts.

## Account Tools

### Get Profile (get-profile)

**Purpose**: Get account profile information.

**Parameters**: None required

**Usage Example**:
\`\`\`
get-profile
\`\`\`

**Output**: JSON with account details.

### Get API Info (get-api-info)

**Purpose**: Get API subscription information.

**Parameters**: None required

**Usage Example**:
\`\`\`
get-api-info
\`\`\`

**Output**: JSON with API plan details and credits.

### Get My IP (get-my-ip)

**Purpose**: View your current IP address as seen by Shodan.

**Parameters**: None required

**Usage Example**:
\`\`\`
get-my-ip
\`\`\`

**Output**: JSON with your IP address.

## Best Practices

### Effective Searching

1. **Use Specific Filters**: Combine multiple filters for precise results
   \`\`\`
   product:"Apache" port:443 country:DE
   \`\`\`

2. **Leverage Facets**: Use facets to understand result distributions
   \`\`\`
   search-host:
     query: "nginx"
     facets: "country,org,version"
   \`\`\`

3. **Validate Queries**: Use search-tokens to understand query interpretation

### Credit Management

1. **Use search-host-count**: For large queries, first get a count to understand scope
2. **Optimize scan requests**: Group IPs/networks when possible
3. **Monitor usage**: Regularly check your API info

### Alert Management

1. **Use Descriptive Names**: Name alerts clearly for easy management
2. **Prioritize Critical Assets**: Focus monitoring on high-value systems
3. **Set Appropriate Expirations**: Use the expires parameter for temporary monitoring

## Conclusion

Shodan tools provide powerful capabilities for discovering, analyzing, and monitoring internet-facing assets. By effectively using these tools, security professionals can identify vulnerabilities, track attack surfaces, and maintain awareness of their organization's exposure.

For more information and advanced usage examples, visit [Shodan's official documentation](https://developer.shodan.io/api).`
      }]
    };
  }
);

// Define VirusTotal tools resource
server.resource(
  "virustotal-tools-guide",
  "guide://virustotal-tools",
  {
    name: "VirusTotal Tools Guide",
    description: "Comprehensive guide on using VirusTotal tools within the ADEO CTI MCP Server"
  },
  async (uri) => {
    return {
      contents: [{
        uri: uri.href,
        mimeType: "text/markdown",
        text: `# VirusTotal Tools Guide

## Introduction

This guide provides detailed information on using the VirusTotal tools available within the ADEO CTI MCP Server. VirusTotal is a platform that analyzes files, URLs, domains, and IP addresses for malicious content, integrating results from multiple security vendors and tools.

## Available VirusTotal Tools

### URL Analysis (virustotal-url-analysis)

**Purpose**: Analyze a URL for security threats and malicious behavior.

**Parameters**:
- \`url\`: The URL to analyze (must be a valid URL)

**Usage Example**:
\`\`\`
virustotal-url-analysis:
  url: "https://example.com/suspicious-page"
\`\`\`

**Output**: Comprehensive analysis with detection results from multiple security vendors, categorization, and associated threat intelligence.

**Key Information Returned**:
- Detection ratios from security vendors
- URL categories
- First/last submission dates
- Associated malware samples
- Related URLs in the same infrastructure
- Embedded content analysis
- WHOIS data
- SSL certificate information (if HTTPS)

**Use Cases**:
- Evaluating suspicious links from emails
- Checking potentially malicious URLs found in logs
- Verifying the legitimacy of download sources
- Analyzing redirect chains for malware delivery

### File Analysis (virustotal-file-analysis)

**Purpose**: Analyze a file hash for malware and security threats.

**Parameters**:
- \`hash\`: MD5, SHA-1, or SHA-256 hash of the file to analyze

**Usage Example**:
\`\`\`
virustotal-file-analysis:
  hash: "44d88612fea8a8f36de82e1278abb02f"
\`\`\`

**Output**: Detailed analysis of the file including multi-engine antivirus scan results and behavior analysis.

**Key Information Returned**:
- Detection results from 70+ antivirus engines
- File metadata and properties
- Behavioral analysis and sandboxing results
- YARA and SIGMA rule matches
- Embedded resources and strings
- Similar/related files
- File reputation and first/last seen dates

**Use Cases**:
- Analyzing suspicious executables
- Verifying the legitimacy of downloaded files
- Investigating potential malware incidents
- Threat intelligence enrichment for file indicators

### IP Analysis (virustotal-ip-analysis)

**Purpose**: Analyze an IP address for security threats and reputation.

**Parameters**:
- \`ip\`: IP address to analyze (must be a valid IPv4 or IPv6 address)

**Usage Example**:
\`\`\`
virustotal-ip-analysis:
  ip: "8.8.8.8"
\`\`\`

**Output**: Comprehensive IP intelligence including reputation data, associated domains, and security verdicts.

**Key Information Returned**:
- Detection ratios from security vendors
- ASN and network information
- Country and geolocation
- Passive DNS (associated domains)
- Historical reputation
- Observed malicious URLs hosted
- WHOIS data
- Associated malware communications

**Use Cases**:
- Investigating suspicious network connections
- Analyzing potential command & control servers
- Understanding the reputation of IP addresses in logs
- Enriching security alerts with threat intelligence

### Domain Analysis (virustotal-domain-analysis)

**Purpose**: Analyze a domain for security threats using VirusTotal's API.

**Parameters**:
- \`domain\`: Domain name to analyze (must be a valid domain name)

**Usage Example**:
\`\`\`
virustotal-domain-analysis:
  domain: "example.com"
\`\`\`

**Output**: Comprehensive domain intelligence including associated IPs, subdomains, and security verdicts.

**Key Information Returned**:
- Detection ratios from security vendors
- Domain categories
- WHOIS information and registration details
- DNS records (A, MX, NS, CNAME, etc.)
- Subdomains
- SSL certificate information
- Hosted URLs and their reputation
- Historical resolution data

**Use Cases**:
- Analyzing potential phishing domains
- Investigating suspicious domains in logs
- Mapping malicious infrastructure
- Evaluating domain reputation before connecting

### YARA Rules (virustotal-yara-rules)

**Purpose**: Access VirusTotal's library of YARA rules to understand detection patterns.

**Parameters**:
- \`action\`: Either "list" or "get"
- \`rule_id\`: (Required for "get" action) ID of the specific rule to retrieve
- \`cursor\`: (Optional for "list" action) Pagination cursor
- \`limit\`: (Optional for "list" action) Number of rules to return per page (max 40)

**Usage Example**:
\`\`\`
virustotal-yara-rules:
  action: "list"
  limit: 10
\`\`\`

**Output**: List of available YARA rules or detailed information about a specific rule.

**Use Cases**:
- Understanding detection methodologies
- Developing custom detection rules
- Researching malware families
- Learning common malware patterns

## Integration with Threat Hunting

### Malware Campaign Analysis

For comprehensive analysis of potential malware campaigns, VirusTotal tools can be combined with Shodan tools to provide a 360° view:

1. Start with suspicious indicators (URLs, files, domains, or IPs)
2. Use appropriate VirusTotal analysis tools to gather comprehensive threat intelligence
3. Use Shodan tools to examine the hosting infrastructure
4. Create alerts to monitor for changes in the infrastructure
5. Document findings and potential connections between indicators

### Domain and IP Reputation Framework

Create a structured approach to evaluating domain/IP reputation:

1. Use virustotal-domain-analysis or virustotal-ip-analysis to get security verdicts
2. Examine detection ratios across vendors
3. Review historical reputation data
4. Check associated malicious indicators
5. Use Shodan host-info to understand infrastructure setup
6. Make risk-based decisions using combined intelligence

## Best Practices

### Effective Analysis

1. **Context Matters**: Always consider the source and context of the indicator being analyzed
2. **Cross-Reference**: Validate findings across multiple tools (VirusTotal and Shodan)
3. **Look for Patterns**: Focus on connections between indicators rather than isolated verdicts
4. **Check Timestamps**: Pay attention to first/last seen dates for historical context
5. **Understand Detections**: Dive deeper into specific detection names to understand the threat type

### Interpretation Guidelines

1. **False Positives**: A small number of detections may indicate false positives
2. **Generic Detections**: Look for specific malware family names rather than generic detections
3. **Infrastructure Sharing**: Consider that legitimate services may share infrastructure with malicious ones
4. **Age of Analysis**: Recent submissions may have fewer detections as engines update

### Security Considerations

1. **Sensitive Data**: Never submit sensitive data to VirusTotal (files may become publicly accessible)
2. **API Key Protection**: Safeguard your VirusTotal API key
3. **Rate Limits**: Be aware of API usage limits when automating requests
4. **Result Caching**: Results may be cached; use the 'scan' endpoints for fresh analysis

## Advanced Techniques

### Correlation Analysis

Strengthen your analysis by correlating data across tools:

1. Use virustotal-domain-analysis to get associated IPs
2. Check those IPs with virustotal-ip-analysis
3. Use Shodan's host-info to examine services running on those IPs
4. Look for patterns and connections across the infrastructure

### Threat Intelligence Enrichment

Enhance existing threat intelligence data:

1. Add VirusTotal reputation scores to threat feeds
2. Enrich IOCs with additional context from file/URL analysis
3. Create severity ratings based on combined detection ratios
4. Track infrastructure changes over time

### Continuous Monitoring

Implement an ongoing monitoring strategy:

1. Regularly analyze critical domains and IPs
2. Set up Shodan alerts for associated infrastructure
3. Track detection ratio changes over time
4. Monitor for new infrastructure associated with known threats

## Conclusion

VirusTotal tools provide powerful threat intelligence and analysis capabilities that complement Shodan's infrastructure visibility. By effectively combining these tools, security analysts can develop a comprehensive understanding of potential threats, make informed decisions, and enhance their organization's security posture.

For more information on VirusTotal's capabilities, visit [VirusTotal's documentation](https://developers.virustotal.com/reference).`
      }]
    };
  }
);

/**
 * Helper function to make API requests to Shodan
 * Handles authentication and error handling for all Shodan API calls
 * 
 * @template T The expected response type
 * @param {string} endpoint The API endpoint to call
 * @param {Record<string, string | number>} params Query parameters to include
 * @returns {Promise<T>} The API response parsed as type T
 * @throws {Error} If the API request fails
 */
async function shodanApiRequest<T>(endpoint: string, params: Record<string, string | number> = {}, method: string = "GET"): Promise<T> {
  // Always include the API key
  const queryParams = new URLSearchParams();
  
  // Add all params
  Object.entries(params).forEach(([key, value]) => {
    queryParams.append(key, String(value));
  });
  
  // Add API key
  queryParams.append('key', shodanApiKey);

  const url = `${API_BASE_URL}${endpoint}?${queryParams}`;
  
  try {
    const response = await fetch(url, { method });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Shodan API error (${response.status}): ${errorText}`);
    }
    
    return await response.json() as T;
  } catch (error) {
    console.error(`Error making request to ${endpoint}:`, error);
    throw error;
  }
}

/**
 * Helper function to make API requests to CVEDB
 */
async function cvedbApiRequest<T>(endpoint: string, params: Record<string, string | number> = {}): Promise<T> {
  const queryParams = new URLSearchParams();
  
  // Add all params
  Object.entries(params).forEach(([key, value]) => {
    queryParams.append(key, String(value));
  });
  
  // Add API key
  queryParams.append('key', shodanApiKey);

  const url = `${CVEDB_API_BASE_URL}${endpoint}?${queryParams}`;
  
  try {
    const response = await fetch(url);
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`CVEDB API error (${response.status}): ${errorText}`);
    }
    
    return await response.json() as T;
  } catch (error) {
    console.error(`Error making request to ${endpoint}:`, error);
    throw error;
  }
}

/**
 * Helper function to make API requests to VirusTotal
 * Handles authentication and error handling for all VirusTotal API calls
 * 
 * @template T The expected response type
 * @param {string} endpoint The API endpoint to call
 * @param {string} method The HTTP method to use
 * @param {any} data Data to send in request body (for POST requests)
 * @param {Record<string, string | number>} params Query parameters to include
 * @returns {Promise<T>} The API response
 * @throws {Error} If the API request fails or if the API key is not set
 */
async function virusTotalApiRequest<T>(
  endpoint: string, 
  method: 'get' | 'post' = 'get',
  data?: any,
  params?: Record<string, string | number>
): Promise<T> {
  
  if (!virusTotalApiKey) {
    throw new Error("VirusTotal API key is not set");
  }
  
  try {
    const config = {
      headers: {
        'x-apikey': virusTotalApiKey
      },
      params
    };
    
    let response;
    
    if (method === 'get') {
      response = await axios.get(`${VIRUSTOTAL_API_BASE_URL}${endpoint}`, config);
    } else {
      response = await axios.post(`${VIRUSTOTAL_API_BASE_URL}${endpoint}`, data, config);
    }
    
    return response.data as T;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const errorMessage = error.response?.data?.error?.message || error.message;
      throw new Error(`VirusTotal API error: ${errorMessage}`);
    }
    console.error(`Error making request to VirusTotal ${endpoint}:`, error);
    throw error;
  }
}

/**
 * Helper function to encode URL for VirusTotal API
 * VirusTotal API requires URLs to be base64 encoded
 * 
 * @param {string} url URL to encode
 * @returns {string} Base64 encoded URL
 */
function encodeUrlForVt(url: string): string {
  return Buffer.from(url).toString('base64url');
}

/**
 * Host Information Tool (Uses Shodan API)
 * Retrieves detailed information about a specific IP address from Shodan.
 * This includes:
 * - Basic host information (IP, organization, location)
 * - Open ports and services
 * - Banners and service details
 * - Historical data (if requested)
 * Uses 1 query credit per lookup
 */
server.tool(
  "host-info",
  "Get detailed information about a host from Shodan",
  {
    ip: z.string().describe("IP address to look up"),
    history: z.boolean().optional().describe("Include historical information (default: false)"),
    minify: z.boolean().optional().describe("Return only basic host information (default: false)")
  },
  async ({ ip, history = false, minify = false }) => {
    const data = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${ip}`, {
      history: history ? 'true' : 'false',
      minify: minify ? 'true' : 'false'
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * DNS Lookup Tool (Uses Shodan API)
 * Resolves domain names to IP addresses using Shodan's DNS service.
 * Supports multiple hostnames in a single request.
 */
server.tool(
  "dns-lookup",
  "Resolve hostnames to IP addresses",
  {
    hostnames: z.string().describe("Comma-separated list of hostnames to resolve (e.g., 'google.com,facebook.com')")
  },
  async ({ hostnames }) => {
    const data = await shodanApiRequest<ShodanDNSResolution>('/dns/resolve', {
      hostnames
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Reverse DNS Tool (Uses Shodan API)
 * Performs reverse DNS lookups on IP addresses using Shodan's DNS service.
 * Supports multiple IP addresses in a single request.
 */
server.tool(
  "reverse-dns",
  "Look up hostnames for IP addresses",
  {
    ips: z.string().describe("Comma-separated list of IP addresses (e.g., '8.8.8.8,1.1.1.1')")
  },
  async ({ ips }) => {
    const data = await shodanApiRequest<ShodanReverseDNS>('/dns/reverse', {
      ips
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Domain Information Tool (Uses Shodan API)
 * Retrieves all available information about a domain including:
 * - DNS entries
 * - Subdomains
 * - All known IPs
 */
server.tool(
  "domain-info",
  "Get DNS entries and subdomains for a domain",
  {
    domain: z.string().describe("Domain name to look up (e.g., 'example.com')")
  },
  async ({ domain }) => {
    const data = await shodanApiRequest<ShodanDomainInfo>('/dns/domain/' + domain);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Shodan Hello Tool (Uses Shodan API)
 * Simple test tool to verify the Shodan API is working.
 * Returns a welcome message if successful.
 */
server.tool(
  "hello",
  "Test if the ADEO CTI MCP server is working",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<{ welcome: string }>('/');
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Shodan Search Tool (Uses Shodan API)
 * Powerful search interface to Shodan's host database.
 * Supports complex queries with filters and facets.
 * Uses query credits based on request parameters.
 */
server.tool(
  "search-host",
  "Search Shodan",
  {
    query: z.string().describe("Shodan search query (e.g. 'apache country:DE')"),
    facets: z.string().optional().describe("Comma-separated list of properties to get summary information"),
    page: z.number().optional().describe("Page number for results (1 credit per page after 1st)")
  },
  async ({ query, facets, page }) => {
    const params: Record<string, string | number> = { query };
    if (facets) params.facets = facets;
    if (page) params.page = page;
    
    const data = await shodanApiRequest<ShodanSearchResult>('/shodan/host/search', params);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Search Count Tool (Uses Shodan API)
 * Get the total number of results for a search query without returning results.
 * Supports facets for summary information.
 * Uses 1 query credit if search query contains a filter.
 */
server.tool(
  "search-host-count",
  "Search Shodan without Results",
  {
    query: z.string().describe("Shodan search query (e.g. 'apache country:DE')"),
    facets: z.string().optional().describe("Comma-separated list of properties to get summary information")
  },
  async ({ query, facets }) => {
    const params: Record<string, string> = { query };
    if (facets) {
      params.facets = facets;
    }

    const data = await shodanApiRequest<ShodanSearchResult>("/shodan/host/count", params);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List Search Facets Tool (Uses Shodan API)
 * Returns a list of available facets that can be used to get summary information
 * in search results. These facets help analyze and group search results.
 */
server.tool(
  "list-search-facets",
  "List all search facets",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanSearchFacets>("/shodan/host/search/facets");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List Search Filters Tool (Uses Shodan API)
 * Returns a list of available search filters that can be used to narrow down
 * search results. These filters are used in search queries to target specific
 * attributes of hosts.
 */
server.tool(
  "list-search-filters",
  "List all filters that can be used when searching",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanSearchFilters>("/shodan/host/search/filters");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Search Query Tokens Tool (Uses Shodan API)
 * Break down a search query into tokens for analysis.
 * Helps understand how Shodan interprets search queries and validates
 * query syntax before performing actual searches.
 */
server.tool(
  "search-tokens",
  "Break the search query into tokens",
  {
    query: z.string().describe("Shodan search query to analyze")
  },
  async ({ query }) => {
    const data = await shodanApiRequest<ShodanSearchTokens>("/shodan/host/search/tokens", { query });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List All Ports Tool (Uses Shodan API)
 * Returns a list of port numbers that Shodan is currently scanning on the Internet.
 * This information is useful for understanding what services Shodan can discover
 * and what ports are being monitored.
 */
server.tool(
  "list-ports",
  "List all ports that Shodan is crawling on the Internet",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanPorts>("/shodan/ports");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List All Protocols Tool
 * Returns a list of protocols that can be used when performing Internet scans
 */
server.tool(
  "list-protocols",
  "List all protocols that can be used for scanning",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanProtocols>("/shodan/protocols");
      
      let formattedText = "## Available Scanning Protocols\n\n";
      formattedText += "The following protocols can be used for Internet scanning:\n\n";
      
      // Group protocols by category based on common prefixes or purposes
      const categories: { [key: string]: { [protocol: string]: string } } = {
        "Web Protocols": {},
        "Database Protocols": {},
        "Industrial Protocols": {},
        "Remote Access": {},
        "Other": {}
      };

      for (const [protocol, description] of Object.entries(data)) {
        if (protocol.includes("http") || protocol.includes("ssl")) {
          categories["Web Protocols"][protocol] = description;
        } else if (protocol.includes("sql") || protocol.includes("db")) {
          categories["Database Protocols"][protocol] = description;
        } else if (protocol.includes("ics") || protocol.includes("scada")) {
          categories["Industrial Protocols"][protocol] = description;
        } else if (protocol.includes("ssh") || protocol.includes("telnet") || protocol.includes("rdp")) {
          categories["Remote Access"][protocol] = description;
        } else {
          categories["Other"][protocol] = description;
        }
      }

      for (const [category, protocols] of Object.entries(categories)) {
        if (Object.keys(protocols).length > 0) {
          formattedText += `### ${category}\n\n`;
          for (const [protocol, description] of Object.entries(protocols)) {
            formattedText += `- **${protocol}**: ${description}\n`;
          }
          formattedText += "\n";
        }
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error getting protocols list: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Request Scan Tool
 * Initiates a scan of specific IPs or networks
 * Uses 1 scan credit per IP address
 */
server.tool(
  "request-scan",
  "Request Shodan to scan an IP/network",
  {
    ips: z.string().describe("Comma-separated list of IPs or networks in CIDR notation (e.g. '8.8.8.8,1.1.1.1/24')"),
  },
  async ({ ips }) => {
    try {
      const data = await shodanApiRequest<ShodanScanResult>("/shodan/scan", { ips }, "POST");
      
      let formattedText = "## Scan Request Submitted\n\n";
      formattedText += `**Scan ID:** ${data.id}\n`;
      formattedText += `**IPs to be scanned:** ${data.count}\n`;
      formattedText += `**Credits remaining:** ${data.credits_left}\n\n`;
      formattedText += "Use the 'get-scan-status' tool to check the progress of this scan.\n";

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error requesting scan: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get Scan Status Tool
 * Checks the progress of a previously submitted scan
 */
server.tool(
  "get-scan-status",
  "Get the status of a scan request",
  {
    id: z.string().describe("The unique scan ID returned by request-scan"),
  },
  async ({ id }) => {
    try {
      const data = await shodanApiRequest<ShodanScanStatus>(`/shodan/scans/${id}`);
      
      let formattedText = "## Scan Status\n\n";
      formattedText += `**Scan ID:** ${data.id}\n`;
      formattedText += `**Status:** ${data.status}\n`;
      formattedText += `**Created:** ${data.created}\n`;
      formattedText += `**IPs being scanned:** ${data.count}\n\n`;

      if (data.status === 'DONE') {
        formattedText += "✅ The scan has completed. You can now search for the results using the search-host tool.\n";
      } else {
        formattedText += "⏳ The scan is still in progress. Check back later for results.\n";
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error getting scan status: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Scans Tool (Uses Shodan API)
 * Returns a list of all scans that have been submitted to Shodan.
 * Shows scan status, progress, and credits used for each scan.
 */
server.tool(
  "list-scans",
  "Get list of all submitted scans",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanScanList>("/shodan/scans");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List Alert Triggers Tool (Uses Shodan API)
 * Returns a list of available network alert triggers that can be used
 * to monitor network events and changes. These triggers define the conditions
 * that will cause an alert to fire.
 */
server.tool(
  "list-triggers",
  "List available triggers for network alerts",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanTriggerList>("/shodan/alert/triggers");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Create Alert Tool (Uses Shodan API)
 * Creates a network alert for monitoring specific IP addresses or ports.
 * Alerts can be configured to notify you when network changes are detected
 * based on the specified filters.
 */
server.tool(
  "create-alert",
  "Create a network alert for monitoring",
  {
    name: z.string().describe("Name of the alert"),
    filters: z.object({
      ip: z.array(z.string()).optional().describe("List of IP addresses to monitor"),
      port: z.array(z.number()).optional().describe("List of ports to monitor"),
    }).describe("Filters to apply (can include IP addresses and ports)"),
    expires: z.number().optional().describe("Number of seconds the alert should be active (optional)"),
  },
  async ({ name, filters, expires }) => {
    const params: Record<string, any> = {
      name,
      filters: JSON.stringify(filters)
    };

    if (expires) {
      params.expires = expires;
    }

    const data = await shodanApiRequest<ShodanAlert>("/shodan/alert", params, "POST");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Get Alert Info Tool (Uses Shodan API)
 * Retrieves detailed information about a specific network alert including:
 * - Alert configuration and filters
 * - Recent matches
 * - Status and expiration
 */
server.tool(
  "get-alert-info",
  "Get information about a specific alert",
  {
    id: z.string().describe("Alert ID to get information about")
  },
  async ({ id }) => {
    const data = await shodanApiRequest<ShodanAlertInfo>(`/shodan/alert/${id}/info`);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Delete Alert Tool
 * Remove a specified network alert
 */
server.tool(
  "delete-alert",
  "Delete a network alert",
  {
    id: z.string().describe("Alert ID to delete"),
  },
  async ({ id }) => {
    try {
      await shodanApiRequest(`/shodan/alert/${id}`, {}, "DELETE");
      
      return {
        content: [
          {
            type: "text",
            text: `✅ Alert ${id} has been successfully deleted.`
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error deleting alert: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Edit Alert Tool
 * Modify an existing network alert
 */
server.tool(
  "edit-alert",
  "Edit an existing alert",
  {
    id: z.string().describe("Alert ID to edit"),
    name: z.string().optional().describe("New name for the alert"),
    filters: z.object({
      ip: z.array(z.string()).optional().describe("New list of IP addresses to monitor"),
      port: z.array(z.number()).optional().describe("New list of ports to monitor"),
    }).optional().describe("New filters to apply"),
  },
  async ({ id, name, filters }) => {
    try {
      const params: Record<string, any> = {};
      if (name) params.name = name;
      if (filters) params.filters = JSON.stringify(filters);

      const data = await shodanApiRequest<ShodanAlert>(`/shodan/alert/${id}`, params, "POST");
      
      let formattedText = "## Alert Updated Successfully\n\n";
      formattedText += `**Alert ID:** ${data.id}\n`;
      formattedText += `**Name:** ${data.name}\n`;
      formattedText += `**Created:** ${data.created}\n`;
      if (data.expires) {
        formattedText += `**Expires:** ${data.expires}\n`;
      }
      formattedText += `**Size:** ${data.size} IP(s)\n`;
      formattedText += `**Credits:** ${data.credits}\n\n`;
      
      formattedText += "### Updated Filters\n";
      if (data.filters.ip && data.filters.ip.length > 0) {
        formattedText += "**IP Addresses:**\n";
        data.filters.ip.forEach(ip => {
          formattedText += `- ${ip}\n`;
        });
      }
      if (data.filters.port && data.filters.port.length > 0) {
        formattedText += "**Ports:**\n";
        data.filters.port.forEach(port => {
          formattedText += `- ${port}\n`;
        });
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error updating alert: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Alerts Tool (Uses Shodan API)
 * Returns a list of all active network alerts for your account.
 * Shows alert configurations, filters, and monitoring status.
 */
server.tool(
  "list-alerts",
  "List all active alerts",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanAlertList>("/shodan/alert");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List Saved Queries Tool (Uses Shodan API)
 * Returns a list of search queries that users have saved in Shodan.
 * Queries can be sorted by votes or timestamp and paginated.
 * These are community-shared search queries useful for discovering services.
 */
server.tool(
  "list-queries",
  "List saved search queries",
  {
    page: z.number().optional().describe("Page number of results (default: 1)"),
    sort: z.enum(["votes", "timestamp"]).optional().describe("Sort queries by (votes or timestamp)"),
    order: z.enum(["asc", "desc"]).optional().describe("Sort order (asc or desc)"),
  },
  async ({ page = 1, sort = "votes", order = "desc" }) => {
    const data = await shodanApiRequest<ShodanQueryList>("/shodan/query", {
      page,
      sort,
      order
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Search Queries Tool (Uses Shodan API)
 * Search through the database of saved search queries.
 * Helps find useful search queries created by the community
 * for discovering specific types of devices or services.
 */
server.tool(
  "search-queries",
  "Search through saved queries",
  {
    query: z.string().describe("Search term to find queries"),
    page: z.number().optional().describe("Page number of results (default: 1)"),
  },
  async ({ query, page = 1 }) => {
    const data = await shodanApiRequest<ShodanQueryList>("/shodan/query/search", {
      query,
      page
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * List Query Tags Tool (Uses Shodan API)
 * Returns a list of popular tags for the saved search queries.
 * Tags help categorize and discover relevant search queries
 * for specific types of devices, services, or vulnerabilities.
 */
server.tool(
  "list-query-tags",
  "List popular tags for saved queries",
  {
    size: z.number().optional().describe("Number of tags to return (default: 10)"),
  },
  async ({ size = 10 }) => {
    const data = await shodanApiRequest<ShodanQueryTags>("/shodan/query/tags", { size });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Get Account Profile Tool (Uses Shodan API)
 * Returns information about the Shodan account linked to the API key.
 * Shows account details, membership status, and credits.
 */
server.tool(
  "get-profile",
  "Get account profile information",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanAccount>("/account/profile");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * Get API Info Tool
 * Returns information about the API plan belonging to the given API key
 */
server.tool(
  "get-api-info",
  "Get API subscription information",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanApiStatus>("/api-info");
      
      let formattedText = "## API Information\n\n";
      formattedText += `**Plan:** ${data.plan}\n`;
      formattedText += `**HTTPS Enabled:** ${data.https ? 'Yes' : 'No'}\n`;
      formattedText += `**Unlocked:** ${data.unlocked ? 'Yes' : 'No'}\n\n`;
      
      formattedText += "### Credits\n";
      formattedText += `**Scan Credits:** ${data.scan_credits}\n\n`;
      
      formattedText += "### Usage Limits\n";
      formattedText += `**Scan Credits:** ${data.usage_limits.scan_credits}\n`;
      formattedText += `**Query Credits:** ${data.usage_limits.query_credits}\n`;
      formattedText += `**Monitored IPs:** ${data.usage_limits.monitored_ips}\n`;

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error getting API information: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get Billing Profile Tool
 * Returns the billing information for the account
 */
server.tool(
  "get-billing",
  "Get billing profile information",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanBillingProfile>("/billing");
      
      let formattedText = "## Billing Profile\n\n";
      formattedText += `**Name:** ${data.name}\n`;
      formattedText += `**Address:** ${data.address}\n`;
      formattedText += `**City:** ${data.city}\n`;
      formattedText += `**State:** ${data.state}\n`;
      formattedText += `**Postal Code:** ${data.postal_code}\n`;
      formattedText += `**Country:** ${data.country}\n\n`;
      
      formattedText += "### Payment Information\n";
      formattedText += `**Card Last 4:** •••• ${data.card_last4}\n`;
      formattedText += `**Card Expiration:** ${data.card_expiration}\n`;

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error getting billing information: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get HTTP Headers Tool
 * Returns the HTTP headers that your client sends when connecting to a webserver
 */
server.tool(
  "get-http-headers",
  "View the HTTP headers that you're sending in requests",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanHTTPHeaders>("/tools/httpheaders");
      
      let formattedText = "## Your HTTP Headers\n\n";
      formattedText += "| Header | Value |\n";
      formattedText += "| ------ | ----- |\n";
      
      for (const [header, value] of Object.entries(data)) {
        formattedText += `| ${header} | ${value} |\n`;
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error getting HTTP headers: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get My IP Tool (Uses Shodan API)
 * Get your current IP address as seen from the Internet.
 * Useful for verifying your external IP address and network configuration.
 */
server.tool(
  "get-my-ip",
  "View your current IP address",
  {
    random_string: z.string().describe("Dummy parameter for no-parameter tools")
  },
  async () => {
    const data = await shodanApiRequest<ShodanMyIP>("/tools/myip");
    return {
      content: [{
        type: "text",
        text: JSON.stringify(data, null, 2)
      }]
    };
  }
);

/**
 * VirusTotal URL Analysis Tool (Uses VirusTotal API)
 * Analyzes a URL for security threats using VirusTotal's API.
 * Returns comprehensive analysis including:
 * - Detection ratios from security vendors
 * - Categories and reputation data
 * - Related malicious indicators
 * - Relationships with other threats
 */
server.tool(
  "virustotal-url-analysis",
  "Analyze a URL for security threats using VirusTotal",
  {
    url: z.string().url("Must be a valid URL").describe("The URL to analyze")
  },
  async ({ url }) => {
    // First submit URL for scanning
    const encodedUrl = encodeUrlForVt(url);
    const scanResponse = await virusTotalApiRequest<VirusTotalResponse<VirusTotalUrlAnalysis>>(
      '/urls',
      'post',
      new URLSearchParams({ url })
    );
    
    const analysisId = scanResponse.data.id;
    
    // Wait for analysis to complete
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Get analysis results
    const analysisResponse = await virusTotalApiRequest<VirusTotalResponse<VirusTotalUrlAnalysis>>(
      `/analyses/${analysisId}`
    );

    return {
      content: [{
        type: "text",
        text: JSON.stringify(analysisResponse.data, null, 2)
      }]
    };
  }
);

/**
 * VirusTotal File Analysis Tool (Uses VirusTotal API)
 * Analyzes a file hash for malware and security threats using VirusTotal's API.
 * Returns comprehensive analysis including:
 * - Multi-engine antivirus scan results
 * - File behavior analysis
 * - YARA and SIGMA rule matches
 * - Related malware families and threats
 */
server.tool(
  "virustotal-file-analysis",
  "Analyze a file hash for malware using VirusTotal",
  {
    hash: z.string()
      .regex(/^[a-fA-F0-9]{32,64}$/, "Must be a valid MD5, SHA-1, or SHA-256 hash")
      .describe("MD5, SHA-1 or SHA-256 hash of the file")
  },
  async ({ hash }) => {
    const response = await virusTotalApiRequest<VirusTotalResponse<VirusTotalFileAnalysis>>(
      `/files/${hash}`
    );
    return {
      content: [{
        type: "text",
        text: JSON.stringify(response.data, null, 2)
      }]
    };
  }
);

/**
 * VirusTotal IP Analysis Tool
 * Analyzes an IP address for security threats using VirusTotal's API
 * Returns comprehensive analysis including:
 * - Reputation data from security vendors
 * - Associated malicious activities
 * - Network infrastructure details
 * - Historical security incidents
 */
server.tool(
  "virustotal-ip-analysis",
  "Analyze an IP address for security threats using VirusTotal",
  {
    ip: z.string()
      .ip("Must be a valid IP address")
      .describe("IP address to analyze")
  },
  async ({ ip }) => {
    try {
      // Get IP report
      const response = await virusTotalApiRequest<VirusTotalResponse<VirusTotalIpAnalysis>>(
        `/ip_addresses/${ip}`
      );

      const attributes = response.data.attributes;
      
      let formattedText = `## IP Analysis Results for ${ip}\n\n`;
      
      // Add network information
      formattedText += "### Network Information\n";
      if (attributes.as_owner) formattedText += `**AS Owner:** ${attributes.as_owner}\n`;
      if (attributes.asn) formattedText += `**ASN:** ${attributes.asn}\n`;
      if (attributes.network) formattedText += `**Network:** ${attributes.network}\n`;
      if (attributes.country) formattedText += `**Country:** ${attributes.country}\n`;
      if (attributes.continent) formattedText += `**Continent:** ${attributes.continent}\n`;
      if (attributes.regional_internet_registry) {
        formattedText += `**Regional Internet Registry:** ${attributes.regional_internet_registry}\n`;
      }
      formattedText += "\n";

      // Add detection statistics
      if (attributes.last_analysis_stats) {
        const stats = attributes.last_analysis_stats;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        
        formattedText += "### Detection Statistics\n";
        formattedText += `- 🔴 Malicious: ${stats.malicious} (${((stats.malicious/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⚠️ Suspicious: ${stats.suspicious} (${((stats.suspicious/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ✅ Clean: ${stats.harmless} (${((stats.harmless/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⚪ Undetected: ${stats.undetected} (${((stats.undetected/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⏳ Timeout: ${stats.timeout} (${((stats.timeout/total) * 100).toFixed(1)}%)\n\n`;
      }

      // Add reputation information
      if (attributes.reputation !== undefined) {
        formattedText += "### Reputation\n";
        formattedText += `**Score:** ${attributes.reputation}\n`;
        if (attributes.total_votes) {
          formattedText += `**Community Votes:**\n`;
          formattedText += `- 👍 Harmless: ${attributes.total_votes.harmless}\n`;
          formattedText += `- 👎 Malicious: ${attributes.total_votes.malicious}\n`;
        }
        formattedText += "\n";
      }

      // Add JARM fingerprint if available
      if (attributes.jarm) {
        formattedText += "### JARM Fingerprint\n";
        formattedText += `\`${attributes.jarm}\`\n\n`;
      }

      // Add SSL certificate information
      if (attributes.last_https_certificate) {
        const cert = attributes.last_https_certificate;
        formattedText += "### SSL Certificate Information\n";
        
        if (cert.issuer) {
          formattedText += "**Issuer:**\n";
          if (cert.issuer.CN) formattedText += `- Common Name: ${cert.issuer.CN}\n`;
          if (cert.issuer.O) formattedText += `- Organization: ${cert.issuer.O}\n`;
          if (cert.issuer.C) formattedText += `- Country: ${cert.issuer.C}\n`;
        }

        if (cert.subject && cert.subject.CN) {
          formattedText += `**Subject Common Name:** ${cert.subject.CN}\n`;
        }

        if (cert.validity) {
          formattedText += "**Validity Period:**\n";
          formattedText += `- Not Before: ${new Date(cert.validity.not_before).toLocaleString()}\n`;
          formattedText += `- Not After: ${new Date(cert.validity.not_after).toLocaleString()}\n`;
        }
        formattedText += "\n";
      }

      // Add WHOIS information if available
      if (attributes.whois) {
        formattedText += "### WHOIS Information\n";
        formattedText += "```\n";
        formattedText += attributes.whois;
        formattedText += "\n```\n\n";
        
        if (attributes.whois_date) {
          formattedText += `**Last Updated:** ${new Date(attributes.whois_date * 1000).toLocaleString()}\n\n`;
        }
      }

      // Add tags if available
      if (attributes.tags && attributes.tags.length > 0) {
        formattedText += "### Tags\n";
        formattedText += attributes.tags.map(tag => `- ${tag}`).join("\n");
        formattedText += "\n";
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error analyzing IP: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * VirusTotal Domain Analysis Tool (Uses VirusTotal API)
 * Analyzes a domain for security threats using VirusTotal's API.
 * Returns comprehensive analysis including:
 * - Domain registration and WHOIS information
 * - DNS records and configurations
 * - Security detections and reputation
 * - Related malicious indicators
 */
server.tool(
  "virustotal-domain-analysis",
  "Analyze a domain for security threats using VirusTotal",
  {
    domain: z.string()
      .regex(/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/, "Must be a valid domain name")
      .describe("Domain name to analyze")
  },
  async ({ domain }) => {
    try {
      // Get domain report
      const response = await virusTotalApiRequest<VirusTotalResponse<VirusTotalDomainAnalysis>>(
        `/domains/${domain}`
      );

      const attributes = response.data.attributes;
      
      let formattedText = `## Domain Analysis Results for ${domain}\n\n`;
      
      // Add creation and last update dates
      if (attributes.creation_date || attributes.last_update_date) {
        formattedText += "### Registration Information\n";
        if (attributes.creation_date) {
          formattedText += `**Created:** ${new Date(attributes.creation_date * 1000).toLocaleString()}\n`;
        }
        if (attributes.last_update_date) {
          formattedText += `**Last Updated:** ${new Date(attributes.last_update_date * 1000).toLocaleString()}\n`;
        }
        if (attributes.registrar) {
          formattedText += `**Registrar:** ${attributes.registrar}\n`;
        }
        formattedText += "\n";
      }

      // Add detection statistics
      if (attributes.last_analysis_stats) {
        const stats = attributes.last_analysis_stats;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        
        formattedText += "### Detection Statistics\n";
        formattedText += `- 🔴 Malicious: ${stats.malicious} (${((stats.malicious/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⚠️ Suspicious: ${stats.suspicious} (${((stats.suspicious/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ✅ Clean: ${stats.harmless} (${((stats.harmless/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⚪ Undetected: ${stats.undetected} (${((stats.undetected/total) * 100).toFixed(1)}%)\n`;
        formattedText += `- ⏳ Timeout: ${stats.timeout} (${((stats.timeout/total) * 100).toFixed(1)}%)\n\n`;
      }

      // Add reputation information
      if (attributes.reputation !== undefined) {
        formattedText += "### Reputation\n";
        formattedText += `**Score:** ${attributes.reputation}\n`;
        if (attributes.total_votes) {
          formattedText += `**Community Votes:**\n`;
          formattedText += `- 👍 Harmless: ${attributes.total_votes.harmless}\n`;
          formattedText += `- 👎 Malicious: ${attributes.total_votes.malicious}\n`;
        }
        formattedText += "\n";
      }

      // Add categories if available
      if (attributes.categories && Object.keys(attributes.categories).length > 0) {
        formattedText += "### Categories\n";
        for (const [source, category] of Object.entries(attributes.categories)) {
          formattedText += `- ${source}: ${category}\n`;
        }
        formattedText += "\n";
      }

      // Add DNS records if available
      if (attributes.last_dns_records && attributes.last_dns_records.length > 0) {
        formattedText += "### DNS Records\n";
        formattedText += "| Type | Value | TTL |\n";
        formattedText += "|------|--------|-----|\n";
        attributes.last_dns_records.forEach(record => {
          formattedText += `| ${record.type} | ${record.value} | ${record.ttl} |\n`;
        });
        formattedText += "\n";
      }

      // Add popularity rankings if available
      if (attributes.popularity_ranks && Object.keys(attributes.popularity_ranks).length > 0) {
        formattedText += "### Popularity Rankings\n";
        for (const [source, data] of Object.entries(attributes.popularity_ranks)) {
          formattedText += `- ${source}: Rank ${data.rank}\n`;
        }
        formattedText += "\n";
      }

      // Add WHOIS information if available
      if (attributes.whois) {
        formattedText += "### WHOIS Information\n";
        formattedText += "```\n";
        formattedText += attributes.whois;
        formattedText += "\n```\n\n";
        
        if (attributes.whois_date) {
          formattedText += `**Last Updated:** ${new Date(attributes.whois_date * 1000).toLocaleString()}\n\n`;
        }
      }

      // Add tags if available
      if (attributes.tags && attributes.tags.length > 0) {
        formattedText += "### Tags\n";
        formattedText += attributes.tags.map(tag => `- ${tag}`).join("\n");
        formattedText += "\n";
      }

      return {
        content: [
          {
            type: "text",
            text: formattedText
          }
        ]
      };
    } catch (error) {
      const err = error as Error;
      return {
        content: [
          {
            type: "text",
            text: `Error analyzing domain: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

// Consolidated Cybersecurity Analysis Workflow Prompts

// Asset Discovery and Reconnaissance Prompt
server.prompt(
  "asset-discovery",
  "Discover and analyze internet-facing assets and infrastructure",
  {
    target: z.string().describe("Domain, IP address, or organization name to analyze"),
    depth: z.enum(["basic", "comprehensive"]).optional().describe("Depth of reconnaissance")
  },
  (args) => {
    const comprehensive = args.depth === "comprehensive";
      
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform a ${args.depth || "basic"} asset discovery and infrastructure mapping for ${args.target}:

1. Initial Reconnaissance
   - If target is a domain:
     * Use domain-info tool with domain="${args.target}"
     * Document DNS records and subdomains
   - If target is an IP:
     * Use host-info tool with ip="${args.target}" and history=${comprehensive ? "true" : "false"}
     * Use reverse-dns tool with ips="${args.target}"
   - If target is an organization name:
     * Use search-host tool with query="org:\\"${args.target}\\""

2. Asset Enumeration
   - Document discovered hosts and IP addresses
   - Identify open ports and services
   - Catalog geographical distribution
   - Note organizations and ASNs

3. Service Analysis
   - Identify exposed service types and versions
   - Document technologies in use (products, software)
   - Note unusual or potentially vulnerable services
   - Look for default configurations or exposed interfaces

4. Security Assessment
   - Highlight potential security exposures
   - Identify systems with known vulnerabilities
   - Note outdated software versions
   - Document unusual port or service combinations

Present findings in a structured report focused on the internet-facing assets discovered through Shodan.`
        }
      }]
    };
  }
);

// Vulnerability Assessment Prompt
server.prompt(
  "vulnerability-assessment",
  "Find vulnerabilities in internet-connected systems",
  {
    target_type: z.enum(["host", "domain", "cpe", "cve"]).describe("Type of target to analyze"),
    target: z.string().describe("Target identifier (IP, domain, CPE string, or CVE ID)"),
    severity_threshold: z.enum(["all", "medium", "high", "critical"]).optional().describe("Minimum severity threshold"),
    include_vt_analysis: z.enum(["yes", "no"]).optional().describe("Include VirusTotal security analysis (default: no)")
  },
  (args) => {
    const severity_map = {
      "all": "0",
      "medium": "4.0",
      "high": "7.0",
      "critical": "9.0"
    };
    
    const min_cvss = severity_map[args.severity_threshold || "all"];
    const includeVt = args.include_vt_analysis === "yes";
    
    const initial_instructions = 
      args.target_type === "host" ?
        `- Use host-info tool with:
   * ip="${args.target}"
   * history=true
   - Examine the banners and vulnerability information in the results
   ${includeVt ? `- Use virustotal-ip-analysis for additional security context` : ''}` :
      args.target_type === "domain" ?
        `- Use domain-info tool with domain="${args.target}"
   - For each IP discovered, use host-info to check for vulnerabilities
   - Pay special attention to subdomains with unusual services
   ${includeVt ? `- Use virustotal-domain-analysis for security assessment
   - For each IP, use virustotal-ip-analysis` : ''}` :
      args.target_type === "cpe" ?
        `- Use cpe-vuln-search tool with:
   * cpe="${args.target}"
   * minCvss=${min_cvss}
   * maxResults=100` :
        `- Use cve-lookup tool with cve="${args.target}"`;
      
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform a vulnerability assessment for ${args.target_type} "${args.target}" with severity threshold ${args.severity_threshold || "all"}:

1. Vulnerability Discovery
   ${initial_instructions}

2. Vulnerability Assessment
   - Identify vulnerability types and categories
   - Note CVE IDs and CVSS scores 
   - Examine service versions and affected products
   - Document exposure dates and discovery timing
   ${includeVt ? `- Include VirusTotal intelligence:
     * Known malware associations
     * Security incidents history
     * Detection ratios and reputation` : ''}

3. Risk Contextualization
   - Prioritize vulnerabilities by severity
   - Highlight internet-exposed vulnerable services
   - Note common exploitation vectors
   - Consider scope of potential impact
   ${includeVt ? `- Analyze threat context:
     * Historical attack patterns
     * Related malicious activities
     * Associated threat indicators` : ''}

4. Remediation Guidance
   - Suggest version upgrades where applicable
   - Recommend configuration changes
   - Advise on exposure reduction options
   - Propose monitoring and alerting measures
   ${includeVt ? `- Include threat mitigation:
     * Specific security controls
     * Detection strategies
     * Monitoring recommendations` : ''}

Present findings based on ${includeVt ? 'combined Shodan vulnerability data and VirusTotal security intelligence' : 'Shodan vulnerability data'}.`
        }
      }]
    };
  }
);

// Internet Search Prompt (Uses Shodan API)
/**
 * Internet Search Prompt (Uses Shodan API)
 * A guided workflow for searching and analyzing specific types of
 * internet-connected systems or services. Helps construct effective
 * Shodan search queries and analyze results.
 */
server.prompt(
  "internet-search",
  "Search for specific internet-connected systems or services",
  {
    search_type: z.enum([
      "service",
      "product",
      "vulnerability",
      "organization",
      "custom"
    ]).describe("Type of search to perform"),
    query: z.string().describe("Search terms or Shodan query string"),
    filters: z.string().optional().describe("Additional Shodan filters to apply")
  },
  (args) => {
    const base_query = args.search_type === "custom" ? 
      args.query :
      args.search_type === "service" ?
        `port:"${args.query}"` :
      args.search_type === "product" ?
        `product:"${args.query}"` :
      args.search_type === "vulnerability" ?
        `vuln:"${args.query}"` :
        `org:"${args.query}"`;

    const final_query = args.filters ? 
      `${base_query} ${args.filters}`.trim() :
      base_query;

    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Analyze internet-connected systems matching "${final_query}":

1. Initial Search
   - Use search-host tool with:
     * query="${final_query}"
     * facets="country,org,product"
   - Document total results found
   - Note geographical distribution
   - List top organizations

2. Result Analysis
   - Identify common service types
   - Document software versions
   - Note unusual configurations
   - Highlight potential security implications

3. Detailed Investigation
   - Sample specific hosts for deeper analysis
   - Check for known vulnerabilities
   - Document interesting banners or metadata
   - Note any concerning exposures

4. Summary Report
   - Provide overview of findings
   - Highlight notable discoveries
   - Suggest additional search refinements
   - Document any security considerations

Present findings based on data available through Shodan's search capabilities.`
        }
      }]
    };
  }
);

// Network Security Monitoring Prompt (Uses Shodan API)
/**
 * Network Monitoring Prompt (Uses Shodan API)
 * A guided workflow for setting up and managing network monitoring
 * alerts using Shodan's monitoring capabilities. Helps track changes
 * and detect security issues.
 */
server.prompt(
  "network-monitoring",
  "Set up network monitoring and alerts",
  {
    target: z.string().describe("IP, network range, or domain to monitor"),
    monitor_type: z.enum([
      "new-service",
      "vulnerability",
      "certificate",
      "custom"
    ]).describe("Type of changes to monitor"),
    notification_threshold: z.enum([
      "all",
      "high",
      "critical"
    ]).optional().describe("Minimum severity for notifications")
  },
  (args) => {
    const isIpRange = args.target.includes("/");
    const isDomain = args.target.includes(".");
    
    const setupInstructions = isIpRange ?
      `- Create alert for network range "${args.target}"
   - Set triggers for service changes and vulnerabilities` :
      isDomain ?
      `- Use domain-info tool to get IP addresses
   - Create alerts for discovered IPs
   - Monitor SSL certificates if applicable` :
      `- Create alert for single IP "${args.target}"
   - Set appropriate triggers based on services`;

    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Set up network monitoring for ${args.target} focusing on ${args.monitor_type} changes:

1. Initial Setup
   ${setupInstructions}

2. Alert Configuration
   - Configure appropriate triggers:
     * New services or ports
     * Vulnerability detections
     * SSL certificate changes
     * Custom conditions
   - Set notification thresholds
   - Define monitoring duration

3. Baseline Assessment
   - Document current services
   - Note existing vulnerabilities
   - Record SSL certificate details
   - Map current infrastructure

4. Monitoring Plan
   - Define response procedures
   - Set review schedules
   - Plan for false positive handling
   - Document escalation paths

Configure monitoring based on Shodan's alerting capabilities.`
        }
      }]
    };
  }
);

// Industrial Control System Analysis Prompt
server.prompt(
  "ics-analysis",
  "Analyze exposed industrial control systems and SCADA devices",
  {
    target_type: z.enum(["ip", "network", "product", "country"]).describe("Type of target to analyze"),
    target: z.string().describe("Target identifier (IP, network range, product name, or country code)"),
    protocol: z.string().optional().describe("Optional specific protocol to focus on")
  },
  (args) => {
    const protocol_filter = args.protocol ? ` ${args.protocol}` : '';
    const search_queries = {
      "ip": `ip:"${args.target}" tag:ics${protocol_filter}`,
      "network": `net:"${args.target}" tag:ics${protocol_filter}`,
      "product": `product:"${args.target}" tag:ics${protocol_filter}`,
      "country": `country:"${args.target}" tag:ics${protocol_filter}`
    };
    
    const query = search_queries[args.target_type];
      
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Analyze industrial control systems for ${args.target_type} "${args.target}"${args.protocol ? ' using protocol ' + args.protocol : ''}:

1. ICS Discovery
   - Use search-host tool with query="${query}"
   - Use search-host-count for statistical overview
   - Use list-protocols tool to identify available ICS protocols
   - For notable systems, use host-info to gather details

2. Device Analysis
   - Identify types of industrial devices exposed
   - Document protocols and ports in use
   - Note device manufacturers and models
   - Examine firmware and software versions

3. Exposure Assessment
   - Map geographical distribution of systems
   - Identify systems with direct internet exposure
   - Note authentication mechanisms (or lack thereof)
   - Document potentially vulnerable configurations

4. Security Observations
   - Highlight systems with known vulnerabilities
   - Note outdated firmware or software
   - Identify unusual exposure patterns
   - Document security-relevant configuration details

Present findings in a detailed report on the industrial systems discovered through Shodan.`
        }
      }]
    };
  }
);

// DNS Intelligence Prompt
server.prompt(
  "dns-intelligence",
  "Analyze DNS information for domains and IP addresses",
  {
    target_type: z.enum(["domain", "ip", "hostname"]).describe("Type of target to analyze"),
    target: z.string().describe("Domain name, IP address, or hostname to analyze"),
    include_history: z.enum(["yes", "no"]).optional().describe("Include historical information if available"),
    include_vt_analysis: z.enum(["yes", "no"]).optional().describe("Include VirusTotal security analysis (default: no)")
  },
  (args) => {
    const includeVt = args.include_vt_analysis === "yes";
    const lookup_instructions =
      args.target_type === "domain" ?
        `- Use domain-info tool with domain="${args.target}"
   - Document all subdomains and DNS records
   ${includeVt ? `- Use virustotal-domain-analysis for security assessment` : ''}` :
      args.target_type === "ip" ?
        `- Use reverse-dns tool with ips="${args.target}"
   - Examine all hostnames associated with the IP
   ${includeVt ? `- Use virustotal-ip-analysis for security assessment` : ''}` :
        `- Use dns-lookup tool with hostnames="${args.target}"
   - Check the resolved IP addresses
   ${includeVt ? `- For resolved IPs, use virustotal-ip-analysis` : ''}`;

    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform DNS intelligence analysis for ${args.target_type} "${args.target}":

1. DNS Reconnaissance
   ${lookup_instructions}
   - If analyzing a domain, use search-host with query="hostname:${args.target}"
   - If analyzing an IP, use host-info with ip="${args.target}"

2. DNS Structure Analysis
   - Map the DNS hierarchy
   - Document all records by type (A, AAAA, MX, CNAME, etc.)
   - Identify primary and secondary nameservers
   - Note DNS-based security mechanisms (SPF, DMARC, etc.)
   ${includeVt ? `- Include security context:
     * Domain categorization
     * SSL certificate analysis
     * Historical DNS patterns` : ''}

3. Infrastructure Assessment
   - Identify hosting providers and networks
   - Map geographical distribution
   - Document organization information
   - Note autonomous system numbers (ASNs)
   ${includeVt ? `- Security assessment:
     * Infrastructure reputation
     * Known security incidents
     * Associated threat indicators` : ''}

4. Security Observations
   - Flag unusual DNS configurations
   - Identify potential DNS-based vulnerabilities
   - Note signs of DNS misconfigurations
   - Highlight suspicious patterns if present
   ${includeVt ? `- Threat intelligence:
     * Malicious DNS usage
     * Related threat activities
     * Historical security events` : ''}

Present findings in a comprehensive DNS intelligence report based on ${includeVt ? 'Shodan data and VirusTotal security intelligence' : 'Shodan data'}.`
        }
      }]
    };
  }
);

// Service Exposure Analysis Prompt
server.prompt(
  "service-exposure",
  "Analyze specific service types exposed on the internet",
  {
    service_type: z.enum(["database", "webcam", "industrial", "remote-access", "custom"]).describe("Type of service to analyze"),
    target_scope: z.enum(["global", "country", "organization", "ip-range"]).describe("Scope of analysis"),
    target: z.string().optional().describe("Target value based on scope (country code, org name, IP range)"),
    custom_query: z.string().optional().describe("Custom query for the 'custom' service type"),
    include_vt_analysis: z.enum(["yes", "no"]).optional().describe("Include VirusTotal security analysis (default: no)")
  },
  (args) => {
    const includeVt = args.include_vt_analysis === "yes";
    
    // Define service-specific queries
    const service_queries = {
      "database": "category:database -product:http",
      "webcam": "webcam screenshot.available:true",
      "industrial": "tag:ics,scada,plc",
      "remote-access": "port:22,23,3389 product:SSH,RDP,Telnet",
      "custom": args.custom_query || ""
    };
    
    // Define scope-specific filters
    const scope_filters = {
      "global": "",
      "country": args.target ? `country:${args.target}` : "",
      "organization": args.target ? `org:"${args.target}"` : "",
      "ip-range": args.target ? `net:${args.target}` : ""
    };
    
    // Combine the queries
    const base_query = service_queries[args.service_type];
    const scope_filter = scope_filters[args.target_scope];
    const query = scope_filter ? `${base_query} ${scope_filter}` : base_query;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Analyze ${args.service_type} services ${args.target_scope !== "global" ? `for ${args.target_scope} "${args.target}"` : 'globally'}:

1. Service Discovery
   - Use search-host tool with query="${query}"
   - Use search-host-count with the same query and facets="country,org,product,version"
   - For notable systems, use host-info to gather detailed information
   ${includeVt ? `- For each critical service:
     * Use virustotal-ip-analysis for security assessment
     * For web services, use virustotal-url-analysis` : ''}

2. Exposure Analysis
   - Document total number of exposed services
   - Map geographical distribution
   - Identify top organizations exposing these services
   - Note common product types and versions
   ${includeVt ? `- Security context:
     * Service reputation scores
     * Known security incidents
     * Malicious usage patterns` : ''}

3. Configuration Assessment
   - Identify default or weak configurations
   - Note authentication mechanisms
   - Document unusual port assignments
   - Highlight risky service combinations
   ${includeVt ? `- Threat analysis:
     * Known vulnerable configurations
     * Common attack vectors
     * Security best practices` : ''}

4. Security Implications
   - Identify outdated or vulnerable versions
   - Note systems with known vulnerabilities
   - Document common misconfigurations
   - Highlight particularly sensitive exposures
   ${includeVt ? `- Threat intelligence:
     * Historical security events
     * Associated malicious activities
     * Related threat indicators` : ''}

Present findings in a detailed service exposure report based on ${includeVt ? 'Shodan data and VirusTotal security intelligence' : 'Shodan data'}.`
        }
      }]
    };
  }
);

// Account and API Status Prompt
server.prompt(
  "account-status",
  "Analyze account information and API usage status",
  {
    info_type: z.enum(["profile", "api", "usage", "all"]).describe("Type of account information to retrieve")
  },
  (args) => {
    const tool_instructions =
      args.info_type === "profile" ?
        `- Use get-profile tool to view account information` :
      args.info_type === "api" ?
        `- Use get-api-info tool to view API subscription details` :
      args.info_type === "usage" ?
        `- Use get-http-headers tool to view request details
   - Use get-my-ip tool to confirm your external IP` :
        `- Use get-profile tool for account information
   - Use get-api-info tool for API subscription details
   - Use get-http-headers and get-my-ip tools for usage information`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Analyze ${args.info_type === "all" ? "all" : args.info_type} account information:

1. Information Gathering
   ${tool_instructions}

2. Account Analysis
   - Summarize account status${args.info_type === "profile" || args.info_type === "all" ? `
   - Check membership status
   - Verify account creation date
   - Note available credits` : ''}${args.info_type === "api" || args.info_type === "all" ? `
   - Document API plan details
   - Check usage limits
   - Note monitoring capabilities
   - Verify scan credits availability` : ''}${args.info_type === "usage" || args.info_type === "all" ? `
   - Confirm current IP address
   - Examine HTTP headers
   - Verify connection details` : ''}

3. Status Summary
   - Provide concise account status overview
   - Highlight available capabilities
   - Note any limitations or restrictions
   - Summarize credit usage and availability

Present a clear summary of the requested account information.`
        }
      }]
    };
  }
);

// Scan Management Prompt
server.prompt(
  "scan-management",
  "Manage and analyze on-demand network scans",
  {
    action: z.enum(["initiate", "check", "list"]).describe("Scan action to perform"),
    target: z.string().optional().describe("Target IPs or networks to scan (comma-separated)"),
    scan_id: z.string().optional().describe("Scan ID for checking status")
  },
  (args) => {
    const action_instructions =
      args.action === "initiate" ?
        `- Use list-ports tool to see what ports Shodan is scanning
   - Use request-scan tool with ips="${args.target}"
   - Note the scan ID for future reference` :
      args.action === "check" ?
        `- Use get-scan-status tool with id="${args.scan_id}"
   - Check if the scan is complete or still in progress` :
        `- Use list-scans tool to see all your submitted scans
   - Note the status of each scan`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `${args.action.charAt(0).toUpperCase() + args.action.slice(1)} network scan ${args.action === "initiate" ? `for ${args.target}` : args.action === "check" ? `with ID ${args.scan_id}` : ""}:

1. Scan Management
   ${action_instructions}

2. Scan Analysis
   - Document scan details${args.action === "initiate" ? `
   - Note the target IP ranges
   - Check how many scan credits were used
   - Verify scan submission status` : args.action === "check" ? `
   - Check current scan progress
   - Verify when the scan was created
   - Note if scan is complete or still running` : `
   - Identify recently completed scans
   - Note scans still in progress
   - Check scan sizes and targets
   - Document credit usage`}

3. Next Steps
   - Provide guidance on follow-up actions${args.action === "initiate" ? `
   - Suggest using get-scan-status to monitor progress
   - Recommend search queries to find scan results when complete` : args.action === "check" ? `
   - If complete, suggest search queries to find the results
   - If in progress, recommend when to check again` : `
   - Highlight important scans to check
   - Suggest cleanup of old scans if necessary`}

Present a clear summary of the scan management action and results.`
        }
      }]
    };
  }
);

// Search Analytics Prompt
server.prompt(
  "search-analytics",
  "Analyze Shodan search capabilities and patterns",
  {
    action: z.enum(["analyze-query", "explore-facets", "examine-filters", "saved-queries"]).describe("Type of search analysis to perform"),
    query: z.string().optional().describe("Query to analyze (for analyze-query action)")
  },
  (args) => {
    const action_instructions =
      args.action === "analyze-query" ?
        `- Use search-tokens tool with query="${args.query}"
   - Examine the token breakdown and filters used` :
      args.action === "explore-facets" ?
        `- Use list-search-facets tool to get all available facets
   - Document facet options for data aggregation` :
      args.action === "examine-filters" ?
        `- Use list-search-filters tool to get all available search filters
   - Explore the filtering capabilities` :
        `- Use list-queries tool to view popular saved searches
   - Examine query patterns and common techniques`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform ${args.action.replace(/-/g, ' ')} analysis${args.action === "analyze-query" ? ` for query "${args.query}"` : ''}:

1. Search Analysis
   ${action_instructions}

2. Insights${args.action === "analyze-query" ? `
   - Break down the query components
   - Identify filters and their parameters
   - Note any syntax issues or errors
   - Suggest query improvements` : args.action === "explore-facets" ? `
   - Categorize available facets by type
   - Explain how facets can be used for data aggregation
   - Highlight useful facets for security analysis
   - Suggest combinations for effective analysis` : args.action === "examine-filters" ? `
   - Document filter categories and purposes
   - Explain syntax for different filter types
   - Highlight security-relevant filters
   - Suggest useful filter combinations` : `
   - Identify popular search patterns
   - Note common query techniques
   - Document security-focused queries
   - Highlight trending search topics`}

3. Applications
   - Suggest practical applications for the findings
   - Recommend how to improve search effectiveness
   - Provide tips for better data discovery
   - Outline advanced search strategies

Present a clear analysis based on Shodan's search capabilities.`
        }
      }]
    };
  }
);

// Targeted Vulnerability Hunting Prompt
server.prompt(
  "vulnerability-hunting",
  "Hunt for specific vulnerabilities across the internet",
  {
    vuln_type: z.enum(["cve", "product", "service", "custom"]).describe("Type of vulnerability to hunt"),
    target: z.string().describe("Vulnerability target (CVE ID, product name, service type)"),
    scope: z.enum(["global", "regional", "industry"]).optional().describe("Scope of the search"),
    scope_value: z.string().optional().describe("Value for scope (country, industry)")
  },
  (args) => {
    // Define base queries by vulnerability type
    const vuln_queries = {
      "cve": `vuln:"${args.target}"`,
      "product": `product:"${args.target}" -product:""`,
      "service": `port:${args.target}`,
      "custom": args.target
    };
    
    // Define scope filters
    const scope_filters = {
      "global": "",
      "regional": args.scope_value ? `country:${args.scope_value}` : "",
      "industry": args.scope_value ? `org:"${args.scope_value}"` : ""
    };
    
    // Build the query
    const base_query = vuln_queries[args.vuln_type];
    const scope_filter = scope_filters[args.scope || "global"];
    const query = scope_filter ? `${base_query} ${scope_filter}` : base_query;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Hunt for ${args.vuln_type === "cve" ? `CVE ${args.target}` : args.vuln_type === "product" ? `vulnerable ${args.target} products` : args.vuln_type === "service" ? `vulnerable services on port ${args.target}` : `custom vulnerability pattern "${args.target}"`}${args.scope && args.scope !== "global" ? ` in ${args.scope} ${args.scope_value}` : ''}:

1. Vulnerability Search
   - Use search-host tool with query="${query}"
   - Use search-host-count with the same query and facets="country,org,os,port,product,version"
   - For CVE-specific searches, use cve-lookup for detailed information

2. Exposure Analysis
   - Document total exposed vulnerable systems
   - Map geographical distribution
   - Identify most affected organizations
   - Note distribution across industries

3. Impact Assessment
   - Analyze affected system types
   - Document vulnerable service versions
   - Note exposure timeframes
   - Highlight critical infrastructure impacts

4. Technical Details
   - Document vulnerable configurations
   - Note common misconfigurations
   - Identify patch levels and versions
   - Record authentication mechanisms

Present a detailed vulnerability hunting report based purely on Shodan data.`
        }
      }]
    };
  }
);

// VirusTotal Analysis Prompts

// Malware Analysis Prompt
server.prompt(
  "malware-analysis",
  "Analyze files and URLs for malware and security threats",
  {
    target_type: z.enum(["file", "url"]).describe("Type of target to analyze"),
    target: z.string().describe("File hash (MD5/SHA1/SHA256) or URL to analyze"),
    include_relationships: z.enum(["yes", "no"]).optional().describe("Include relationship data in analysis")
  },
  (args) => {
    const includeRelationships = args.include_relationships === "yes";
    const tool_instructions = 
      args.target_type === "file" ?
        `- Use virustotal-file-analysis tool with hash="${args.target}"
   - Document detection ratios and malware classifications
   - Note sandbox behaviors and capabilities
   - Examine YARA and SIGMA rule matches` :
        `- Use virustotal-url-analysis tool with url="${args.target}"
   - Document detection ratios and categories
   - Note redirection chains and final destinations
   - Examine associated threats and behaviors`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Analyze ${args.target_type} "${args.target}" for malware and security threats:

1. Initial Analysis
   ${tool_instructions}

2. Threat Assessment
   - Evaluate detection consensus across vendors
   - Identify malware families and types
   - Document observed malicious behaviors
   - Note potential impact and risks

3. Technical Details
   - Document file/URL properties
   - Note significant timestamps
   - Record infrastructure details
   - List associated indicators

4. Recommendations
   - Suggest containment measures
   - Provide mitigation steps
   - Recommend monitoring strategies
   - List similar threats to watch

Present a comprehensive security analysis based on VirusTotal data.`
        }
      }]
    };
  }
);

// ... after malware analysis prompt ...

// Infrastructure Analysis Prompt
server.prompt(
  "infrastructure-analysis",
  "Analyze network infrastructure using combined Shodan and VirusTotal data",
  {
    target_type: z.enum(["ip", "domain"]).describe("Type of target to analyze"),
    target: z.string().describe("IP address or domain to analyze"),
    depth: z.enum(["basic", "comprehensive"]).optional().describe("Analysis depth (default: basic)"),
    include_vt_analysis: z.enum(["yes", "no"]).optional().describe("Include VirusTotal security analysis (default: yes)")
  },
  (args) => {
    const isComprehensive = args.depth === "comprehensive";
    const includeVt = args.include_vt_analysis !== "no";
    
    const vt_tool_instructions = 
      args.target_type === "ip" ?
        `- Use virustotal-ip-analysis tool with ip="${args.target}"
   - Document reputation and detection ratios
   - Note network infrastructure details
   - Examine historical security incidents` :
        `- Use virustotal-domain-analysis tool with domain="${args.target}"
   - Document reputation and categories
   - Note DNS records and WHOIS data
   - Examine historical security incidents`;
    
    const shodan_tool_instructions = 
      args.target_type === "ip" ?
        `- Use host-info tool with:
     * ip="${args.target}"
     * history=${isComprehensive}
   - Document exposed services and ports
   - Note geographical and network location
   - Examine service configurations` :
        `- Use domain-info tool with domain="${args.target}"
   - Document DNS records and subdomains
   - For each IP, use host-info for details
   - Map the domain's infrastructure`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform ${args.depth || "basic"} infrastructure analysis for ${args.target_type} "${args.target}":

1. ${includeVt ? 'VirusTotal Analysis' : 'Initial Analysis'}
   ${includeVt ? vt_tool_instructions : '- Skip VirusTotal analysis as requested'}

2. Shodan Analysis
   ${shodan_tool_instructions}

3. Infrastructure Assessment
   - Map network topology and relationships
   - Identify critical services and exposures
   - Document security posture and risks
   - Note unusual configurations or patterns
   ${includeVt ? `- Security context:
     * Infrastructure reputation
     * Historical security events
     * Known malicious activities` : ''}

4. Security Analysis
   - Evaluate overall infrastructure security
   - Identify potential vulnerabilities
   - Document security incidents and reputation
   - Note suspicious patterns or behaviors
   ${includeVt ? `- Threat intelligence:
     * Detection patterns
     * Associated threats
     * Risk indicators` : ''}

5. Recommendations
   - Suggest security improvements
   - Recommend monitoring strategies
   - Propose exposure reduction measures
   - List similar infrastructure to watch
   ${includeVt ? `- Threat mitigation:
     * Specific security controls
     * Detection strategies
     * Monitoring recommendations` : ''}

Present a comprehensive infrastructure analysis combining ${includeVt ? 'both VirusTotal and Shodan data' : 'Shodan data'}.`
        }
      }]
    };
  }
);

// ... after infrastructure analysis prompt ...

// Threat Hunting Prompt
server.prompt(
  "threat-hunting",
  "Hunt for threats across multiple data sources using combined intelligence",
  {
    indicator_type: z.enum(["ip", "domain", "url", "file"]).describe("Type of indicator to investigate"),
    indicator: z.string().describe("Indicator value to investigate"),
    include_vt_analysis: z.enum(["yes", "no"]).optional().describe("Include VirusTotal security analysis (default: yes)")
  },
  (args) => {
    const includeVt = args.include_vt_analysis !== "no";
    const vt_tool_instructions = 
      args.indicator_type === "ip" ? 
        `- Use virustotal-ip-analysis tool with ip="${args.indicator}"` :
      args.indicator_type === "domain" ?
        `- Use virustotal-domain-analysis tool with domain="${args.indicator}"` :
      args.indicator_type === "url" ?
        `- Use virustotal-url-analysis tool with url="${args.indicator}"` :
        `- Use virustotal-file-analysis tool with hash="${args.indicator}"`;
    
    const shodan_tool_instructions = 
      args.indicator_type === "ip" ?
        `- Use host-info tool with ip="${args.indicator}"
   - Use search-host to find similar systems` :
      args.indicator_type === "domain" ?
        `- Use domain-info tool with domain="${args.indicator}"
   - For each IP, use host-info for details` :
        `- Use search-host to find related infrastructure
   - Document any matching systems or services`;
    
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform threat hunting analysis for ${args.indicator_type} "${args.indicator}":

1. Initial Indicator Analysis
   ${includeVt ? vt_tool_instructions : '- Skip VirusTotal analysis as requested'}
   - Document reputation and detection data
   - Note historical security incidents
   - Examine relationships and patterns

2. Infrastructure Investigation
   ${shodan_tool_instructions}
   - Map associated infrastructure
   - Identify exposed services
   - Document security posture
   ${includeVt ? `- Security context:
     * Infrastructure reputation
     * Known security incidents
     * Associated threats` : ''}

3. Threat Pattern Analysis
   - Identify malicious behaviors
   - Map attack patterns and TTPs
   - Document threat actor tactics
   - Note similar threat indicators
   ${includeVt ? `- Threat intelligence:
     * Malware family associations
     * Attack pattern correlations
     * Related threat activities` : ''}

4. Relationship Mapping
   - Document connected infrastructure
   - Identify related malware families
   - Map associated threat actors
   - Note similar attack patterns
   ${includeVt ? `- Extended analysis:
     * Infrastructure relationships
     * Threat actor associations
     * Campaign correlations` : ''}

5. Hunting Recommendations
   - Suggest additional search patterns
   - Recommend monitoring rules
   - Propose detection strategies
   - List indicators to track
   ${includeVt ? `- Threat mitigation:
     * Specific detection rules
     * Monitoring strategies
     * Response procedures` : ''}

Present a comprehensive threat hunting report combining ${includeVt ? 'both VirusTotal and Shodan intelligence' : 'Shodan intelligence'}.`
        }
      }]
    };
  }
);

/**
 * VirusTotal YARA Rules Tool
 * Lists and retrieves crowdsourced YARA rules from VirusTotal.
 * Can be used to:
 * - List all available YARA rules
 * - Get details of a specific YARA rule
 * - Search for YARA rules by name or content
 */
server.tool(
  "virustotal-yara-rules",
  "List and retrieve YARA rules from VirusTotal",
  {
    action: z.enum(["list", "get"]).describe("Action to perform (list all rules or get a specific rule)"),
    rule_id: z.string().optional().describe("ID of the specific rule to retrieve (required for 'get' action)"),
    cursor: z.string().optional().describe("Cursor for pagination when listing rules"),
    limit: z.number().optional().describe("Number of rules to return per page (max 40)")
  },
  async ({ action, rule_id, cursor, limit }) => {
    try {
      if (action === "list") {
        // Build query parameters
        const params: Record<string, string | number> = {};
        if (cursor) params.cursor = cursor;
        if (limit) params.limit = Math.min(limit, 40); // Cap at 40 as per API docs

        const response = await virusTotalApiRequest<VirusTotalResponse<any>>(
          '/yara_rules',
          'get',
          undefined,
          params
        );

        let formattedText = "## YARA Rules List\n\n";
        
        if (response.data && Array.isArray(response.data)) {
          formattedText += "### Available Rules\n\n";
          formattedText += "| Rule Name | Author | Matches | Last Modified |\n";
          formattedText += "|-----------|---------|---------|---------------|\n";
          
          for (const rule of response.data) {
            const attrs = rule.attributes;
            const date = new Date(attrs.last_modification_date * 1000).toLocaleDateString();
            formattedText += `| ${attrs.name} | ${attrs.author || 'N/A'} | ${attrs.matches} | ${date} |\n`;
          }
          
          if (response.meta?.cursor) {
            formattedText += "\n**Next Page Cursor:** " + response.meta.cursor;
          }
        }

        return {
          content: [{
            type: "text",
            text: formattedText
          }]
        };

      } else if (action === "get" && rule_id) {
        const response = await virusTotalApiRequest<VirusTotalResponse<any>>(
          `/yara_rules/${rule_id}`
        );

        const rule = response.data.attributes;
        
        let formattedText = `## YARA Rule: ${rule.name}\n\n`;
        
        // Add metadata
        formattedText += "### Metadata\n\n";
        formattedText += `- **Author:** ${rule.author || 'N/A'}\n`;
        formattedText += `- **Created:** ${new Date(rule.creation_date * 1000).toLocaleString()}\n`;
        formattedText += `- **Last Modified:** ${new Date(rule.last_modification_date * 1000).toLocaleString()}\n`;
        formattedText += `- **Total Matches:** ${rule.matches}\n\n`;

        // Add tags if present
        if (rule.tags && rule.tags.length > 0) {
          formattedText += "### Tags\n";
          formattedText += rule.tags.map((tag: string) => `- ${tag}`).join('\n');
          formattedText += "\n\n";
        }

        // Add rule content
        formattedText += "### Rule Content\n\n";
        formattedText += "```yara\n";
        formattedText += rule.rule;
        formattedText += "\n```\n";

        // Add metadata table if present
        if (rule.meta && rule.meta.length > 0) {
          formattedText += "\n### Rule Metadata\n\n";
          formattedText += "| Key | Value |\n";
          formattedText += "|-----|-------|\n";
          rule.meta.forEach((meta: { key: string, value: string }) => {
            formattedText += `| ${meta.key} | ${meta.value} |\n`;
          });
        }

        return {
          content: [{
            type: "text",
            text: formattedText
          }]
        };

      } else {
        throw new Error("Rule ID is required for 'get' action");
      }
    } catch (error) {
      const err = error as Error;
      return {
        content: [{
          type: "text",
          text: `Error accessing YARA rules: ${err.message}`
        }],
        isError: true
      };
    }
  }
);

/**
 * Current Date Tool
 * Returns the current date in various formats.
 * Simple utility tool that's useful for timestamping operations,
 * creating log entries, or any situation where the current date is needed.
 */
server.tool(
  "current-date",
  "Get the current date in various formats",
  {
    format: z.enum(["iso", "local", "utc"]).optional().describe("Date format: iso (ISO 8601), local (local format), utc (UTC string)")
  },
  async ({ format = "iso" }) => {
    const now = new Date();
    let formattedDate;
    
    switch (format) {
      case "iso":
        formattedDate = now.toISOString();
        break;
      case "local":
        formattedDate = now.toLocaleDateString();
        break;
      case "utc":
        formattedDate = now.toUTCString();
        break;
    }
    
    return {
      content: [{
        type: "text",
        text: formattedDate
      }]
    };
  }
);

/**
 * Current Time Tool
 * Returns the current time with various formatting options.
 * Useful for timestamping, logging, and any operation
 * where precise time information is needed.
 */
server.tool(
  "current-time",
  "Get the current time in various formats",
  {
    format: z.enum(["24h", "12h", "timestamp"]).optional().describe("Time format: 24h (24-hour format), 12h (12-hour format), timestamp (Unix timestamp)"),
    include_seconds: z.boolean().optional().describe("Whether to include seconds in the output")
  },
  async ({ format = "24h", include_seconds = true }) => {
    const now = new Date();
    let formattedTime;
    
    switch (format) {
      case "24h":
        formattedTime = include_seconds 
          ? now.toLocaleTimeString([], { hour12: false })
          : now.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
        break;
      case "12h":
        formattedTime = include_seconds
          ? now.toLocaleTimeString([], { hour12: true })
          : now.toLocaleTimeString([], { hour12: true, hour: '2-digit', minute: '2-digit' });
        break;
      case "timestamp":
        formattedTime = Math.floor(now.getTime() / 1000).toString();
        break;
    }
    
    return {
      content: [{
        type: "text",
        text: formattedTime
      }]
    };
  }
);

/**
 * Main function to start the MCP server
 * Initializes the server with stdio transport for command-line interaction
 * This follows the MCP specification for server initialization and connection handling
 */
async function main() {
  console.error("🚀 Starting ADEO CTI MCP Server...");
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error("✅ ADEO CTI MCP Server connected and ready");
}

main().catch(error => {
  console.error("Fatal error:", error);
  process.exit(1);
});