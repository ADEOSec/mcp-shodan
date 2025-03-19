/**
 * Shodan MCP Server Implementation
 * This file implements a Model Context Protocol (MCP) server that provides access to Shodan's API functionality.
 * The server exposes various tools for host information lookup, DNS operations, and network scanning capabilities.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import * as dotenv from "dotenv";
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
  CPEDictionaryList
} from "./types.js";

// Load environment variables (SHODAN_API_KEY)
dotenv.config();

/**
 * Parse command line arguments to get the Shodan API key
 * @returns {Object} Object containing the API key
 * @throws {Error} If API key is not provided
 */
function parseArgs() {
  const args = process.argv.slice(2);
  let apiKey = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--api-key' && i + 1 < args.length) {
      apiKey = args[i + 1];
      break;
    }
  }

  if (!apiKey) {
    console.error("❌ --api-key parameter is required");
    console.error("Usage: npm start -- --api-key YOUR_API_KEY");
    process.exit(1);
  }

  return { apiKey };
}

const { apiKey } = parseArgs();
const API_BASE_URL = "https://api.shodan.io";

// CVEDB API base URL
const CVEDB_API_BASE_URL = "https://cvedb.shodan.io";

// Create an MCP server instance with metadata
const server = new McpServer({
  name: "Shodan Server",
  version: "1.0.0",
  capabilities: {
    resources: {},  // Enable resources capability
    tools: {},      // Keep existing tools capability
    prompts: {}     // Enable prompts capability
  }
});

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
  queryParams.append('key', apiKey);

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
  queryParams.append('key', apiKey);

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
 * Host Information Tool
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
    try {
      const data = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${ip}`, {
        history: history ? "true" : "false",
        minify: minify ? "true" : "false"
      });
      
      // Format the response to highlight important information
      let formattedText = `## Host Information for ${ip} (${data.ip_str})\n\n`;
      
      if (data.country_name) {
        formattedText += `**Location**: ${data.city || 'Unknown City'}, ${data.country_name}\n`;
      }
      
      if (data.org) {
        formattedText += `**Organization**: ${data.org}\n`;
      }
      
      if (data.isp) {
        formattedText += `**ISP**: ${data.isp}\n`;
      }
      
      if (data.asn) {
        formattedText += `**ASN**: ${data.asn}\n`;
      }
      
      if (data.hostnames && data.hostnames.length > 0) {
        formattedText += `**Hostnames**: ${data.hostnames.join(', ')}\n`;
      }
      
      if (data.ports && data.ports.length > 0) {
        formattedText += `**Open Ports**: ${data.ports.join(', ')}\n`;
      }
      
      if (data.tags && data.tags.length > 0) {
        formattedText += `**Tags**: ${data.tags.join(', ')}\n`;
      }
      
      if (data.last_update) {
        formattedText += `**Last Updated**: ${data.last_update}\n`;
      }
      
      // Include detailed service information if available and not minified
      if (data.data && data.data.length > 0 && !minify) {
        formattedText += `\n## Services (${data.data.length})\n\n`;
        
        data.data.forEach((service, index) => {
          formattedText += `### Service ${index + 1}: Port ${service.port} (${service.transport})\n`;
          
          if (service.product) {
            formattedText += `**Product**: ${service.product}`;
            if (service.version) {
              formattedText += ` ${service.version}`;
            }
            formattedText += '\n';
          }
          
          if (service.cpe && service.cpe.length > 0) {
            formattedText += `**CPE**: ${service.cpe.join(', ')}\n`;
          }
          
          if (service.data) {
            formattedText += `\n\`\`\`\n${service.data.slice(0, 500)}${service.data.length > 500 ? '...' : ''}\n\`\`\`\n\n`;
          }
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
            text: `Error fetching host information: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * DNS Lookup Tool
 * Resolves hostnames to IP addresses using Shodan's DNS resolution service.
 * This is useful for:
 * - Mapping domain names to IP addresses
 * - Verifying DNS records
 * - Preparing for host lookups
 * No query credits are consumed for this operation
 */
server.tool(
  "dns-lookup",
  "Resolve hostnames to IP addresses",
  {
    hostnames: z.string().describe("Comma-separated list of hostnames to resolve (e.g., 'google.com,facebook.com')")
  },
  async ({ hostnames }) => {
    try {
      const data = await shodanApiRequest<ShodanDNSResolution>("/dns/resolve", { hostnames });
      
      // Format the response as a table
      let formattedText = "## DNS Lookup Results\n\n";
      formattedText += "| Hostname | IP Address |\n";
      formattedText += "| -------- | ---------- |\n";
      
      for (const [hostname, ip] of Object.entries(data)) {
        formattedText += `| ${hostname} | ${ip} |\n`;
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
            text: `Error performing DNS lookup: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Reverse DNS Tool
 * Performs reverse DNS lookups for IP addresses using Shodan's service.
 * This tool is useful for:
 * - Identifying domains associated with IPs
 * - Network mapping and reconnaissance
 * - Validating PTR records
 * No query credits are consumed for this operation
 */
server.tool(
  "reverse-dns",
  "Look up hostnames for IP addresses",
  {
    ips: z.string().describe("Comma-separated list of IP addresses (e.g., '8.8.8.8,1.1.1.1')")
  },
  async ({ ips }) => {
    try {
      const data = await shodanApiRequest<ShodanReverseDNS>("/dns/reverse", { ips });
      
      // Format the response as a table
      let formattedText = "## Reverse DNS Lookup Results\n\n";
      formattedText += "| IP Address | Hostnames |\n";
      formattedText += "| ---------- | --------- |\n";
      
      for (const [ip, hostnames] of Object.entries(data)) {
        formattedText += `| ${ip} | ${hostnames.join(', ') || 'No hostnames found'} |\n`;
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
            text: `Error performing reverse DNS lookup: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Domain Information Tool
 * Retrieves comprehensive DNS information about a domain including:
 * - Subdomains
 * - DNS records (A, AAAA, MX, etc.)
 * - Historical data
 * Uses 1 query credit per lookup
 */
server.tool(
  "domain-info",
  "Get DNS entries and subdomains for a domain",
  {
    domain: z.string().describe("Domain name to look up (e.g., 'example.com')")
  },
  async ({ domain }) => {
    try {
      const data = await shodanApiRequest<ShodanDomainInfo>(`/dns/domain/${domain}`);
      
      // Format the response in a readable way
      let formattedText = `## Domain Information for ${domain}\n\n`;
      
      if (data.tags && data.tags.length > 0) {
        formattedText += `**Tags**: ${data.tags.join(', ')}\n\n`;
      }
      
      // Display DNS records
      if (data.data && data.data.length > 0) {
        formattedText += "### DNS Records\n\n";
        formattedText += "| Type | Value | Last Seen |\n";
        formattedText += "| ---- | ----- | --------- |\n";
        
        data.data.forEach((record) => {
          formattedText += `| ${record.type} | ${record.value} | ${record.last_seen || 'N/A'} |\n`;
        });
        formattedText += "\n";
      }
      
      // Display subdomains in a grid layout
      if (data.subdomains && data.subdomains.length > 0) {
        formattedText += "### Subdomains\n\n";
        
        // Split subdomains into chunks of 5 for better readability
        const chunks: string[][] = [];
        for (let i = 0; i < data.subdomains.length; i += 5) {
          chunks.push(data.subdomains.slice(i, i + 5));
        }
        
        chunks.forEach(chunk => {
          formattedText += chunk.map(subdomain => `- ${subdomain}`).join("\n") + "\n";
        });
        
        formattedText += "\n";
      }
      
      if (data.more) {
        formattedText += "_Note: More results are available_\n";
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
            text: `Error fetching domain information: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Hello Tool
 * Simple test tool to verify the MCP server is working correctly.
 * This tool doesn't interact with the Shodan API and is useful for:
 * - Testing server connectivity
 * - Verifying MCP protocol implementation
 * - Basic health checking
 */
server.tool(
  "hello",
  "Test if the Shodan MCP server is working",
  {},
  async () => {
    return {
      content: [
        {
          type: "text",
          text: "👋 Hello from Shodan MCP Server! Server is running correctly."
        }
      ]
    };
  }
);

/**
 * Search Shodan Tool
 * Search Shodan using the same query syntax as the website and use facets to get summary information.
 * This method may use API query credits depending on usage:
 * 1. If the search query contains a filter
 * 2. If accessing results past the 1st page
 */
server.tool(
  "search-host",
  "Search Shodan",
  {
    query: z.string().describe("Shodan search query (e.g. 'apache country:DE')"),
    facets: z.string().optional().describe("Comma-separated list of properties to get summary information"),
    page: z.number().optional().describe("Page number for results (1 credit per page after 1st)"),
  },
  async ({ query, facets, page = 1 }) => {
    try {
      const params: Record<string, string | number> = {
        query,
        page
      };

      if (facets) {
        params.facets = facets;
      }

      const data = await shodanApiRequest<ShodanSearchResult>("/shodan/host/search", params);
      
      // Format the response in a readable way
      let formattedText = `## Search Results for "${query}"\n\n`;
      formattedText += `**Total Results:** ${data.total}\n`;
      formattedText += `**Page:** ${page}\n\n`;

      if (data.facets) {
        formattedText += "### Summary Information\n\n";
        for (const [facetName, facetValues] of Object.entries(data.facets)) {
          formattedText += `**${facetName}:**\n`;
          facetValues.forEach(({ value, count }) => {
            formattedText += `- ${value}: ${count}\n`;
          });
        }
        formattedText += "\n";
      }

      if (data.matches && data.matches.length > 0) {
        formattedText += "### Matches\n\n";
        data.matches.forEach((match, index) => {
          formattedText += `#### Match ${index + 1}\n`;
          formattedText += `- **IP:** ${match.ip_str}\n`;
          formattedText += `- **Port:** ${match.port}\n`;
          if (match.org) formattedText += `- **Organization:** ${match.org}\n`;
          if (match.hostnames.length > 0) formattedText += `- **Hostnames:** ${match.hostnames.join(", ")}\n`;
          if (match.location.country_name) formattedText += `- **Location:** ${match.location.city || "Unknown City"}, ${match.location.country_name}\n`;
          if (match.product) formattedText += `- **Product:** ${match.product}\n`;
          if (match.os) formattedText += `- **OS:** ${match.os}\n`;
          formattedText += `- **Last Updated:** ${match.timestamp}\n`;
          if (match.data) {
            formattedText += "\n```\n";
            formattedText += match.data.slice(0, 500);
            if (match.data.length > 500) formattedText += "...\n";
            formattedText += "```\n";
          }
          formattedText += "\n";
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
            text: `Error searching Shodan: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Search Host Count Tool
 * Returns only the total number of results and facet information without consuming query credits
 */
server.tool(
  "search-host-count",
  "Search Shodan without Results",
  {
    query: z.string().describe("Shodan search query (e.g. 'apache country:DE')"),
    facets: z.string().optional().describe("Comma-separated list of properties to get summary information"),
  },
  async ({ query, facets }) => {
    try {
      const params: Record<string, string> = { query };
      if (facets) {
        params.facets = facets;
      }

      const data = await shodanApiRequest<ShodanSearchResult>("/shodan/host/count", params);
      
      let formattedText = `## Search Count Results for "${query}"\n\n`;
      formattedText += `**Total Results:** ${data.total}\n\n`;

      if (data.facets) {
        formattedText += "### Summary Information\n\n";
        for (const [facetName, facetValues] of Object.entries(data.facets)) {
          formattedText += `**${facetName}:**\n`;
          facetValues.forEach(({ value, count }) => {
            formattedText += `- ${value}: ${count}\n`;
          });
        }
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
            text: `Error getting search count: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Search Facets Tool
 * Returns a list of available facets that can be used to get summary information
 */
server.tool(
  "list-search-facets",
  "List all search facets",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanSearchFacets>("/shodan/host/search/facets");
      
      let formattedText = "## Available Search Facets\n\n";
      formattedText += "The following facets can be used to get summary information in search results:\n\n";
      
      data.facets.forEach(facet => {
        formattedText += `- ${facet}\n`;
      });

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
            text: `Error getting search facets: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Search Filters Tool
 * Returns a list of available search filters
 */
server.tool(
  "list-search-filters",
  "List all filters that can be used when searching",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanSearchFilters>("/shodan/host/search/filters");
      
      let formattedText = "## Available Search Filters\n\n";
      formattedText += "The following filters can be used in search queries:\n\n";
      
      data.filters.forEach(filter => {
        formattedText += `- ${filter}\n`;
      });

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
            text: `Error getting search filters: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Search Query Tokens Tool
 * Break down a search query into tokens for analysis
 */
server.tool(
  "search-tokens",
  "Break the search query into tokens",
  {
    query: z.string().describe("Shodan search query to analyze"),
  },
  async ({ query }) => {
    try {
      const data = await shodanApiRequest<ShodanSearchTokens>("/shodan/host/search/tokens", { query });
      
      let formattedText = `## Search Query Analysis for "${query}"\n\n`;
      
      formattedText += "### Search String\n";
      formattedText += `${data.string}\n\n`;
      
      if (data.filters.length > 0) {
        formattedText += "### Filters Used\n";
        data.filters.forEach(filter => {
          formattedText += `- ${filter}\n`;
        });
        formattedText += "\n";
      }

      if (Object.keys(data.attributes).length > 0) {
        formattedText += "### Attributes\n";
        for (const [key, value] of Object.entries(data.attributes)) {
          formattedText += `- **${key}:** ${JSON.stringify(value)}\n`;
        }
        formattedText += "\n";
      }

      if (data.errors.length > 0) {
        formattedText += "### Errors\n";
        data.errors.forEach(error => {
          formattedText += `- ${error}\n`;
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
            text: `Error analyzing search query: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List All Ports Tool
 * Returns a list of port numbers that Shodan is currently scanning on the Internet
 */
server.tool(
  "list-ports",
  "List all ports that Shodan is crawling on the Internet",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanPorts>("/shodan/ports");
      
      let formattedText = "## Shodan Scanning Ports\n\n";
      formattedText += "The following ports are being actively scanned by Shodan:\n\n";
      
      // Group ports by common services
      const commonPorts: { [key: string]: number[] } = {
        "Web Services": [80, 443, 8080, 8443],
        "Email": [25, 110, 143, 465, 587, 993, 995],
        "SSH/Telnet": [22, 23],
        "Database": [1433, 1521, 3306, 5432, 6379, 27017],
        "Other": []
      };

      data.ports.forEach(port => {
        let categorized = false;
        for (const [category, ports] of Object.entries(commonPorts)) {
          if (ports.includes(port)) {
            categorized = true;
            break;
          }
        }
        if (!categorized) {
          commonPorts["Other"].push(port);
        }
      });

      for (const [category, ports] of Object.entries(commonPorts)) {
        const categoryPorts = ports.filter(port => data.ports.includes(port));
        if (categoryPorts.length > 0) {
          formattedText += `### ${category}\n`;
          formattedText += categoryPorts.sort((a, b) => a - b).join(", ") + "\n\n";
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
            text: `Error getting ports list: ${err.message}`
          }
        ],
        isError: true
      };
    }
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
 * List Scans Tool
 * Returns a list of all scans that have been submitted
 */
server.tool(
  "list-scans",
  "Get list of all submitted scans",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanScanList>("/shodan/scans");
      
      let formattedText = "## Your Scans\n\n";
      formattedText += `**Total Scans:** ${data.total}\n\n`;

      if (data.matches.length > 0) {
        formattedText += "### Recent Scans\n\n";
        data.matches.forEach((scan, index) => {
          formattedText += `#### Scan ${index + 1}\n`;
          formattedText += `- **ID:** ${scan.id}\n`;
          formattedText += `- **Status:** ${scan.status}\n`;
          formattedText += `- **Created:** ${scan.created}\n`;
          formattedText += `- **Last Status Check:** ${scan.status_check}\n`;
          formattedText += `- **Size:** ${scan.size} IP(s)\n`;
          formattedText += `- **Credits Left:** ${scan.credits_left}\n\n`;
        });
      } else {
        formattedText += "No scans found.\n";
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
            text: `Error listing scans: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Alert Triggers Tool
 * Returns a list of available network alert triggers
 */
server.tool(
  "list-triggers",
  "List available triggers for network alerts",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanTriggerList>("/shodan/alert/triggers");
      
      let formattedText = "## Available Alert Triggers\n\n";
      formattedText += "The following triggers can be used when creating network alerts:\n\n";
      
      data.triggers.forEach(trigger => {
        formattedText += `### ${trigger.name}\n`;
        formattedText += `${trigger.description}\n`;
        formattedText += `**Rule:** \`${trigger.rule}\`\n\n`;
      });

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
            text: `Error getting alert triggers: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Create Alert Tool
 * Creates a network alert for monitoring
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
    try {
      const params: Record<string, any> = {
        name,
        filters: JSON.stringify(filters)
      };

      if (expires) {
        params.expires = expires;
      }

      const data = await shodanApiRequest<ShodanAlert>("/shodan/alert", params, "POST");
      
      let formattedText = "## Alert Created Successfully\n\n";
      formattedText += `**Alert ID:** ${data.id}\n`;
      formattedText += `**Name:** ${data.name}\n`;
      formattedText += `**Created:** ${data.created}\n`;
      if (data.expires) {
        formattedText += `**Expires:** ${data.expires}\n`;
      }
      formattedText += `**Size:** ${data.size} IP(s)\n`;
      formattedText += `**Credits:** ${data.credits}\n\n`;
      
      formattedText += "### Filters\n";
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
            text: `Error creating alert: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get Alert Info Tool
 * Get the details of a specific network alert
 */
server.tool(
  "get-alert-info",
  "Get information about a specific alert",
  {
    id: z.string().describe("Alert ID to get information about"),
  },
  async ({ id }) => {
    try {
      const data = await shodanApiRequest<ShodanAlertInfo>(`/shodan/alert/${id}/info`);
      
      let formattedText = "## Alert Information\n\n";
      formattedText += `**Alert ID:** ${data.id}\n`;
      formattedText += `**Name:** ${data.name}\n`;
      formattedText += `**Created:** ${data.created}\n`;
      if (data.expires) {
        formattedText += `**Expires:** ${data.expires}\n`;
      }
      formattedText += `**Size:** ${data.size} IP(s)\n`;
      formattedText += `**Credits:** ${data.credits}\n\n`;
      
      formattedText += "### Filters\n";
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

      if (data.matches && data.matches.length > 0) {
        formattedText += "\n### Recent Matches\n\n";
        data.matches.forEach((match, index) => {
          formattedText += `#### Match ${index + 1}\n`;
          formattedText += `- **IP:** ${match.ip_str}\n`;
          formattedText += `- **Port:** ${match.port}\n`;
          if (match.org) formattedText += `- **Organization:** ${match.org}\n`;
          if (match.location.country_name) formattedText += `- **Location:** ${match.location.city || "Unknown City"}, ${match.location.country_name}\n`;
          formattedText += `- **Last Updated:** ${match.timestamp}\n\n`;
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
            text: `Error getting alert info: ${err.message}`
          }
        ],
        isError: true
      };
    }
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
 * List Alerts Tool
 * Get a list of all network alerts
 */
server.tool(
  "list-alerts",
  "List all active alerts",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanAlertList>("/shodan/alert/info");
      
      let formattedText = "## Active Network Alerts\n\n";
      
      if (data.alerts.length === 0) {
        formattedText += "No active alerts found.\n";
      } else {
        data.alerts.forEach((alert, index) => {
          formattedText += `### ${index + 1}. ${alert.name}\n`;
          formattedText += `**ID:** ${alert.id}\n`;
          formattedText += `**Created:** ${alert.created}\n`;
          if (alert.expires) {
            formattedText += `**Expires:** ${alert.expires}\n`;
          }
          formattedText += `**Size:** ${alert.size} IP(s)\n`;
          formattedText += `**Credits:** ${alert.credits}\n\n`;
          
          formattedText += "#### Filters\n";
          if (alert.filters.ip && alert.filters.ip.length > 0) {
            formattedText += "**IP Addresses:**\n";
            alert.filters.ip.forEach(ip => {
              formattedText += `- ${ip}\n`;
            });
          }
          if (alert.filters.port && alert.filters.port.length > 0) {
            formattedText += "**Ports:**\n";
            alert.filters.port.forEach(port => {
              formattedText += `- ${port}\n`;
            });
          }
          formattedText += "\n";
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
            text: `Error listing alerts: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Saved Queries Tool
 * Returns a list of search queries that users have saved in Shodan
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
    try {
      const data = await shodanApiRequest<ShodanQueryList>("/shodan/query", {
        page,
        sort,
        order
      });
      
      let formattedText = "## Saved Search Queries\n\n";
      formattedText += `**Total Queries:** ${data.total}\n`;
      formattedText += `**Page:** ${page}\n\n`;

      if (data.matches.length === 0) {
        formattedText += "No saved queries found.\n";
      } else {
        data.matches.forEach((query, index) => {
          formattedText += `### ${index + 1}. ${query.name}\n`;
          formattedText += `**ID:** ${query.id}\n`;
          formattedText += `**Query:** \`${query.query}\`\n`;
          if (query.description) {
            formattedText += `**Description:** ${query.description}\n`;
          }
          formattedText += `**Created:** ${query.created}\n`;
          formattedText += `**Votes:** ${query.votes}\n`;
          if (query.tags.length > 0) {
            formattedText += `**Tags:** ${query.tags.join(", ")}\n`;
          }
          formattedText += "\n";
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
            text: `Error listing queries: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Search Queries Tool
 * Search through saved search queries
 */
server.tool(
  "search-queries",
  "Search through saved queries",
  {
    query: z.string().describe("Search term to find queries"),
    page: z.number().optional().describe("Page number of results (default: 1)"),
  },
  async ({ query, page = 1 }) => {
    try {
      const data = await shodanApiRequest<ShodanQueryList>("/shodan/query/search", {
        query,
        page
      });
      
      let formattedText = `## Search Results for "${query}"\n\n`;
      formattedText += `**Total Matches:** ${data.total}\n`;
      formattedText += `**Page:** ${page}\n\n`;

      if (data.matches.length === 0) {
        formattedText += "No matching queries found.\n";
      } else {
        data.matches.forEach((query, index) => {
          formattedText += `### ${index + 1}. ${query.name}\n`;
          formattedText += `**ID:** ${query.id}\n`;
          formattedText += `**Query:** \`${query.query}\`\n`;
          if (query.description) {
            formattedText += `**Description:** ${query.description}\n`;
          }
          formattedText += `**Created:** ${query.created}\n`;
          formattedText += `**Votes:** ${query.votes}\n`;
          if (query.tags.length > 0) {
            formattedText += `**Tags:** ${query.tags.join(", ")}\n`;
          }
          formattedText += "\n";
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
            text: `Error searching queries: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * List Query Tags Tool
 * Returns a list of popular tags for the saved search queries
 */
server.tool(
  "list-query-tags",
  "List popular tags for saved queries",
  {
    size: z.number().optional().describe("Number of tags to return (default: 10)"),
  },
  async ({ size = 10 }) => {
    try {
      const data = await shodanApiRequest<ShodanQueryTags>("/shodan/query/tags", { size });
      
      let formattedText = "## Popular Query Tags\n\n";
      formattedText += `**Total Tags:** ${data.total}\n\n`;

      if (data.tags.length === 0) {
        formattedText += "No tags found.\n";
      } else {
        formattedText += "| Tag | Usage Count |\n";
        formattedText += "| --- | ----------- |\n";
        
        data.tags.forEach(tag => {
          formattedText += `| ${tag.value} | ${tag.count} |\n`;
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
            text: `Error listing query tags: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Get Account Profile Tool
 * Returns information about the Shodan account linked to the API key
 */
server.tool(
  "get-profile",
  "Get account profile information",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanAccount>("/account/profile");
      
      let formattedText = "## Account Profile\n\n";
      formattedText += `**Display Name:** ${data.display_name || 'Not set'}\n`;
      formattedText += `**Member:** ${data.member ? 'Yes' : 'No'}\n`;
      formattedText += `**Credits:** ${data.credits}\n`;
      formattedText += `**Created:** ${data.created}\n`;

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
            text: `Error getting account profile: ${err.message}`
          }
        ],
        isError: true
      };
    }
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
 * Get My IP Tool
 * Get your current IP address as seen from the Internet
 */
server.tool(
  "get-my-ip",
  "View your current IP address",
  {},
  async () => {
    try {
      const data = await shodanApiRequest<ShodanMyIP>("/tools/myip");
      
      let formattedText = "## Your IP Address\n\n";
      formattedText += `Your current IP address is: **${data.ip}**\n`;
      formattedText += "\nThis is how your IP appears to external services on the Internet.\n";

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
            text: `Error getting IP address: ${err.message}`
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
    severity_threshold: z.enum(["all", "medium", "high", "critical"]).optional().describe("Minimum severity threshold")
  },
  (args) => {
    const severity_map = {
      "all": "0",
      "medium": "4.0",
      "high": "7.0",
      "critical": "9.0"
    };
    
    const min_cvss = severity_map[args.severity_threshold || "all"];
    
    const initial_instructions = 
      args.target_type === "host" ?
        `- Use host-info tool with:
   * ip="${args.target}"
   * history=true
   - Examine the banners and vulnerability information in the results` :
      args.target_type === "domain" ?
        `- Use domain-info tool with domain="${args.target}"
   - For each IP discovered, use host-info to check for vulnerabilities
   - Pay special attention to subdomains with unusual services` :
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

3. Risk Contextualization
   - Prioritize vulnerabilities by severity
   - Highlight internet-exposed vulnerable services
   - Note common exploitation vectors
   - Consider scope of potential impact

4. Remediation Guidance
   - Suggest version upgrades where applicable
   - Recommend configuration changes
   - Advise on exposure reduction options
   - Propose monitoring and alerting measures

Present findings based solely on information available through Shodan's vulnerability data.`
        }
      }]
    };
  }
);

// Internet Search Prompt
server.prompt(
  "internet-search",
  "Search for specific internet-connected systems or services",
  {
    query: z.string().describe("Shodan search query to execute"),
    facets: z.string().optional().describe("Optional facets for statistical breakdown (comma-separated)"),
    page_limit: z.string().optional().describe("Maximum number of results pages to retrieve")
  },
  (args) => {
    const facet_param = args.facets ? `\n     * facets="${args.facets}"` : '';
    const pages = args.page_limit ? Math.min(parseInt(args.page_limit) || 1, 10) : 1;
      
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `Perform a comprehensive Shodan search for "${args.query}":

1. Initial Search
   - Use search-host-count tool with:
     * query="${args.query}"${facet_param}
   - Use search-host tool with:
     * query="${args.query}"${facet_param}
     * page=1${pages > 1 ? '\n   - Repeat for pages 2 through ' + pages + ' as needed' : ''}

2. Results Analysis
   - Summarize total results count and distribution
   - Identify patterns in returned data
   - Analyze geographical and organizational distribution
   - Document common services, ports, and technologies

3. Notable Findings
   - Highlight unusual or interesting systems
   - Note potential security implications
   - Identify outdated or vulnerable services
   - Document unexpected exposure patterns

4. Suggested Follow-up
   - Recommend more specific searches if applicable
   - Suggest host-info for notable results
   - Recommend potential monitoring targets
   - Outline next analytical steps

Present results in a clear report with statistics and key findings from the Shodan search.`
        }
      }]
    };
  }
);

// Network Security Monitoring Prompt
server.prompt(
  "security-monitoring",
  "Setup and manage network security monitoring alerts",
  {
    action: z.enum(["create", "review", "modify", "delete"]).describe("Alert management action"),
    target_type: z.enum(["ip", "service", "vulnerability", "custom"]).optional().describe("Type of target to monitor"),
    target: z.string().optional().describe("Target to monitor (IP, service name, or vulnerability)"),
    alert_id: z.string().optional().describe("Alert ID for modification or review")
  },
  (args) => {
    const filter_examples = {
      "ip": `{"ip": ["${args.target}"]}`,
      "service": `{"port": [80, 443], "keyword": "${args.target}"}`,
      "vulnerability": `{"vuln": ["${args.target}"]}`,
      "custom": "{}"
    };
    
    const filters = args.target_type ? filter_examples[args.target_type] : "{}";
    
    const action_instructions = 
      args.action === "create" ?
        `- Use list-triggers tool to view available triggers
   - Use create-alert tool with:
     * name="Monitor ${args.target_type || ''}: ${args.target || 'Custom Alert'}"
     * filters=${filters}
   - Document the alert ID for future reference` :
      args.action === "review" ?
        `- Use list-alerts tool to view all configured alerts
   - Use get-alert-info tool with id="${args.alert_id}" to get detailed information
   - Examine the alert configuration in detail` :
      args.action === "modify" ?
        `- Use get-alert-info tool with id="${args.alert_id}" to get current configuration
   - Use edit-alert tool with:
     * id="${args.alert_id}"
     * filters=${filters}
   - Verify the updated configuration` :
      `- Use delete-alert tool with id="${args.alert_id}"
   - Confirm the alert has been removed`;
      
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `${args.action.charAt(0).toUpperCase() + args.action.slice(1)} security monitoring alert for ${args.target_type ? args.target_type + ' "' + args.target + '"' : 'alert ID "' + args.alert_id + '"'}:

1. Alert Management
   ${action_instructions}

2. Alert Configuration Analysis
   - Review the IP ranges or systems being monitored
   - Examine the triggers that are configured
   - Check notification settings and recipients
   - Verify alert scope and coverage

3. Monitoring Strategy
   - Analyze what changes will trigger notifications
   - Assess how the alert complements other monitoring
   - Determine if the filters are appropriately specific
   - Evaluate alert effectiveness for security visibility

4. Optimization Suggestions
   - Recommend adjustments to filter criteria
   - Suggest additional triggers if appropriate
   - Provide tips for reducing false positives
   - Propose complementary alerts if needed

Present a comprehensive report on the alert configuration and management.`
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
    include_history: z.enum(["yes", "no"]).optional().describe("Include historical information if available")
  },
  (args) => {
    const lookup_instructions =
      args.target_type === "domain" ?
        `- Use domain-info tool with domain="${args.target}"
   - Document all subdomains and DNS records` :
      args.target_type === "ip" ?
        `- Use reverse-dns tool with ips="${args.target}"
   - Examine all hostnames associated with the IP` :
        `- Use dns-lookup tool with hostnames="${args.target}"
   - Check the resolved IP addresses`;

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

3. Infrastructure Assessment
   - Identify hosting providers and networks
   - Map geographical distribution
   - Document organization information
   - Note autonomous system numbers (ASNs)

4. Security Observations
   - Flag unusual DNS configurations
   - Identify potential DNS-based vulnerabilities
   - Note signs of DNS misconfigurations
   - Highlight suspicious patterns if present

Present findings in a comprehensive DNS intelligence report based on Shodan data.`
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
    custom_query: z.string().optional().describe("Custom query for the 'custom' service type")
  },
  (args) => {
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

2. Exposure Analysis
   - Document total number of exposed services
   - Map geographical distribution
   - Identify top organizations exposing these services
   - Note common product types and versions

3. Configuration Assessment
   - Identify default or weak configurations
   - Note authentication mechanisms
   - Document unusual port assignments
   - Highlight risky service combinations

4. Security Implications
   - Identify outdated or vulnerable versions
   - Note systems with known vulnerabilities
   - Document common misconfigurations
   - Highlight particularly sensitive exposures

Present findings in a detailed service exposure report based on Shodan data.`
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

/**
 * Main function to start the MCP server
 * Initializes the server with stdio transport for command-line interaction
 * This follows the MCP specification for server initialization and connection handling
 */
async function main() {
  console.error("🚀 Starting Shodan MCP Server...");
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error("✅ Shodan MCP Server connected and ready");
}

main().catch(error => {
  console.error("Fatal error:", error);
  process.exit(1);
});