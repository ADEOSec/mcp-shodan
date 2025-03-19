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

// Resource Implementations
server.resource(
  "host-info",
  "shodan://host/{ip}",
  async (request) => {
    const ip = request.toString().split("/").pop() || "";
    try {
      const data = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${ip}`, {
        history: "false",
        minify: "false"
      });
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch host information: ${error}`);
    }
  }
);

server.resource(
  "domain-info",
  "shodan://domain/{domain}",
  async (request) => {
    const domain = request.toString().split("/").pop() || "";
    try {
      const data = await shodanApiRequest<ShodanDomainInfo>("/dns/domain/" + domain, {});
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch domain information: ${error}`);
    }
  }
);

// Prompt Implementations
server.prompt(
  "security-assessment",
  {
    target: z.string().describe("IP address or domain to analyze"),
    depth: z.string().optional().describe("Analysis depth (basic, standard, deep)")
  },
  async (args) => {
    const depth = args.depth || "standard";
    const target = args.target;
    
    try {
      // Fetch host information
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${target}`, {
        history: depth === "deep" ? "true" : "false"
      });
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Analyze the security posture of ${target} with the following information:\n\n${JSON.stringify(hostInfo, null, 2)}`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate security assessment: ${error}`);
    }
  }
);

server.prompt(
  "vuln-analysis",
  {
    target: z.string().describe("IP address to analyze"),
    timeframe: z.string().optional().describe("History timeframe to consider")
  },
  async (args) => {
    const target = args.target;
    
    try {
      // Fetch host information with vulnerabilities
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${target}`, {
        history: "true"
      });
      
      // Extract vulnerability information
      const vulns = hostInfo.data?.flatMap(service => service.vulns || []) || [];
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Analyze the vulnerabilities found for ${target}:\n\n${JSON.stringify(vulns, null, 2)}`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate vulnerability analysis: ${error}`);
    }
  }
);

// Enhanced Vulnerability Assessment Prompt
server.prompt(
  "enhanced-vuln-assessment",
  "Perform detailed vulnerability assessment with severity filtering",
  {
    target: z.string().describe("IP address or domain to analyze"),
    severityThreshold: z.string().optional().describe("Minimum severity level to include (low, medium, high, critical)"),
    priorityLevel: z.string().optional().describe("Priority level for remediation (low, medium, high)")
  },
  async (args) => {
    const target = args.target;
    const severityThreshold = args.severityThreshold || "low";
    
    try {
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${target}`, {
        history: "true"
      });
      
      // Extract and filter vulnerabilities based on severity
      const vulns = hostInfo.data?.flatMap(service => service.vulns || [])
        .filter(vuln => shouldIncludeVulnerability(vuln, severityThreshold)) || [];
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Perform a detailed vulnerability assessment for ${target} with severity threshold ${severityThreshold}:\n\n` +
                  `Vulnerabilities found: ${JSON.stringify(vulns, null, 2)}\n\n` +
                  `Please analyze these vulnerabilities and provide:\n` +
                  `1. Severity ranking\n` +
                  `2. Potential impact analysis\n` +
                  `3. Recommended remediation steps\n` +
                  `4. Prioritization based on business impact`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate enhanced vulnerability assessment: ${error}`);
    }
  }
);

// Network Topology Analysis Prompt
server.prompt(
  "network-topology",
  "Analyze network topology and suggest visualizations",
  {
    target: z.string().describe("IP range or domain to analyze"),
    scanType: z.string().optional().describe("Type of scan (basic, detailed, comprehensive)"),
    compareWithPrevious: z.string().optional().describe("Compare with previous scan results (true/false)")
  },
  async (args) => {
    const target = args.target;
    const scanType = args.scanType || "basic";
    const compareWithPrevious = args.compareWithPrevious === "true";
    
    try {
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${target}`, {
        history: compareWithPrevious ? "true" : "false"
      });
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Analyze the network topology for ${target}:\n\n` +
                  `Host Information: ${JSON.stringify(hostInfo, null, 2)}\n\n` +
                  `Please provide:\n` +
                  `1. Network structure visualization suggestions\n` +
                  `2. Identified entry points\n` +
                  `3. Network segmentation analysis\n` +
                  `4. Security recommendations based on topology`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate network topology analysis: ${error}`);
    }
  }
);

// IoT Device Discovery Prompt
server.prompt(
  "iot-discovery",
  "Discover and analyze IoT devices in the network",
  {
    target: z.string().describe("Network range to scan for IoT devices"),
    deviceType: z.string().optional().describe("Specific type of IoT device to look for"),
    manufacturer: z.string().optional().describe("Specific manufacturer to filter by"),
    protocol: z.string().optional().describe("Specific protocol to search for")
  },
  async (args) => {
    try {
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${args.target}`, {
        history: "false"
      });
      
      // Filter for IoT-related services and protocols
      const iotServices = hostInfo.data?.filter(service => 
        isIoTService(service, args.deviceType, args.manufacturer, args.protocol)
      ) || [];
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Analyze IoT devices found in network ${args.target}:\n\n` +
                  `Discovered devices: ${JSON.stringify(iotServices, null, 2)}\n\n` +
                  `Please provide:\n` +
                  `1. Device categorization\n` +
                  `2. Security assessment for each device type\n` +
                  `3. Common vulnerabilities for identified devices\n` +
                  `4. Security best practices for discovered device types`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate IoT device discovery report: ${error}`);
    }
  }
);

// Security Posture Evaluation Prompt
server.prompt(
  "security-posture",
  "Evaluate security posture against compliance frameworks",
  {
    target: z.string().describe("Target network or domain to evaluate"),
    complianceFramework: z.string().optional().describe("Compliance framework to evaluate against (NIST, ISO, etc.)"),
    includeRemediation: z.string().optional().describe("Include detailed remediation steps (true/false)")
  },
  async (args) => {
    try {
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${args.target}`, {
        history: "true"
      });
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Evaluate security posture for ${args.target} against ${args.complianceFramework || 'general security best practices'}:\n\n` +
                  `Host Information: ${JSON.stringify(hostInfo, null, 2)}\n\n` +
                  `Please provide:\n` +
                  `1. Overall security rating\n` +
                  `2. Compliance status\n` +
                  `3. Critical findings\n` +
                  `4. Remediation roadmap\n` +
                  `5. Prioritized action items`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate security posture evaluation: ${error}`);
    }
  }
);

// Threat Intelligence Integration Prompt
server.prompt(
  "threat-intel",
  "Analyze threat intelligence and provide risk assessment",
  {
    target: z.string().describe("IP or domain to analyze"),
    threatSource: z.string().optional().describe("Specific threat intelligence source to use"),
    riskLevel: z.string().optional().describe("Minimum risk level to include (low, medium, high)")
  },
  async (args) => {
    try {
      const hostInfo = await shodanApiRequest<ShodanHostInfo>(`/shodan/host/${args.target}`, {
        history: "true"
      });
      
      return {
        messages: [{
          role: "user",
          content: {
            type: "text",
            text: `Analyze threat intelligence for ${args.target}:\n\n` +
                  `Host Information: ${JSON.stringify(hostInfo, null, 2)}\n\n` +
                  `Please provide:\n` +
                  `1. Known threat actors associated with observed patterns\n` +
                  `2. Risk assessment based on current threat landscape\n` +
                  `3. Potential attack vectors\n` +
                  `4. Recommended security controls\n` +
                  `5. Mitigation strategies`
          }
        }]
      };
    } catch (error) {
      throw new Error(`Failed to generate threat intelligence analysis: ${error}`);
    }
  }
);

// Helper function to determine if vulnerability meets severity threshold
function shouldIncludeVulnerability(vuln: any, threshold: string): boolean {
  const severityLevels: { [key: string]: number } = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
  };
  
  const vulnSeverity = (vuln.severity?.toLowerCase() || 'low') as string;
  return (severityLevels[vulnSeverity] || 1) >= (severityLevels[threshold] || 1);
}

// Helper function to identify IoT services
function isIoTService(service: any, deviceType?: string, manufacturer?: string, protocol?: string): boolean {
  // Common IoT ports and protocols
  const iotPorts = [80, 443, 8080, 1883, 8883, 5683, 5684]; // HTTP(S), MQTT, CoAP
  const iotProtocols = ['mqtt', 'coap', 'modbus', 'bacnet'];
  
  // Check if service matches specified filters
  if (deviceType && !service.product?.toLowerCase().includes(deviceType.toLowerCase())) {
    return false;
  }
  if (manufacturer && !service.product?.toLowerCase().includes(manufacturer.toLowerCase())) {
    return false;
  }
  if (protocol && !service.transport?.toLowerCase().includes(protocol.toLowerCase())) {
    return false;
  }
  
  // Check if service is likely an IoT device
  return iotPorts.includes(service.port) || 
         iotProtocols.includes(service.transport?.toLowerCase()) ||
         (service.tags || []).some((tag: string) => tag.toLowerCase().includes('iot'));
}

// Search Results Resource
server.resource(
  "search-results",
  "shodan://search/{query}",
  async (request) => {
    const query = request.toString().split("/").pop() || "";
    try {
      const data = await shodanApiRequest<ShodanSearchResult>("/shodan/host/search", {
        query: decodeURIComponent(query)
      });
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch search results: ${error}`);
    }
  }
);

// Network Alerts Resource
server.resource(
  "alerts",
  "shodan://alerts/{id}",
  async (request) => {
    const id = request.toString().split("/").pop();
    try {
      const data = id === "all" 
        ? await shodanApiRequest<any>("/shodan/alert/info", {})
        : await shodanApiRequest<any>(`/shodan/alert/${id}/info`, {});
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch alert information: ${error}`);
    }
  }
);

// Scan Status Resource
server.resource(
  "scan-status",
  "shodan://scan/{id}",
  async (request) => {
    const id = request.toString().split("/").pop() || "";
    try {
      const data = await shodanApiRequest<any>(`/shodan/scan/${id}`, {});
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch scan status: ${error}`);
    }
  }
);

// Query Directory Resource
server.resource(
  "saved-queries",
  "shodan://queries/{type}",
  async (request) => {
    const type = request.toString().split("/").pop() || "list";
    try {
      let endpoint = "/shodan/query";
      if (type === "tags") {
        endpoint = "/shodan/query/tags";
      }
      
      const data = await shodanApiRequest<any>(endpoint, {});
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch saved queries: ${error}`);
    }
  }
);

// API Status Resource
server.resource(
  "api-status",
  "shodan://api/status",
  async (request) => {
    try {
      const data = await shodanApiRequest<any>("/api-info", {});
      
      return {
        contents: [{
          uri: request.toString(),
          mimeType: "application/json",
          text: JSON.stringify(data, null, 2)
        }]
      };
    } catch (error) {
      throw new Error(`Failed to fetch API status: ${error}`);
    }
  }
);

/**
 * CVE Lookup Tool
 * Get detailed information about a specific CVE
 */
server.tool(
  "cve-lookup",
  "Get detailed information about a CVE",
  {
    cve: z.string().describe("CVE ID to look up (e.g., CVE-2021-44228)")
  },
  async ({ cve }) => {
    try {
      const data = await cvedbApiRequest<CVEDBVulnerability>(`/api/v1/cve/${cve}`);
      
      let formattedText = `## CVE Information: ${cve}\n\n`;
      formattedText += `**Summary:** ${data.summary}\n\n`;
      
      formattedText += "### Severity Scores\n";
      formattedText += `- **CVSS Score:** ${data.cvss} (v${data.cvss_version})\n`;
      if (data.cvss_v2) formattedText += `- **CVSS v2:** ${data.cvss_v2}\n`;
      if (data.cvss_v3) formattedText += `- **CVSS v3:** ${data.cvss_v3}\n`;
      formattedText += `- **EPSS Score:** ${data.epss}\n`;
      formattedText += `- **EPSS Ranking:** ${data.ranking_epss}\n`;
      formattedText += `- **Known Exploited Vulnerability:** ${data.kev ? "Yes" : "No"}\n\n`;
      
      if (data.ransomware_campaign) {
        formattedText += `### ⚠️ Ransomware Campaign\n${data.ransomware_campaign}\n\n`;
      }
      
      formattedText += `### Proposed Action\n${data.propose_action}\n\n`;
      
      if (data.cpes.length > 0) {
        formattedText += "### Affected Products (CPE)\n";
        data.cpes.forEach((cpe: string) => {
          formattedText += `- \`${cpe}\`\n`;
        });
        formattedText += "\n";
      }
      
      if (data.references.length > 0) {
        formattedText += "### References\n";
        data.references.forEach((ref: string) => {
          formattedText += `- ${ref}\n`;
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
            text: `Error looking up CVE: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * CPE Vulnerability Search Tool
 * Search for vulnerabilities affecting a specific CPE
 */
server.tool(
  "cpe-vuln-search",
  "Search for vulnerabilities by CPE",
  {
    cpe: z.string().describe("CPE 2.3 string to search for"),
    minCvss: z.number().optional().describe("Minimum CVSS score (0-10)"),
    maxResults: z.number().optional().describe("Maximum number of results to return")
  },
  async ({ cpe, minCvss = 0, maxResults = 50 }) => {
    try {
      const params: Record<string, string | number> = {
        cpe,
        limit: maxResults
      };
      
      if (minCvss > 0) {
        params.cvss = minCvss;
      }
      
      const data = await cvedbApiRequest<CVEDBVulnerabilityList>("/api/v1/cpe/vulnerabilities", params);
      
      let formattedText = `## Vulnerabilities for ${cpe}\n\n`;
      formattedText += `**Total Vulnerabilities Found:** ${data.total}\n\n`;
      
      if (data.matches.length > 0) {
        // Sort by CVSS score descending
        const sortedVulns = data.matches.sort((a: CVEDBVulnerability, b: CVEDBVulnerability) => b.cvss - a.cvss);
        
        sortedVulns.forEach((vuln: CVEDBVulnerability, index: number) => {
          formattedText += `### ${index + 1}. ${vuln.cve}\n`;
          formattedText += `**CVSS Score:** ${vuln.cvss} | **EPSS:** ${vuln.epss}\n`;
          formattedText += `**Summary:** ${vuln.summary}\n`;
          if (vuln.kev) formattedText += `⚠️ **Known Exploited Vulnerability**\n`;
          if (vuln.ransomware_campaign) formattedText += `🚨 **Associated with Ransomware**\n`;
          formattedText += "\n";
        });
      } else {
        formattedText += "No vulnerabilities found matching the criteria.\n";
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
            text: `Error searching vulnerabilities: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Latest Vulnerabilities Tool
 * Get the most recently published vulnerabilities
 */
server.tool(
  "latest-vulns",
  "Get latest published vulnerabilities",
  {
    days: z.number().optional().describe("Number of days to look back"),
    minEpss: z.number().optional().describe("Minimum EPSS score (0-1)"),
    kevOnly: z.boolean().optional().describe("Show only Known Exploited Vulnerabilities")
  },
  async ({ days = 7, minEpss = 0, kevOnly = false }) => {
    try {
      const params: Record<string, string | number> = {
        days,
        limit: 100
      };
      
      if (minEpss > 0) {
        params.epss = minEpss;
      }
      
      if (kevOnly) {
        params.kev = "true";
      }
      
      const data = await cvedbApiRequest<CVEDBVulnerabilityList>("/api/v1/vulns/latest", params);
      
      let formattedText = "## Latest Vulnerabilities\n\n";
      formattedText += `**Time Period:** Last ${days} days\n`;
      formattedText += `**Total Found:** ${data.total}\n\n`;
      
      if (data.matches.length > 0) {
        // Sort by EPSS score descending
        const sortedVulns = data.matches.sort((a: CVEDBVulnerability, b: CVEDBVulnerability) => b.epss - a.epss);
        
        sortedVulns.forEach((vuln: CVEDBVulnerability, index: number) => {
          formattedText += `### ${index + 1}. ${vuln.cve}\n`;
          formattedText += `**Published:** ${vuln.published_time}\n`;
          formattedText += `**EPSS Score:** ${vuln.epss} | **CVSS:** ${vuln.cvss}\n`;
          formattedText += `**Summary:** ${vuln.summary}\n`;
          if (vuln.kev) formattedText += `⚠️ **Known Exploited Vulnerability**\n`;
          if (vuln.ransomware_campaign) formattedText += `🚨 **Associated with Ransomware**\n`;
          formattedText += "\n";
        });
      } else {
        formattedText += "No vulnerabilities found matching the criteria.\n";
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
            text: `Error fetching latest vulnerabilities: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * Product Vulnerability Analysis Tool
 * Analyze vulnerabilities for a specific product
 */
server.tool(
  "product-vuln-analysis",
  "Analyze vulnerabilities for a product",
  {
    vendor: z.string().describe("Vendor name"),
    product: z.string().describe("Product name"),
    version: z.string().optional().describe("Product version"),
    timeframe: z.number().optional().describe("Days to look back")
  },
  async ({ vendor, product, version, timeframe = 365 }) => {
    try {
      const params: Record<string, string | number> = {
        vendor,
        product,
        days: timeframe
      };
      
      if (version) {
        params.version = version;
      }
      
      const data = await cvedbApiRequest<CVEDBVulnerabilityList>("/api/v1/product/vulnerabilities", params);
      
      let formattedText = `## Vulnerability Analysis: ${vendor} ${product}`;
      if (version) formattedText += ` ${version}`;
      formattedText += "\n\n";
      
      formattedText += `**Time Period:** Last ${timeframe} days\n`;
      formattedText += `**Total Vulnerabilities:** ${data.total}\n\n`;
      
      if (data.matches.length > 0) {
        // Calculate statistics
        const criticalVulns = data.matches.filter((v: CVEDBVulnerability) => v.cvss >= 9.0);
        const highVulns = data.matches.filter((v: CVEDBVulnerability) => v.cvss >= 7.0 && v.cvss < 9.0);
        const kevVulns = data.matches.filter((v: CVEDBVulnerability) => v.kev);
        const ransomwareVulns = data.matches.filter((v: CVEDBVulnerability) => v.ransomware_campaign);
        
        formattedText += "### Summary Statistics\n";
        formattedText += `- Critical Vulnerabilities (CVSS ≥ 9.0): ${criticalVulns.length}\n`;
        formattedText += `- High Vulnerabilities (CVSS 7.0-8.9): ${highVulns.length}\n`;
        formattedText += `- Known Exploited Vulnerabilities: ${kevVulns.length}\n`;
        formattedText += `- Ransomware-Related: ${ransomwareVulns.length}\n\n`;
        
        formattedText += "### Critical Vulnerabilities\n";
        criticalVulns.forEach((vuln: CVEDBVulnerability) => {
          formattedText += `- ${vuln.cve} (CVSS: ${vuln.cvss})\n`;
          formattedText += `  ${vuln.summary}\n\n`;
        });
        
        if (kevVulns.length > 0) {
          formattedText += "### Known Exploited Vulnerabilities\n";
          kevVulns.forEach((vuln: CVEDBVulnerability) => {
            formattedText += `- ${vuln.cve} (CVSS: ${vuln.cvss})\n`;
            formattedText += `  ${vuln.summary}\n\n`;
          });
        }
      } else {
        formattedText += "No vulnerabilities found matching the criteria.\n";
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
            text: `Error analyzing product vulnerabilities: ${err.message}`
          }
        ],
        isError: true
      };
    }
  }
);

/**
 * CPE Dictionary Search Tool
 * Search for CPE 2.3 entries by product name
 */
server.tool(
  "cpe-search",
  "Search for CPE 2.3 entries",
  {
    query: z.string().describe("Product name to search for"),
    maxResults: z.number().optional().describe("Maximum number of results to return")
  },
  async ({ query, maxResults = 50 }) => {
    try {
      const data = await cvedbApiRequest<CPEDictionaryList>("/api/v1/cpe/search", {
        q: query,
        limit: maxResults
      });
      
      let formattedText = `## CPE Search Results: "${query}"\n\n`;
      formattedText += `**Total Matches:** ${data.total}\n\n`;
      
      if (data.matches.length > 0) {
        // Group by vendor
        const vendorGroups = data.matches.reduce((groups: { [key: string]: CPEDictionaryEntry[] }, entry: CPEDictionaryEntry) => {
          const vendor = entry.vendor;
          if (!groups[vendor]) {
            groups[vendor] = [];
          }
          groups[vendor].push(entry);
          return groups;
        }, {});
        
        for (const [vendor, entries] of Object.entries(vendorGroups)) {
          formattedText += `### ${vendor}\n`;
          (entries as CPEDictionaryEntry[]).forEach((entry: CPEDictionaryEntry) => {
            formattedText += `- **Product:** ${entry.product}\n`;
            formattedText += `  **Version:** ${entry.version}\n`;
            formattedText += `  **CPE:** \`${entry.cpe23}\`\n\n`;
          });
        }
      } else {
        formattedText += "No CPE entries found matching the search query.\n";
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
            text: `Error searching CPE dictionary: ${err.message}`
          }
        ],
        isError: true
      };
    }
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