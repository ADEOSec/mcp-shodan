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
import { ShodanHostInfo, ShodanDNSResolution, ShodanReverseDNS, ShodanDomainInfo } from "./types.js";

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

// Create an MCP server instance with metadata
const server = new McpServer({
  name: "Shodan Server",
  version: "1.0.0"
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
async function shodanApiRequest<T>(endpoint: string, params: Record<string, string | number> = {}): Promise<T> {
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
    const response = await fetch(url);
    
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