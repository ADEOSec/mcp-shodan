/**
 * Type definitions for Shodan API responses
 * These interfaces define the structure of data returned by various Shodan API endpoints
 * Based on the official Shodan REST API specification
 */

/**
 * Represents detailed information about a service running on a host
 * This is returned as part of the host information lookup
 */
export interface ShodanHostService {
  /** The port number the service is running on */
  port: number;
  
  /** The transport protocol (tcp/udp) */
  transport: string;
  
  /** Name of the software/product running the service (if detected) */
  product?: string;
  
  /** Version of the software/product (if detected) */
  version?: string;
  
  /** Common Platform Enumeration (CPE) identifiers for the service */
  cpe?: string[];
  
  /** Raw banner data or response received from the service */
  data?: string;
}

/**
 * Comprehensive host information returned by Shodan
 * Contains everything Shodan knows about a specific IP address
 */
export interface ShodanHostInfo {
  /** String representation of the IP address */
  ip_str: string;
  
  /** City where the host is located (if known) */
  city?: string;
  
  /** Full country name where the host is located */
  country_name?: string;
  
  /** Organization (usually ISP or company) that owns the IP address */
  org?: string;
  
  /** Internet Service Provider (ISP) that owns the IP address */
  isp?: string;
  
  /** Autonomous System Number (ASN) the IP belongs to */
  asn?: string;
  
  /** List of hostnames that resolve to this IP address */
  hostnames?: string[];
  
  /** List of open ports discovered on the host */
  ports?: number[];
  
  /** List of tags associated with the host (e.g., "cloud", "database") */
  tags?: string[];
  
  /** Timestamp of when Shodan last scanned this host */
  last_update?: string;
  
  /** Detailed information about each service discovered on the host */
  data?: ShodanHostService[];
}

/**
 * DNS Resolution Response
 * Maps hostnames to their resolved IP addresses
 * Used by the DNS lookup endpoint
 */
export interface ShodanDNSResolution {
  /** Key is hostname, value is resolved IP address */
  [hostname: string]: string;
}

/**
 * Reverse DNS Response
 * Maps IP addresses to their associated hostnames
 * Used by the reverse DNS lookup endpoint
 */
export interface ShodanReverseDNS {
  /** Key is IP address, value is array of associated hostnames */
  [ip: string]: string[];
}

/**
 * Domain Information Response
 * Contains comprehensive DNS information about a domain
 * Including subdomains, DNS records, and metadata
 */
export interface ShodanDomainInfo {
  /** Tags associated with the domain (e.g., "ipv6", "mail") */
  tags?: string[];
  
  /** Array of DNS records found for the domain */
  data?: Array<{
    /** Subdomain part of the DNS record */
    subdomain: string;
    
    /** DNS record type (A, AAAA, MX, etc.) */
    type: string;
    
    /** Value of the DNS record */
    value: string;
    
    /** When this DNS record was last observed */
    last_seen?: string;
  }>;
  
  /** List of all discovered subdomains */
  subdomains?: string[];
  
  /** Indicates if there are more results available */
  more?: boolean;
} 