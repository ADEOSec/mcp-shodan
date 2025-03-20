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

  /** Vulnerabilities found in this service */
  vulns?: ShodanVulnerability[];
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

// Search Methods Types
export interface ShodanSearchResult {
  matches: ShodanSearchMatch[];
  facets?: Record<string, Array<{count: number, value: string}>>;
  total: number;
}

export interface ShodanSearchMatch {
  product?: string;
  hash?: number;
  ip: number;
  ip_str: string;
  port: number;
  hostnames: string[];
  org?: string;
  isp?: string;
  location: {
    city?: string;
    region_code?: string;
    area_code?: number;
    longitude: number;
    latitude: number;
    country_code: string;
    country_name: string;
  };
  timestamp: string;
  domains?: string[];
  data?: string;
  asn?: string;
  transport?: string;
  os?: string;
  _shodan: {
    crawler: string;
    ptr: boolean;
    id: string;
    module: string;
    options: Record<string, any>;
  };
}

export interface ShodanSearchTokens {
  attributes: {
    ports?: number[];
    [key: string]: any;
  };
  errors: string[];
  string: string;
  filters: string[];
}

export interface ShodanSearchFilters {
  filters: string[];
}

export interface ShodanSearchFacets {
  facets: string[];
}

// On-Demand Scanning Types
export interface ShodanScanResult {
  id: string;
  count: number;
  credits_left: number;
}

export interface ShodanScanStatus {
  id: string;
  count: number;
  status: 'SUBMITTING' | 'QUEUE' | 'PROCESSING' | 'DONE';
  created: string;
}

export interface ShodanScanList {
  matches: Array<{
    id: string;
    status: 'SUBMITTING' | 'QUEUE' | 'PROCESSING' | 'DONE';
    created: string;
    status_check: string;
    credits_left: number;
    size: number;
  }>;
  total: number;
}

export interface ShodanProtocols {
  [protocol: string]: string;
}

export interface ShodanPorts {
  ports: number[];
}

// Network Alerts Types
export interface ShodanAlert {
  id: string;
  name: string;
  created: string;
  expires: string | null;
  filters: {
    ip: string[];
    port: number[];
    [key: string]: any;
  };
  size: number;
  credits: number;
}

export interface ShodanAlertInfo extends ShodanAlert {
  matches: ShodanSearchMatch[];
}

export interface ShodanAlertList {
  alerts: ShodanAlert[];
}

export interface ShodanTrigger {
  name: string;
  description: string;
  rule: string;
}

export interface ShodanTriggerList {
  triggers: ShodanTrigger[];
}

// Directory Methods Types
export interface ShodanQuery {
  id: string;
  name: string;
  query: string;
  created: string;
  description?: string;
  votes: number;
  timestamp: string;
  tags: string[];
  sharing: number;
}

export interface ShodanQueryList {
  total: number;
  matches: ShodanQuery[];
}

export interface ShodanQueryTags {
  total: number;
  tags: Array<{
    count: number;
    value: string;
  }>;
}

// Account Methods Types
export interface ShodanAccount {
  member: boolean;
  credits: number;
  display_name: string | null;
  created: string;
}

export interface ShodanApiStatus {
  scan_credits: number;
  usage_limits: {
    scan_credits: number;
    query_credits: number;
    monitored_ips: number;
  };
  plan: string;
  https: boolean;
  unlocked: boolean;
}

export interface ShodanBillingProfile {
  name: string;
  address: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
  card_last4: string;
  card_expiration: string;
}

// Utility Methods Types
export interface ShodanHTTPHeaders {
  [header: string]: string;
}

export interface ShodanMyIP {
  ip: string;
}

/**
 * Represents a vulnerability found in a service
 */
export interface ShodanVulnerability {
  /** CVE ID of the vulnerability */
  id: string;
  
  /** CVSS score of the vulnerability */
  cvss: number;
  
  /** Summary description of the vulnerability */
  summary: string;
  
  /** References to more information about the vulnerability */
  references?: string[];
}

// Add types for MCP Resources
export interface ResourceUri {
  uri: string;
}

export interface ResourceContent {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;
}

// Add types for MCP Prompts
export interface PromptArguments {
  target?: string;
  depth?: string;
  timeframe?: string;
  // Network Topology Analysis
  scanType?: string;
  compareWithPrevious?: boolean;
  // IoT Device Discovery
  deviceType?: string;
  manufacturer?: string;
  protocol?: string;
  // Security Posture Evaluation
  complianceFramework?: string;
  includeRemediation?: boolean;
  // Threat Intelligence
  threatSource?: string;
  riskLevel?: string;
  // Vulnerability Assessment
  severityThreshold?: string;
  priorityLevel?: string;
}

export interface PromptMessage {
  role: "user" | "assistant";
  content: {
    type: "text";
    text: string;
  };
}

export interface CVEDBVulnerability {
    cve: string;
    summary: string;
    cvss: number;
    cvss_version: number;
    cvss_v2?: number;
    cvss_v3?: number;
    epss: number;
    ranking_epss: number;
    kev: boolean;
    propose_action: string;
    ransomware_campaign: string;
    references: string[];
    published_time: string;
    cpes: string[];
}

export interface CVEDBVulnerabilityList {
    total: number;
    matches: CVEDBVulnerability[];
}

export interface CPEDictionaryEntry {
    cpe23: string;
    vendor: string;
    product: string;
    version: string;
    update?: string;
    edition?: string;
}

export interface CPEDictionaryList {
    total: number;
    matches: CPEDictionaryEntry[];
}

// VirusTotal API Types

/**
 * Base VirusTotal API response interface
 */
export interface VirusTotalResponse<T> {
  data: T;
  meta?: Record<string, any>;
}

/**
 * Common analysis statistics structure
 */
export interface AnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
}

/**
 * VirusTotal URL Analysis Interface
 */
export interface VirusTotalUrlAnalysis {
  id: string;
  type: string;
  attributes: {
    date: number;
    status: string;
    url: string;
    last_analysis_date?: number;
    last_analysis_stats?: AnalysisStats;
    last_analysis_results?: Record<string, {
      category: string;
      engine_name: string;
      method: string;
      result: string | null;
    }>;
    reputation?: number;
    categories?: Record<string, string>;
    title?: string;
    last_http_response_code?: number;
    last_http_response_content_length?: number;
    times_submitted?: number;
    tags?: string[];
    total_votes?: {
      harmless: number;
      malicious: number;
    };
    last_final_url?: string;
    html_meta?: Record<string, string[]>;
    redirection_chain?: string[];
  };
  links?: {
    self: string;
  };
  relationships?: Record<string, {
    data: any;
    meta?: {
      count: number;
    };
  }>;
}

/**
 * VirusTotal File Analysis Interface
 */
export interface VirusTotalFileAnalysis {
  id: string;
  type: string;
  attributes: {
    md5: string;
    sha1: string;
    sha256: string;
    size: number;
    last_analysis_date?: number;
    last_analysis_stats?: AnalysisStats;
    last_analysis_results?: Record<string, {
      category: string;
      engine_name: string;
      method: string;
      result: string | null;
    }>;
    reputation?: number;
    meaningful_name?: string;
    type_description?: string;
    tags?: string[];
    total_votes?: {
      harmless: number;
      malicious: number;
    };
    times_submitted?: number;
    last_submission_date?: number;
    first_submission_date?: number;
    sandbox_verdicts?: Record<string, {
      category: string;
      confidence: number;
      sandbox_name: string;
      malware_classification?: string[];
    }>;
    capabilities_tags?: string[];
    crowdsourced_yara_results?: Array<{
      description: string;
      rule_name: string;
      source: string;
    }>;
    sigma_analysis_stats?: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  links?: {
    self: string;
  };
  relationships?: Record<string, {
    data: any;
    meta?: {
      count: number;
    };
  }>;
}

/**
 * VirusTotal IP Analysis Interface
 */
export interface VirusTotalIpAnalysis {
  id: string;
  type: string;
  attributes: {
    as_owner?: string;
    asn?: number;
    country?: string;
    network?: string;
    regional_internet_registry?: string;
    last_analysis_date?: number;
    last_analysis_stats?: AnalysisStats;
    last_analysis_results?: Record<string, {
      category: string;
      engine_name: string;
      method: string;
      result: string | null;
    }>;
    reputation?: number;
    tags?: string[];
    total_votes?: {
      harmless: number;
      malicious: number;
    };
    continent?: string;
    jarm?: string;
    last_https_certificate?: {
      issuer: {
        C?: string;
        CN?: string;
        O?: string;
      };
      subject: {
        CN?: string;
      };
      validity: {
        not_after: string;
        not_before: string;
      };
    };
    whois?: string;
    whois_date?: number;
  };
  links?: {
    self: string;
  };
  relationships?: Record<string, {
    data: any;
    meta?: {
      count: number;
    };
  }>;
}

/**
 * VirusTotal Domain Analysis Interface
 */
export interface VirusTotalDomainAnalysis {
  id: string;
  type: string;
  attributes: {
    creation_date?: number;
    last_update_date?: number;
    last_analysis_date?: number;
    last_analysis_stats?: AnalysisStats;
    last_analysis_results?: Record<string, {
      category: string;
      engine_name: string;
      method: string;
      result: string | null;
    }>;
    categories?: Record<string, string>;
    reputation?: number;
    registrar?: string;
    whois?: string;
    whois_date?: number;
    last_dns_records?: Array<{
      type: string;
      value: string;
      ttl: number;
    }>;
    tags?: string[];
    total_votes?: {
      harmless: number;
      malicious: number;
    };
    popularity_ranks?: Record<string, { rank: number }>;
  };
  links?: {
    self: string;
  };
  relationships?: Record<string, {
    data: any;
    meta?: {
      count: number;
    };
  }>;
} 