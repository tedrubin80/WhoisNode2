// FILE LOCATION: /utils/blacklist-checker.js
// FILE NAME: blacklist-checker.js
// PURPOSE: Comprehensive Email and IP Blacklist Checker for WHOIS Intelligence
// DESCRIPTION: Checks emails and IPs against multiple blacklist databases and APIs
// VERSION: 2.0.0
// USAGE: Import and use in main server for blacklist analysis

const axios = require('axios');
const dns = require('dns').promises;

// ===== CONFIGURATION =====
const BLACKLIST_CONFIG = {
  // Rate limits per minute
  RATE_LIMITS: {
    virustotal: 4,     // Free tier: 500/day, 4/min
    abuseipdb: 1000,   // Free tier: 1000/day
    spamhaus: 100,     // Rate limited
    barracuda: 50      // Rate limited
  },
  
  // Cache TTL in seconds
  CACHE_TTL: {
    positive: 86400,   // 24 hours for positive hits
    negative: 3600,    // 1 hour for clean results
    error: 300         // 5 minutes for errors
  },
  
  // Timeouts in milliseconds
  TIMEOUTS: {
    api: 10000,        // 10 seconds
    dns: 5000          // 5 seconds
  }
};

// ===== PRIVACY PROTECTION EMAIL DATABASES =====
const PRIVACY_EMAIL_PATTERNS = {
  // Major privacy protection services
  whoisguard: [
    /@whoisguard\.com$/i,
    /@namecheap\.com$/i,
    /whoisguard.*@/i
  ],
  
  domainsbyproxy: [
    /@domainsbyproxy\.com$/i,
    /@domainprotection\.net$/i,
    /privacy.*@.*godaddy/i
  ],
  
  perfectprivacy: [
    /@perfectprivacy\.com$/i,
    /@privateid\.com$/i
  ],
  
  networksolutions: [
    /@networksolutions\.com$/i,
    /@privacyprotect\.com$/i
  ],
  
  tucows: [
    /@tucowsdomains\.com$/i,
    /@hover\.com$/i,
    /privacy.*@.*tucows/i
  ],
  
  enom: [
    /@enomprivacy\.com$/i,
    /@enom\.com$/i
  ],
  
  generic_patterns: [
    /privacy.*@/i,
    /whois.*@/i,
    /protected.*@/i,
    /private.*@/i,
    /proxy.*@/i,
    /guard.*@/i,
    /masked.*@/i,
    /hidden.*@/i,
    /redacted.*@/i,
    /protection.*@/i
  ]
};

// Known privacy protection email domains
const PRIVACY_EMAIL_DOMAINS = new Set([
  'whoisguard.com',
  'domainsbyproxy.com',
  'domainprotection.net',
  'perfectprivacy.com',
  'privateid.com',
  'networksolutions.com',
  'privacyprotect.com',
  'tucowsdomains.com',
  'enomprivacy.com',
  'contactprivacy.com',
  'domainprivacy.com',
  'whoisprotection.cc',
  'privacyprotected.net',
  'registrarprotection.com',
  'domainprotected.org',
  'registrantprotection.org'
]);

// ===== DNS BLACKLIST SERVERS =====
const DNS_BLACKLISTS = {
  // Spam/Email blacklists
  email: [
    'zen.spamhaus.org',           // Spamhaus combined list
    'bl.spamcop.net',             // SpamCop
    'dnsbl.sorbs.net',            // SORBS
    'b.barracudacentral.org',     // Barracuda
    'dnsbl-1.uceprotect.net',     // UCE Protect Level 1
    'psbl.surriel.com',           // Passive Spam Block List
    'rbl.interserver.net',        // InterServer RBL
    'spam.dnsbl.anonmails.de'     // Anonymous mails
  ],
  
  // Malware/Phishing blacklists
  malware: [
    'phishing.rbl.msrbl.net',     // Microsoft RBL
    'uribl.com',                  // URIBL
    'multi.surbl.org',            // SURBL
    'rhsbl.ahbl.org',             // AHBL
    'dbl.spamhaus.org',           // Spamhaus Domain Block List
    'multi.uribl.com'             // URIBL Multi
  ],
  
  // Botnet/Malicious IPs
  botnet: [
    'cbl.abuseat.org',            // Composite Blocking List
    'exploit.rbl.msrbl.net',      // Microsoft Exploit RBL
    'virus.rbl.msrbl.net',        // Microsoft Virus RBL
    'rbl.efnetrbl.org'            // EFnet RBL
  ]
};

// ===== RATE LIMITING =====
class RateLimiter {
  constructor() {
    this.requests = new Map();
  }
  
  canMakeRequest(service) {
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const limit = BLACKLIST_CONFIG.RATE_LIMITS[service] || 10;
    
    if (!this.requests.has(service)) {
      this.requests.set(service, []);
    }
    
    const serviceRequests = this.requests.get(service);
    
    // Remove old requests outside the window
    const recentRequests = serviceRequests.filter(time => now - time < windowMs);
    this.requests.set(service, recentRequests);
    
    if (recentRequests.length >= limit) {
      return false;
    }
    
    recentRequests.push(now);
    return true;
  }
}

const rateLimiter = new RateLimiter();

// ===== MAIN BLACKLIST CHECKER CLASS =====
class BlacklistChecker {
  constructor(cache = null) {
    this.cache = cache;
  }
  
  async checkEmailAndIPs(emails, ips) {
    const results = {
      timestamp: new Date().toISOString(),
      emails: {},
      ips: {},
      summary: {
        totalEmails: emails.length,
        totalIPs: ips.length,
        blacklistedEmails: 0,
        blacklistedIPs: 0,
        privacyEmails: 0,
        suspiciousEmails: 0,
        maliciousIPs: 0,
        overallRisk: 'low'
      }
    };
    
    // Check emails
    for (const email of emails) {
      try {
        results.emails[email] = await this.checkEmail(email);
        
        if (results.emails[email].isBlacklisted) {
          results.summary.blacklistedEmails++;
        }
        if (results.emails[email].isPrivacyProtection) {
          results.summary.privacyEmails++;
        }
        if (results.emails[email].isSuspicious) {
          results.summary.suspiciousEmails++;
        }
      } catch (error) {
        results.emails[email] = {
          error: error.message,
          checked: false
        };
      }
    }
    
    // Check IPs
    for (const ip of ips) {
      try {
        results.ips[ip] = await this.checkIP(ip);
        
        if (results.ips[ip].isBlacklisted) {
          results.summary.blacklistedIPs++;
        }
        if (results.ips[ip].isMalicious) {
          results.summary.maliciousIPs++;
        }
      } catch (error) {
        results.ips[ip] = {
          error: error.message,
          checked: false
        };
      }
    }
    
    // Calculate overall risk
    results.summary.overallRisk = this.calculateOverallRisk(results.summary);
    
    return results;
  }
  
  async checkEmail(email) {
    const cacheKey = `blacklist:email:${email}`;
    
    // Check cache first
    if (this.cache) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return { ...cached, fromCache: true };
      }
    }
    
    const result = {
      email,
      checked: true,
      timestamp: new Date().toISOString(),
      isBlacklisted: false,
      isPrivacyProtection: false,
      isSuspicious: false,
      sources: [],
      details: {
        privacyService: null,
        blacklistReasons: [],
        riskScore: 0,
        confidence: 'low'
      }
    };
    
    // 1. Check for privacy protection patterns
    const privacyCheck = this.checkPrivacyProtectionEmail(email);
    if (privacyCheck.isPrivacy) {
      result.isPrivacyProtection = true;
      result.details.privacyService = privacyCheck.service;
      result.details.riskScore += 15;
      result.sources.push('privacy_patterns');
    }
    
    // 2. Check domain against email blacklists
    const domain = email.split('@')[1];
    if (domain) {
      const domainCheck = await this.checkDomainDNSBlacklists(domain, 'email');
      if (domainCheck.isBlacklisted) {
        result.isBlacklisted = true;
        result.details.blacklistReasons.push(...domainCheck.reasons);
        result.details.riskScore += 30;
        result.sources.push(...domainCheck.sources);
      }
    }
    
    // 3. Check for suspicious patterns
    const suspiciousCheck = this.checkSuspiciousEmailPatterns(email);
    if (suspiciousCheck.isSuspicious) {
      result.isSuspicious = true;
      result.details.blacklistReasons.push(...suspiciousCheck.reasons);
      result.details.riskScore += suspiciousCheck.score;
      result.sources.push('pattern_analysis');
    }
    
    // 4. API checks (rate limited)
    try {
      const apiChecks = await this.performEmailAPIChecks(email);
      if (apiChecks.length > 0) {
        result.details.blacklistReasons.push(...apiChecks);
        result.sources.push('api_checks');
      }
    } catch (error) {
      result.details.apiError = error.message;
    }
    
    // Calculate final assessment
    result.details.confidence = this.calculateConfidence(result.sources.length, result.details.riskScore);
    
    // Cache result
    if (this.cache) {
      const ttl = result.isBlacklisted ? 
        BLACKLIST_CONFIG.CACHE_TTL.positive : 
        BLACKLIST_CONFIG.CACHE_TTL.negative;
      this.cache.set(cacheKey, result, ttl);
    }
    
    return result;
  }
  
  async checkIP(ip) {
    const cacheKey = `blacklist:ip:${ip}`;
    
    // Check cache first
    if (this.cache) {
      const cached = this.cache.get(cacheKey);
      if (cached) {
        return { ...cached, fromCache: true };
      }
    }
    
    const result = {
      ip,
      checked: true,
      timestamp: new Date().toISOString(),
      isBlacklisted: false,
      isMalicious: false,
      isSuspicious: false,
      sources: [],
      details: {
        blacklistReasons: [],
        categories: [],
        riskScore: 0,
        confidence: 'low',
        geoLocation: null
      }
    };
    
    // 1. DNS blacklist checks
    const dnsChecks = await this.performDNSBlacklistChecks(ip);
    if (dnsChecks.isBlacklisted) {
      result.isBlacklisted = true;
      result.details.blacklistReasons.push(...dnsChecks.reasons);
      result.details.categories.push(...dnsChecks.categories);
      result.details.riskScore += dnsChecks.score;
      result.sources.push(...dnsChecks.sources);
    }
    
    // 2. API checks (rate limited)
    try {
      const apiChecks = await this.performIPAPIChecks(ip);
      if (apiChecks.isMalicious) {
        result.isMalicious = true;
        result.details.blacklistReasons.push(...apiChecks.reasons);
        result.details.riskScore += apiChecks.score;
        result.sources.push(...apiChecks.sources);
      }
      
      if (apiChecks.geoLocation) {
        result.details.geoLocation = apiChecks.geoLocation;
      }
    } catch (error) {
      result.details.apiError = error.message;
    }
    
    // 3. Check for suspicious IP patterns
    const suspiciousCheck = this.checkSuspiciousIPPatterns(ip);
    if (suspiciousCheck.isSuspicious) {
      result.isSuspicious = true;
      result.details.blacklistReasons.push(...suspiciousCheck.reasons);
      result.details.riskScore += suspiciousCheck.score;
      result.sources.push('pattern_analysis');
    }
    
    // Calculate final assessment
    result.details.confidence = this.calculateConfidence(result.sources.length, result.details.riskScore);
    
    // Cache result
    if (this.cache) {
      const ttl = result.isBlacklisted ? 
        BLACKLIST_CONFIG.CACHE_TTL.positive : 
        BLACKLIST_CONFIG.CACHE_TTL.negative;
      this.cache.set(cacheKey, result, ttl);
    }
    
    return result;
  }
  
  // ===== PRIVACY PROTECTION EMAIL DETECTION =====
  checkPrivacyProtectionEmail(email) {
    const domain = email.split('@')[1]?.toLowerCase();
    const localPart = email.split('@')[0]?.toLowerCase();
    
    // Check against known privacy domains
    if (domain && PRIVACY_EMAIL_DOMAINS.has(domain)) {
      return {
        isPrivacy: true,
        service: this.identifyPrivacyService(domain),
        confidence: 'high'
      };
    }
    
    // Check against patterns
    for (const [service, patterns] of Object.entries(PRIVACY_EMAIL_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(email)) {
          return {
            isPrivacy: true,
            service: service,
            confidence: 'medium'
          };
        }
      }
    }
    
    return { isPrivacy: false };
  }
  
  identifyPrivacyService(domain) {
    const serviceMap = {
      'whoisguard.com': 'Namecheap WhoisGuard',
      'domainsbyproxy.com': 'GoDaddy Domains By Proxy',
      'domainprotection.net': 'GoDaddy Domain Protection',
      'perfectprivacy.com': 'Perfect Privacy',
      'privateid.com': 'Private ID',
      'networksolutions.com': 'Network Solutions Privacy',
      'privacyprotect.com': 'Privacy Protect',
      'tucowsdomains.com': 'Tucows Privacy',
      'enomprivacy.com': 'eNom Privacy'
    };
    
    return serviceMap[domain] || 'Unknown Privacy Service';
  }
  
  // ===== DNS BLACKLIST CHECKS =====
  async performDNSBlacklistChecks(ip) {
    const result = {
      isBlacklisted: false,
      reasons: [],
      categories: [],
      sources: [],
      score: 0
    };
    
    const reversedIP = this.reverseIP(ip);
    const allBlacklists = [
      ...DNS_BLACKLISTS.email,
      ...DNS_BLACKLISTS.malware,
      ...DNS_BLACKLISTS.botnet
    ];
    
    const checks = allBlacklists.map(async (blacklist) => {
      try {
        const query = `${reversedIP}.${blacklist}`;
        const addresses = await dns.resolve4(query);
        
        if (addresses.length > 0) {
          return {
            blacklist,
            result: addresses[0],
            category: this.categorizeBlacklist(blacklist)
          };
        }
      } catch (error) {
        // Not listed (NXDOMAIN is expected for clean IPs)
        return null;
      }
    });
    
    const results = await Promise.all(checks);
    const hits = results.filter(r => r !== null);
    
    if (hits.length > 0) {
      result.isBlacklisted = true;
      result.score = Math.min(hits.length * 20, 100);
      
      for (const hit of hits) {
        result.reasons.push(`Listed on ${hit.blacklist} (${hit.result})`);
        result.categories.push(hit.category);
        result.sources.push('dns_blacklist');
      }
      
      result.categories = [...new Set(result.categories)];
      result.sources = [...new Set(result.sources)];
    }
    
    return result;
  }
  
  async checkDomainDNSBlacklists(domain, category = 'email') {
    const result = {
      isBlacklisted: false,
      reasons: [],
      sources: []
    };
    
    const blacklists = DNS_BLACKLISTS[category] || DNS_BLACKLISTS.email;
    
    const checks = blacklists.map(async (blacklist) => {
      try {
        const query = `${domain}.${blacklist}`;
        const addresses = await dns.resolve4(query);
        
        if (addresses.length > 0) {
          return { blacklist, result: addresses[0] };
        }
      } catch (error) {
        return null;
      }
    });
    
    const results = await Promise.all(checks);
    const hits = results.filter(r => r !== null);
    
    if (hits.length > 0) {
      result.isBlacklisted = true;
      
      for (const hit of hits) {
        result.reasons.push(`Domain listed on ${hit.blacklist}`);
        result.sources.push('dns_blacklist');
      }
    }
    
    return result;
  }
  
  // ===== API CHECKS =====
  async performIPAPIChecks(ip) {
    const result = {
      isMalicious: false,
      reasons: [],
      sources: [],
      score: 0,
      geoLocation: null
    };
    
    // VirusTotal API check
    if (process.env.VIRUSTOTAL_API_KEY && rateLimiter.canMakeRequest('virustotal')) {
      try {
        const vtResult = await this.checkVirusTotalIP(ip);
        if (vtResult.malicious > 0) {
          result.isMalicious = true;
          result.reasons.push(`VirusTotal: ${vtResult.malicious}/${vtResult.total} engines flagged as malicious`);
          result.sources.push('virustotal');
          result.score += Math.min(vtResult.malicious * 10, 50);
        }
      } catch (error) {
        console.log('VirusTotal API error:', error.message);
      }
    }
    
    // AbuseIPDB API check
    if (process.env.ABUSEIPDB_API_KEY && rateLimiter.canMakeRequest('abuseipdb')) {
      try {
        const abuseResult = await this.checkAbuseIPDB(ip);
        if (abuseResult.abuseConfidence > 25) {
          result.isMalicious = true;
          result.reasons.push(`AbuseIPDB: ${abuseResult.abuseConfidence}% confidence, ${abuseResult.totalReports} reports`);
          result.sources.push('abuseipdb');
          result.score += Math.min(abuseResult.abuseConfidence, 50);
        }
        
        if (abuseResult.countryCode) {
          result.geoLocation = {
            country: abuseResult.countryCode,
            isp: abuseResult.isp
          };
        }
      } catch (error) {
        console.log('AbuseIPDB API error:', error.message);
      }
    }
    
    return result;
  }
  
  async performEmailAPIChecks(email) {
    const reasons = [];
    
    // Additional email-specific API checks can be added here
    // Most email reputation APIs are paid services
    
    return reasons;
  }
  
  async checkVirusTotalIP(ip) {
    const response = await axios.get(`https://www.virustotal.com/vtapi/v2/ip-address/report`, {
      params: {
        apikey: process.env.VIRUSTOTAL_API_KEY,
        ip: ip
      },
      timeout: BLACKLIST_CONFIG.TIMEOUTS.api
    });
    
    const data = response.data;
    return {
      malicious: data.detected_engines || 0,
      total: data.total_engines || 0,
      detections: data.detected_urls || []
    };
  }
  
  async checkAbuseIPDB(ip) {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: {
        'Key': process.env.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      },
      timeout: BLACKLIST_CONFIG.TIMEOUTS.api
    });
    
    const data = response.data.data;
    return {
      abuseConfidence: data.abuseConfidencePercentage || 0,
      totalReports: data.totalReports || 0,
      countryCode: data.countryCode,
      isp: data.isp,
      categories: data.usageType
    };
  }
  
  // ===== PATTERN ANALYSIS =====
  checkSuspiciousEmailPatterns(email) {
    const result = {
      isSuspicious: false,
      reasons: [],
      score: 0
    };
    
    const localPart = email.split('@')[0];
    const domain = email.split('@')[1];
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      { pattern: /^\d+$/, reason: 'Local part is only numbers', score: 10 },
      { pattern: /^.{1,2}$/, reason: 'Very short local part', score: 15 },
      { pattern: /^.{50,}$/, reason: 'Extremely long local part', score: 20 },
      { pattern: /[!#$%&*+=?^`{|}~]/, reason: 'Contains unusual special characters', score: 10 },
      { pattern: /\.{2,}/, reason: 'Contains consecutive dots', score: 25 },
      { pattern: /^\.|\.$/m, reason: 'Starts or ends with dot', score: 25 }
    ];
    
    for (const { pattern, reason, score } of suspiciousPatterns) {
      if (pattern.test(localPart)) {
        result.isSuspicious = true;
        result.reasons.push(reason);
        result.score += score;
      }
    }
    
    // Check domain patterns
    if (domain) {
      const domainPatterns = [
        { pattern: /\d{5,}/, reason: 'Domain contains long number sequence', score: 15 },
        { pattern: /^[^.]+\.[a-z]{2,3}\.[a-z]{2,3}$/, reason: 'Suspicious TLD pattern', score: 10 },
        { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/i, reason: 'Free/suspicious TLD', score: 20 }
      ];
      
      for (const { pattern, reason, score } of domainPatterns) {
        if (pattern.test(domain)) {
          result.isSuspicious = true;
          result.reasons.push(reason);
          result.score += score;
        }
      }
    }
    
    return result;
  }
  
  checkSuspiciousIPPatterns(ip) {
    const result = {
      isSuspicious: false,
      reasons: [],
      score: 0
    };
    
    // Check for private/internal IPs being used publicly
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^224\./  // Multicast
    ];
    
    for (const range of privateRanges) {
      if (range.test(ip)) {
        result.isSuspicious = true;
        result.reasons.push('Private/internal IP address');
        result.score += 30;
        break;
      }
    }
    
    return result;
  }
  
  // ===== UTILITY FUNCTIONS =====
  reverseIP(ip) {
    return ip.split('.').reverse().join('.');
  }
  
  categorizeBlacklist(blacklist) {
    if (blacklist.includes('spam') || blacklist.includes('rbl')) return 'spam';
    if (blacklist.includes('phishing') || blacklist.includes('virus')) return 'malware';
    if (blacklist.includes('botnet') || blacklist.includes('exploit')) return 'botnet';
    return 'general';
  }
  
  calculateConfidence(sourceCount, riskScore) {
    if (sourceCount >= 3 && riskScore > 50) return 'high';
    if (sourceCount >= 2 && riskScore > 25) return 'medium';
    if (sourceCount >= 1) return 'low';
    return 'very_low';
  }
  
  calculateOverallRisk(summary) {
    let riskScore = 0;
    
    riskScore += summary.blacklistedEmails * 25;
    riskScore += summary.blacklistedIPs * 30;
    riskScore += summary.maliciousIPs * 40;
    riskScore += summary.privacyEmails * 10;
    riskScore += summary.suspiciousEmails * 15;
    
    if (riskScore >= 70) return 'critical';
    if (riskScore >= 40) return 'high';
    if (riskScore >= 20) return 'medium';
    return 'low';
  }
}

// ===== BULK CHECKING FUNCTIONS =====
async function performBulkBlacklistCheck(domains, cache = null) {
  const checker = new BlacklistChecker(cache);
  const results = {};
  
  for (const domain of domains) {
    try {
      // Extract emails and IPs from domain analysis
      const emails = []; // Would come from WHOIS data
      const ips = [];    // Would come from DNS data
      
      results[domain] = await checker.checkEmailAndIPs(emails, ips);
    } catch (error) {
      results[domain] = {
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
    
    // Rate limiting between domains
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  
  return results;
}

// ===== EXPORT =====
module.exports = {
  BlacklistChecker,
  performBulkBlacklistCheck,
  PRIVACY_EMAIL_PATTERNS,
  PRIVACY_EMAIL_DOMAINS,
  DNS_BLACKLISTS,
  BLACKLIST_CONFIG
};