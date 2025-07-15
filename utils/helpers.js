// FILE LOCATION: /utils/helpers.js
// FILE NAME: helpers.js
// PURPOSE: Missing Helper Functions for Enhanced WHOIS Intelligence Server
// DESCRIPTION: Core analysis functions that need to be added to the enhanced server
// VERSION: 2.0.0
// USAGE: Import these functions into server-enhanced.js

// ===== CORE ANALYSIS FUNCTION (from original server) =====
async function performDomainAnalysis(domain) {
  const startTime = Date.now();
  
  const analysis = {
    domain,
    timestamp: new Date().toISOString(),
    success: true,
    processingTime: null,
    whoisData: null,
    dnsData: null,
    privacyAnalysis: null,
    registrarInfo: null,
    geoData: null,
    summary: {}
  };
  
  try {
    console.log(`[WHOIS] Fetching data for ${domain}...`);
    
    // 1. WHOIS Lookup with timeout
    analysis.whoisData = await Promise.race([
      getWhoisData(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('WHOIS lookup timeout')), 20000)
      )
    ]);
    
    console.log(`[DNS] Fetching records for ${domain}...`);
    
    // 2. DNS Records with timeout
    analysis.dnsData = await Promise.race([
      getDNSRecords(domain),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('DNS lookup timeout')), 15000)
      )
    ]);
    
    console.log(`[ANALYSIS] Processing intelligence for ${domain}...`);
    
    // 3. Enhanced Privacy Protection Analysis
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    
    // 4. Registrar Analysis
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // 5. Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // 6. Generate Intelligence Summary
    analysis.summary = generateIntelligenceSummary(analysis);
    
    analysis.processingTime = Date.now() - startTime;
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
    analysis.processingTime = Date.now() - startTime;
    console.error(`[ANALYSIS FAILED] ${domain}: ${error.message}`);
  }
  
  return analysis;
}

// ===== WHOIS DATA RETRIEVAL =====
async function getWhoisData(domain) {
  const methods = [
    () => whoisCommandLookup(domain),
    () => whoisAPILookup(domain)
  ];
  
  for (const method of methods) {
    try {
      const result = await method();
      if (result && result.domain) {
        return result;
      }
    } catch (error) {
      console.log(`[WHOIS METHOD FAILED] ${domain}: ${error.message}`);
    }
  }
  
  throw new Error(`All WHOIS methods failed for ${domain}`);
}

function whoisCommandLookup(domain) {
  const whois = require('whois');
  
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('WHOIS command timeout'));
    }, 18000);
    
    whois.lookup(domain, { timeout: 15000 }, (err, data) => {
      clearTimeout(timeout);
      if (err) {
        reject(new Error(`WHOIS command failed: ${err.message}`));
      } else {
        resolve(parseRawWhois(data, domain));
      }
    });
  });
}

async function whoisAPILookup(domain) {
  const axios = require('axios');
  
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: 12000,
      headers: { 
        'User-Agent': 'WHOIS-Intelligence-Tool/2.0',
        ...(process.env.WHOISJSON_API_KEY && { 
          'Authorization': `Bearer ${process.env.WHOISJSON_API_KEY}` 
        })
      }
    });
    
    if (response.data && !response.data.error) {
      return parseWhoisResponse(response.data);
    }
  } catch (error) {
    throw new Error(`WHOIS API failed: ${error.message}`);
  }
  
  return null;
}

// ===== DNS RECORDS RETRIEVAL =====
async function getDNSRecords(domain) {
  const dns = require('dns').promises;
  const records = {};
  const startTime = Date.now();
  
  try {
    // Parallel DNS lookups for speed
    const [A, AAAA, MX, NS, TXT, SOA] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolve6(domain),
      dns.resolveMx(domain),
      dns.resolveNs(domain),
      dns.resolveTxt(domain),
      dns.resolveSoa(domain)
    ]);
    
    records.A = A.status === 'fulfilled' ? A.value : [];
    records.AAAA = AAAA.status === 'fulfilled' ? AAAA.value : [];
    records.MX = MX.status === 'fulfilled' ? MX.value : [];
    records.NS = NS.status === 'fulfilled' ? NS.value : [];
    records.TXT = TXT.status === 'fulfilled' ? TXT.value : [];
    records.SOA = SOA.status === 'fulfilled' ? SOA.value : null;
    
    records.queryTime = Date.now() - startTime;
    
  } catch (error) {
    console.error(`[DNS ERROR] ${domain}: ${error.message}`);
    records.error = error.message;
  }
  
  return records;
}

// ===== PRIVACY PROTECTION ANALYSIS =====
async function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration',
    'proxy protection', 'domain privacy', 'registration private',
    'withheld for privacy', 'privacy protected', 'domain protection'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyEmails = [];
  let privacyDomains = [];
  
  // Check for privacy indicators
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  // Extract privacy-related emails and domains
  if (whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      const localPart = email.split('@')[0].toLowerCase();
      
      // Check if email is privacy-related
      const isPrivacyEmail = 
        domain.includes('privacy') || 
        domain.includes('whoisguard') || 
        domain.includes('proxy') ||
        domain.includes('protection') ||
        localPart.includes('privacy') ||
        localPart.includes('whois') ||
        localPart.includes('proxy') ||
        privacyServices.some(service => 
          domain.includes(service.replace(/\s+/g, '')) || 
          localPart.includes(service.replace(/\s+/g, ''))
        );
      
      if (isPrivacyEmail) {
        isPrivate = true;
        privacyEmails.push(email);
        if (!privacyDomains.includes(domain)) {
          privacyDomains.push(domain);
        }
      }
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyEmails,
    privacyDomains,
    confidence: isPrivate ? 'high' : 'low'
  };
}

// ===== REGISTRAR ANALYSIS =====
function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  let category = 'Other';
  let isUSBased = false;
  
  const registrarLower = registrar.toLowerCase();
  
  // US Registrar Detection
  const usRegistrars = {
    'godaddy': { category: 'Major US Commercial', usBased: true },
    'namecheap': { category: 'Discount US Provider', usBased: true },
    'network solutions': { category: 'Legacy US Provider', usBased: true },
    'verisign': { category: 'Legacy US Provider', usBased: true },
    'enom': { category: 'US Wholesale/Reseller', usBased: true },
    'tucows': { category: 'US Wholesale/Reseller', usBased: true },
    'google domains': { category: 'Tech Giant US', usBased: true },
    'amazon': { category: 'Tech Giant US', usBased: true },
    'cloudflare': { category: 'Tech Giant US', usBased: true },
    'markmonitor': { category: 'Enterprise US', usBased: true },
    'csc corporate domains': { category: 'Enterprise US', usBased: true }
  };
  
  for (const [key, info] of Object.entries(usRegistrars)) {
    if (registrarLower.includes(key)) {
      category = info.category;
      isUSBased = info.usBased;
      break;
    }
  }
  
  return {
    name: registrar,
    category,
    isUSBased,
    country: whoisData.registrantCountry || whoisData.adminCountry || 'Unknown'
  };
}

// ===== GEOGRAPHIC ANALYSIS =====
async function analyzeGeolocation(dnsData) {
  const geoip = require('geoip-lite');
  
  const geoInfo = {
    countries: new Set(),
    regions: new Set(),
    cities: new Set(),
    primaryLocation: null
  };
  
  if (dnsData.A && dnsData.A.length > 0) {
    // Analyze first 3 IPs for geographic diversity
    for (const ip of dnsData.A.slice(0, 3)) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoInfo.countries.add(geo.country);
        geoInfo.regions.add(geo.region);
        geoInfo.cities.add(geo.city);
        
        if (!geoInfo.primaryLocation) {
          geoInfo.primaryLocation = {
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            timezone: geo.timezone,
            ll: geo.ll // latitude/longitude
          };
        }
      }
    }
  }
  
  return {
    countries: Array.from(geoInfo.countries),
    regions: Array.from(geoInfo.regions),
    cities: Array.from(geoInfo.cities),
    primaryLocation: geoInfo.primaryLocation,
    totalIPs: dnsData.A ? dnsData.A.length : 0
  };
}

// ===== INTELLIGENCE SUMMARY GENERATION =====
function generateIntelligenceSummary(analysis) {
  const flags = [];
  
  // Generate workflow flags
  if (analysis.registrarInfo?.isUSBased) flags.push('US_REGISTRAR');
  if (analysis.privacyAnalysis?.isPrivate) flags.push('PRIVACY_PROTECTED');
  if (analysis.geoData?.primaryLocation?.country === 'US') flags.push('US_HOSTED');
  
  return {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    registrarCategory: analysis.registrarInfo?.category || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null,
    quickAssessment: {
      flags,
      priority: flags.includes('PRIVACY_PROTECTED') ? 'high' : 'normal'
    }
  };
}

// ===== SPF RECORD ANALYSIS =====
async function analyzeSPFRecord(domain) {
  const dns = require('dns').promises;
  
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spfRecord = txtRecords.find(record => 
      record.join('').toLowerCase().startsWith('v=spf1')
    );
    
    if (!spfRecord) {
      return { exists: false, record: null, analysis: 'No SPF record found' };
    }
    
    const spfString = spfRecord.join('');
    const mechanisms = spfString.split(' ').filter(part => part.length > 0);
    
    const analysis = {
      exists: true,
      record: spfString,
      mechanisms: mechanisms,
      includes: mechanisms.filter(m => m.startsWith('include:')),
      ipRanges: mechanisms.filter(m => m.startsWith('ip4:') || m.startsWith('ip6:')),
      all: mechanisms.find(m => m.startsWith('~all') || m.startsWith('-all') || m.startsWith('+all')),
      strength: 'unknown'
    };
    
    // Determine SPF strength
    if (analysis.all === '-all') {
      analysis.strength = 'strict';
    } else if (analysis.all === '~all') {
      analysis.strength = 'soft';
    } else if (analysis.all === '+all') {
      analysis.strength = 'weak';
    }
    
    return analysis;
    
  } catch (error) {
    return { exists: false, error: error.message };
  }
}

// ===== DMARC RECORD ANALYSIS =====
async function analyzeDMARCRecord(domain) {
  const dns = require('dns').promises;
  
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    const dmarcRecord = txtRecords.find(record => 
      record.join('').toLowerCase().startsWith('v=dmarc1')
    );
    
    if (!dmarcRecord) {
      return { exists: false, record: null, analysis: 'No DMARC record found' };
    }
    
    const dmarcString = dmarcRecord.join('');
    const tags = {};
    
    // Parse DMARC tags
    dmarcString.split(';').forEach(tag => {
      const [key, value] = tag.trim().split('=');
      if (key && value) {
        tags[key.trim()] = value.trim();
      }
    });
    
    return {
      exists: true,
      record: dmarcString,
      policy: tags.p || 'none',
      subdomainPolicy: tags.sp,
      percentage: tags.pct || '100',
      reportingEmails: {
        aggregate: tags.rua,
        forensic: tags.ruf
      },
      alignment: {
        spf: tags.aspf || 'r',
        dkim: tags.adkim || 'r'
      },
      strength: tags.p === 'reject' ? 'strict' : tags.p === 'quarantine' ? 'moderate' : 'weak'
    };
    
  } catch (error) {
    return { exists: false, error: error.message };
  }
}

// ===== WHOIS PARSING FUNCTIONS =====
function parseWhoisResponse(data) {
  return {
    domain: data.domain,
    registrar: data.registrar,
    creationDate: data.creation_date || data.created,
    expirationDate: data.expiration_date || data.expires,
    updatedDate: data.updated_date || data.updated,
    status: data.status,
    registrantName: data.registrant_name,
    registrantOrganization: data.registrant_organization,
    registrantEmail: data.registrant_email,
    registrantCountry: data.registrant_country,
    adminEmail: data.admin_email,
    techEmail: data.tech_email,
    nameServers: data.name_servers || data.nameservers,
    emails: extractEmails(JSON.stringify(data)),
    rawData: data
  };
}

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  // Extract key fields from raw WHOIS
  for (const line of lines) {
    const lower = line.toLowerCase();
    
    if (lower.includes('registrar:') && !parsed.registrar) {
      parsed.registrar = line.split(':')[1]?.trim();
    } else if ((lower.includes('creation date:') || lower.includes('created:')) && !parsed.creationDate) {
      parsed.creationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('expir') && !parsed.expirationDate) {
      parsed.expirationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('registrant country:') && !parsed.registrantCountry) {
      parsed.registrantCountry = line.split(':')[1]?.trim();
    }
  }
  
  // Extract emails
  parsed.emails = extractEmails(rawData);
  
  // Extract name servers
  const nsRegex = /name server:\s*([^\s\r\n]+)/gi;
  const nameServers = [];
  let match;
  while ((match = nsRegex.exec(rawData)) !== null) {
    nameServers.push(match[1].toLowerCase());
  }
  parsed.nameServers = [...new Set(nameServers)];
  
  return parsed;
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails.map(email => email.toLowerCase()))];
}

// Export all functions for use in main server
module.exports = {
  performDomainAnalysis,
  getWhoisData,
  whoisCommandLookup,
  whoisAPILookup,
  getDNSRecords,
  analyzePrivacyProtection,
  analyzeRegistrar,
  analyzeGeolocation,
  generateIntelligenceSummary,
  analyzeSPFRecord,
  analyzeDMARCRecord,
  parseWhoisResponse,
  parseRawWhois,
  extractEmails
};