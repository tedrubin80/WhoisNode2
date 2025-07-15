// File Location: /server.js
// WHOIS Backend Server - Production Ready for GitHub Apps + Railway
// Node.js + Express backend for domain intelligence analysis

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// ===== CACHE CONFIGURATION =====
const cache = new NodeCache({ 
  stdTTL: 21600, // 6 hours cache (Railway optimized)
  checkperiod: 3600, // cleanup every hour
  maxKeys: 2000 // increased for better performance
});

// ===== RATE LIMITING =====
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // increased for heavy usage
  message: { error: 'Rate limit exceeded. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + ':' + (req.headers['user-agent'] || '');
  }
});

// ===== MIDDLEWARE =====
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(limiter);

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// ===== LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip}`);
  next();
});

// ===== HEALTH CHECK ENDPOINT =====
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
    },
    cache: {
      keys: cache.keys().length,
      hits: cache.getStats().hits || 0,
      misses: cache.getStats().misses || 0
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== API STATUS ENDPOINT =====
app.get('/api/status', (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool',
    version: '1.0.0',
    status: 'operational',
    endpoints: ['/api/analyze', '/api/bulk-analyze', '/api/mx-analysis'],
    rateLimit: '300 requests per 15 minutes',
    cache: '6 hours TTL'
  });
});

// ===== MAIN ANALYSIS ENDPOINT =====
app.post('/api/analyze', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ 
        success: false,
        error: 'Domain parameter is required',
        example: { domain: 'example.com' }
      });
    }
    
    const cleanDomain = cleanDomainName(domain);
    
    if (!isValidDomain(cleanDomain)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid domain format',
        domain: cleanDomain
      });
    }
    
    console.log(`[ANALYSIS] Starting analysis for: ${cleanDomain}`);
    
    // Check cache first
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      console.log(`[CACHE HIT] ${cleanDomain}`);
      return res.json({ 
        ...cached, 
        fromCache: true,
        responseTime: Date.now() - startTime
      });
    }
    
    // Perform comprehensive analysis
    const analysis = await performDomainAnalysis(cleanDomain);
    
    // Cache successful results
    if (analysis.success) {
      cache.set(cacheKey, analysis, 21600); // 6 hours
    }
    
    analysis.responseTime = Date.now() - startTime;
    console.log(`[ANALYSIS COMPLETE] ${cleanDomain} in ${analysis.responseTime}ms`);
    
    res.json(analysis);
    
  } catch (error) {
    console.error('[ANALYSIS ERROR]', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error during analysis',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== BULK ANALYSIS ENDPOINT =====
app.post('/api/bulk-analyze', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({ 
        success: false,
        error: 'Domains array is required',
        example: { domains: ['example.com', 'test.org'] }
      });
    }
    
    if (domains.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one domain is required'
      });
    }
    
    if (domains.length > 10) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 10 domains allowed per bulk request',
        provided: domains.length
      });
    }
    
    console.log(`[BULK ANALYSIS] Processing ${domains.length} domains`);
    
    const results = [];
    let processedCount = 0;
    
    for (const domain of domains) {
      try {
        const cleanDomain = cleanDomainName(domain);
        
        if (!isValidDomain(cleanDomain)) {
          results.push({
            domain: cleanDomain,
            success: false,
            error: 'Invalid domain format',
            timestamp: new Date().toISOString()
          });
          continue;
        }
        
        const cacheKey = `analysis:${cleanDomain}`;
        let analysis = cache.get(cacheKey);
        
        if (!analysis) {
          analysis = await performDomainAnalysis(cleanDomain);
          if (analysis.success) {
            cache.set(cacheKey, analysis, 21600); // 6 hours
          }
        } else {
          analysis.fromCache = true;
        }
        
        results.push(analysis);
        processedCount++;
        
        // Rate limiting between requests (only for non-cached)
        if (!analysis.fromCache && processedCount < domains.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
      } catch (error) {
        console.error(`[BULK ERROR] ${domain}:`, error.message);
        results.push({
          domain: domain,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    const responseTime = Date.now() - startTime;
    const successCount = results.filter(r => r.success).length;
    
    console.log(`[BULK COMPLETE] ${successCount}/${domains.length} successful in ${responseTime}ms`);
    
    res.json({ 
      results,
      total: results.length,
      successful: successCount,
      failed: results.length - successCount,
      responseTime
    });
    
  } catch (error) {
    console.error('[BULK ANALYSIS ERROR]', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error during bulk analysis',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== MX TOOLBOX STYLE ANALYSIS ENDPOINT =====
app.post('/api/mx-analysis', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ 
        success: false,
        error: 'Domain parameter is required for MX analysis'
      });
    }
    
    const cleanDomain = cleanDomainName(domain);
    console.log(`[MX ANALYSIS] Starting comprehensive analysis for: ${cleanDomain}`);
    
    const mxAnalysis = {
      domain: cleanDomain,
      timestamp: new Date().toISOString(),
      success: true,
      dnsRecords: null,
      mxRecords: null,
      spfRecord: null,
      dmarcRecord: null,
      reverseIpAnalysis: null,
      emailInfrastructure: null,
      geoDistribution: null,
      securityAnalysis: null
    };
    
    // 1. Comprehensive DNS Analysis
    mxAnalysis.dnsRecords = await getDNSRecords(cleanDomain);
    
    // 2. Enhanced MX Analysis
    mxAnalysis.mxRecords = await analyzeMXRecords(cleanDomain);
    
    // 3. SPF Record Analysis
    mxAnalysis.spfRecord = await analyzeSPFRecord(cleanDomain);
    
    // 4. DMARC Record Analysis
    mxAnalysis.dmarcRecord = await analyzeDMARCRecord(cleanDomain);
    
    // 5. Reverse IP Analysis for all A records
    if (mxAnalysis.dnsRecords.A && mxAnalysis.dnsRecords.A.length > 0) {
      mxAnalysis.reverseIpAnalysis = {};
      for (const ip of mxAnalysis.dnsRecords.A.slice(0, 3)) {
        mxAnalysis.reverseIpAnalysis[ip] = await performReverseIPAnalysis(ip);
      }
    }
    
    // 6. Email Infrastructure Summary
    mxAnalysis.emailInfrastructure = generateEmailInfrastructureSummary(mxAnalysis);
    
    // 7. Geographic Distribution
    mxAnalysis.geoDistribution = analyzeGeoDistribution(mxAnalysis);
    
    // 8. Security Analysis
    mxAnalysis.securityAnalysis = analyzeEmailSecurity(mxAnalysis);
    
    mxAnalysis.processingTime = Date.now() - startTime;
    
    res.json(mxAnalysis);
    
  } catch (error) {
    console.error('[MX ANALYSIS ERROR]', error);
    res.status(500).json({ 
      success: false,
      error: 'MX analysis failed',
      message: error.message,
      responseTime: Date.now() - startTime
    });
  }
});

// ===== CORE ANALYSIS FUNCTION =====
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
    
    // 3. Enhanced Privacy Protection Analysis with recursive investigation
    analysis.privacyAnalysis = await analyzePrivacyProtection(analysis.whoisData);
    
    // 4. Registrar Analysis (US detection)
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // 5. Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // 6. Enhanced Privacy Domain Analysis with recursive investigation
    if (analysis.privacyAnalysis.isPrivate && analysis.privacyAnalysis.privacyDomains.length > 0) {
      console.log(`[PRIVACY] Analyzing ${analysis.privacyAnalysis.privacyDomains.length} privacy domains...`);
      // Privacy analysis is already done in analyzePrivacyProtection function
    }
    
    // 7. Generate Intelligence Summary
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
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: 12000,
      headers: { 
        'User-Agent': 'WHOIS-Intelligence-Tool/1.0',
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
    // Return empty records rather than failing
    records.error = error.message;
  }
  
  return records;
}

// ===== ADVANCED PRIVACY PROTECTION ANALYSIS =====
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
  
  // Extract ALL privacy-related emails and domains
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
  
  // Perform recursive analysis on privacy domains
  const recursiveAnalysis = {};
  
  for (const domain of privacyDomains) {
    try {
      console.log(`[RECURSIVE] Analyzing privacy domain: ${domain}`);
      const analysis = await performRecursivePrivacyAnalysis(domain);
      recursiveAnalysis[domain] = analysis;
    } catch (error) {
      console.log(`[RECURSIVE ERROR] Failed to analyze ${domain}: ${error.message}`);
      recursiveAnalysis[domain] = { error: error.message };
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyEmails,
    privacyDomains,
    recursiveAnalysis,
    confidence: isPrivate ? 'high' : 'low'
  };
}

// ===== RECURSIVE PRIVACY ANALYSIS =====
async function performRecursivePrivacyAnalysis(domain) {
  const analysis = {
    domain,
    whoisData: null,
    dnsRecords: null,
    mxRecords: null,
    reverseAnalysis: null,
    registrarIntelligence: null,
    geoIntelligence: null,
    companyIntelligence: null
  };
  
  try {
    // 1. Get WHOIS data for privacy domain
    console.log(`[RECURSIVE WHOIS] ${domain}`);
    analysis.whoisData = await getWhoisData(domain);
    
    // 2. Get comprehensive DNS records
    console.log(`[RECURSIVE DNS] ${domain}`);
    analysis.dnsRecords = await getDNSRecords(domain);
    
    // 3. Analyze MX records for email infrastructure
    console.log(`[RECURSIVE MX] ${domain}`);
    analysis.mxRecords = await analyzeMXRecords(domain);
    
    // 4. Perform reverse IP analysis
    if (analysis.dnsRecords.A && analysis.dnsRecords.A.length > 0) {
      console.log(`[RECURSIVE REVERSE] ${analysis.dnsRecords.A[0]}`);
      analysis.reverseAnalysis = await performReverseIPAnalysis(analysis.dnsRecords.A[0]);
    }
    
    // 5. Enhanced registrar intelligence
    analysis.registrarIntelligence = await enhancedRegistrarAnalysis(analysis.whoisData);
    
    // 6. Geographic and company intelligence
    analysis.geoIntelligence = await enhancedGeoAnalysis(analysis.dnsRecords, analysis.whoisData);
    
    // 7. Company intelligence (detect actual company behind privacy service)
    analysis.companyIntelligence = await detectActualCompany(analysis);
    
    return analysis;
    
  } catch (error) {
    console.error(`[RECURSIVE ERROR] ${domain}:`, error.message);
    analysis.error = error.message;
    return analysis;
  }
}

// ===== MX RECORDS ANALYSIS =====
async function analyzeMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    const mxAnalysis = {
      records: mxRecords,
      providers: [],
      infrastructure: [],
      insights: []
    };
    
    for (const mx of mxRecords) {
      const mxDomain = mx.exchange.toLowerCase();
      
      // Identify email providers
      let provider = 'Unknown';
      let infrastructure = 'Unknown';
      
      if (mxDomain.includes('google') || mxDomain.includes('gmail')) {
        provider = 'Google Workspace';
        infrastructure = 'US-based (Google)';
      } else if (mxDomain.includes('outlook') || mxDomain.includes('microsoft')) {
        provider = 'Microsoft 365';
        infrastructure = 'US-based (Microsoft)';
      } else if (mxDomain.includes('amazonaws') || mxDomain.includes('aws')) {
        provider = 'Amazon SES';
        infrastructure = 'US-based (Amazon)';
      } else if (mxDomain.includes('cloudflare')) {
        provider = 'Cloudflare Email';
        infrastructure = 'US-based (Cloudflare)';
      } else if (mxDomain.includes('namecheap')) {
        provider = 'Namecheap Email';
        infrastructure = 'US-based (Namecheap)';
      } else if (mxDomain.includes('godaddy')) {
        provider = 'GoDaddy Email';
        infrastructure = 'US-based (GoDaddy)';
      }
      
      mxAnalysis.providers.push(provider);
      mxAnalysis.infrastructure.push(infrastructure);
      
      // Get geographic info for MX server
      try {
        const mxIPs = await dns.resolve4(mxDomain);
        if (mxIPs.length > 0) {
          const geo = geoip.lookup(mxIPs[0]);
          if (geo) {
            mxAnalysis.insights.push({
              mx: mxDomain,
              ip: mxIPs[0],
              country: geo.country,
              provider: provider,
              priority: mx.priority
            });
          }
        }
      } catch (error) {
        console.log(`MX geo lookup failed for ${mxDomain}`);
      }
    }
    
    return mxAnalysis;
    
  } catch (error) {
    console.log(`MX analysis failed for ${domain}: ${error.message}`);
    return { error: error.message };
  }
}

// ===== REVERSE IP ANALYSIS =====
async function performReverseIPAnalysis(ip) {
  const reverseAnalysis = {
    ip,
    hostname: null,
    geo: null,
    asn: null,
    sharedHosts: [],
    networkInfo: null
  };
  
  try {
    // Reverse DNS lookup
    try {
      const hostnames = await dns.reverse(ip);
      reverseAnalysis.hostname = hostnames[0] || null;
    } catch (error) {
      console.log(`Reverse DNS failed for ${ip}`);
    }
    
    // Geographic analysis
    reverseAnalysis.geo = geoip.lookup(ip);
    
    // Try to get ASN information from hostname patterns
    if (reverseAnalysis.hostname) {
      const hostname = reverseAnalysis.hostname.toLowerCase();
      
      if (hostname.includes('amazonaws') || hostname.includes('aws')) {
        reverseAnalysis.networkInfo = { provider: 'Amazon Web Services', country: 'US' };
      } else if (hostname.includes('googleusercontent') || hostname.includes('google')) {
        reverseAnalysis.networkInfo = { provider: 'Google Cloud', country: 'US' };
      } else if (hostname.includes('azure') || hostname.includes('microsoft')) {
        reverseAnalysis.networkInfo = { provider: 'Microsoft Azure', country: 'US' };
      } else if (hostname.includes('cloudflare')) {
        reverseAnalysis.networkInfo = { provider: 'Cloudflare', country: 'US' };
      } else if (hostname.includes('namecheap')) {
        reverseAnalysis.networkInfo = { provider: 'Namecheap Hosting', country: 'US' };
      } else if (hostname.includes('godaddy')) {
        reverseAnalysis.networkInfo = { provider: 'GoDaddy Hosting', country: 'US' };
      }
    }
    
    return reverseAnalysis;
    
  } catch (error) {
    console.error(`Reverse IP analysis failed for ${ip}: ${error.message}`);
    reverseAnalysis.error = error.message;
    return reverseAnalysis;
  }
}

// ===== ENHANCED REGISTRAR ANALYSIS =====
async function enhancedRegistrarAnalysis(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  const registrarLower = registrar.toLowerCase();
  
  const registrarIntelligence = {
    name: registrar,
    category: 'Unknown',
    isUSBased: false,
    parentCompany: null,
    headquarters: null,
    founded: null,
    icannAccredited: null,
    confidence: 'medium'
  };
  
  // Enhanced US registrar database with parent companies and locations
  const enhancedRegistrarDB = {
    'namecheap': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'Namecheap, Inc.',
      headquarters: 'Los Angeles, California, USA',
      founded: '2000',
      icannAccredited: true,
      actualLocation: 'USA (despite Reykjavik presence)',
      confidence: 'high'
    },
    'godaddy': {
      category: 'Major US Commercial',
      isUSBased: true,
      parentCompany: 'GoDaddy Inc.',
      headquarters: 'Scottsdale, Arizona, USA',
      founded: '1997',
      icannAccredited: true,
      confidence: 'high'
    },
    'network solutions': {
      category: 'Legacy US Provider',
      isUSBased: true,
      parentCompany: 'Web.com Group',
      headquarters: 'Herndon, Virginia, USA',
      founded: '1979',
      icannAccredited: true,
      confidence: 'high'
    },
    'enom': {
      category: 'US Wholesale/Reseller',
      isUSBased: true,
      parentCompany: 'Tucows Inc.',
      headquarters: 'Bellevue, Washington, USA',
      founded: '1997',
      icannAccredited: true,
      confidence: 'high'
    },
    'tucows': {
      category: 'US/Canada Provider',
      isUSBased: true,
      parentCompany: 'Tucows Inc.',
      headquarters: 'Toronto, Canada (US operations)',
      founded: '1993',
      icannAccredited: true,
      confidence: 'high'
    },
    'markmonitor': {
      category: 'Enterprise US',
      isUSBased: true,
      parentCompany: 'Clarivate Analytics',
      headquarters: 'San Francisco, California, USA',
      founded: '1999',
      icannAccredited: true,
      confidence: 'high'
    }
  };
  
  // Check against enhanced database
  for (const [key, info] of Object.entries(enhancedRegistrarDB)) {
    if (registrarLower.includes(key)) {
      Object.assign(registrarIntelligence, info);
      break;
    }
  }
  
  // Additional intelligence from WHOIS data
  if (whoisData.registrantCountry) {
    registrarIntelligence.registrantCountry = whoisData.registrantCountry;
  }
  
  return registrarIntelligence;
}

// ===== ENHANCED GEOGRAPHIC ANALYSIS =====
async function enhancedGeoAnalysis(dnsRecords, whoisData) {
  const geoAnalysis = {
    ipLocations: [],
    nameServerLocations: [],
    registrantLocation: null,
    infrastructureCountries: new Set(),
    usPresence: false,
    primaryCountry: null
  };
  
  // Analyze A record IPs
  if (dnsRecords.A) {
    for (const ip of dnsRecords.A) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoAnalysis.ipLocations.push({
          ip,
          country: geo.country,
          region: geo.region,
          city: geo.city,
          timezone: geo.timezone
        });
        geoAnalysis.infrastructureCountries.add(geo.country);
        if (geo.country === 'US') {
          geoAnalysis.usPresence = true;
        }
      }
    }
  }
  
  // Analyze name server locations
  if (dnsRecords.NS) {
    for (const ns of dnsRecords.NS) {
      try {
        const nsIPs = await dns.resolve4(ns);
        for (const ip of nsIPs) {
          const geo = geoip.lookup(ip);
          if (geo) {
            geoAnalysis.nameServerLocations.push({
              nameServer: ns,
              ip,
              country: geo.country,
              region: geo.region,
              city: geo.city
            });
            geoAnalysis.infrastructureCountries.add(geo.country);
            if (geo.country === 'US') {
              geoAnalysis.usPresence = true;
            }
          }
        }
      } catch (error) {
        console.log(`NS geo lookup failed for ${ns}`);
      }
    }
  }
  
  // Registrant location from WHOIS
  if (whoisData.registrantCountry) {
    geoAnalysis.registrantLocation = whoisData.registrantCountry;
  }
  
  // Determine primary country
  const countries = Array.from(geoAnalysis.infrastructureCountries);
  if (countries.length > 0) {
    // US takes precedence if present
    geoAnalysis.primaryCountry = geoAnalysis.usPresence ? 'US' : countries[0];
  }
  
  return geoAnalysis;
}

// ===== COMPANY INTELLIGENCE DETECTION =====
async function detectActualCompany(analysis) {
  const companyIntelligence = {
    actualCompany: null,
    confidence: 'low',
    indicators: [],
    usConnections: [],
    reasoning: []
  };
  
  const domain = analysis.domain;
  const whoisData = analysis.whoisData;
  const mxAnalysis = analysis.mxRecords;
  const geoAnalysis = analysis.geoIntelligence;
  
  // Check for known company patterns
  if (domain.includes('namecheap')) {
    companyIntelligence.actualCompany = 'Namecheap, Inc. (US Company)';
    companyIntelligence.confidence = 'high';
    companyIntelligence.indicators.push('Domain contains "namecheap"');
    companyIntelligence.usConnections.push('Namecheap headquarters: Los Angeles, CA');
    companyIntelligence.reasoning.push('Despite Reykjavik presence, Namecheap is a US-incorporated company');
  }
  
  // Analyze email infrastructure for US connections
  if (mxAnalysis && mxAnalysis.infrastructure) {
    const usProviders = mxAnalysis.infrastructure.filter(inf => inf.includes('US-based'));
    if (usProviders.length > 0) {
      companyIntelligence.usConnections.push(...usProviders);
      companyIntelligence.indicators.push('Uses US-based email infrastructure');
    }
  }
  
  // Check registrar information
  if (analysis.registrarIntelligence && analysis.registrarIntelligence.isUSBased) {
    companyIntelligence.usConnections.push(`Registrar: ${analysis.registrarIntelligence.name} (US-based)`);
    companyIntelligence.indicators.push('Registered with US-based registrar');
  }
  
  // Geographic infrastructure analysis
  if (geoAnalysis && geoAnalysis.usPresence) {
    companyIntelligence.usConnections.push('Infrastructure hosted in US');
    companyIntelligence.indicators.push('US infrastructure presence detected');
  }
  
  // Name server analysis
  if (analysis.dnsRecords && analysis.dnsRecords.NS) {
    const usNameServers = analysis.dnsRecords.NS.filter(ns => 
      ns.includes('namecheap') || 
      ns.includes('godaddy') ||
      ns.includes('amazonaws') ||
      ns.includes('cloudflare')
    );
    
    if (usNameServers.length > 0) {
      companyIntelligence.usConnections.push(`US name servers: ${usNameServers.join(', ')}`);
      companyIntelligence.indicators.push('Uses US-controlled name servers');
    }
  }
  
  // Calculate confidence based on indicators
  if (companyIntelligence.indicators.length >= 3) {
    companyIntelligence.confidence = 'high';
  } else if (companyIntelligence.indicators.length >= 2) {
    companyIntelligence.confidence = 'medium';
  }
  
  return companyIntelligence;
}

// ===== SPF RECORD ANALYSIS =====
async function analyzeSPFRecord(domain) {
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

// ===== EMAIL INFRASTRUCTURE SUMMARY =====
function generateEmailInfrastructureSummary(mxAnalysis) {
  const summary = {
    primaryProvider: 'Unknown',
    isUSBased: false,
    providers: [],
    infrastructure: [],
    securityScore: 0,
    recommendations: []
  };
  
  // Analyze MX records for primary provider
  if (mxAnalysis.mxRecords && mxAnalysis.mxRecords.providers) {
    summary.providers = [...new Set(mxAnalysis.mxRecords.providers)];
    summary.primaryProvider = summary.providers[0] || 'Unknown';
    
    // Check if US-based
    summary.isUSBased = summary.providers.some(provider => 
      provider.includes('US-based') || 
      provider.includes('Google') || 
      provider.includes('Microsoft') || 
      provider.includes('Amazon')
    );
  }
  
  // Calculate security score
  let score = 0;
  
  if (mxAnalysis.spfRecord?.exists) {
    score += 25;
    if (mxAnalysis.spfRecord.strength === 'strict') score += 10;
  }
  
  if (mxAnalysis.dmarcRecord?.exists) {
    score += 25;
    if (mxAnalysis.dmarcRecord.strength === 'strict') score += 15;
    else if (mxAnalysis.dmarcRecord.strength === 'moderate') score += 10;
  }
  
  // TLS support (assumed for major providers)
  if (summary.providers.some(p => p.includes('Google') || p.includes('Microsoft') || p.includes('Amazon'))) {
    score += 20;
  }
  
  summary.securityScore = Math.min(score, 100);
  
  // Generate recommendations
  if (!mxAnalysis.spfRecord?.exists) {
    summary.recommendations.push('Implement SPF record to prevent email spoofing');
  }
  
  if (!mxAnalysis.dmarcRecord?.exists) {
    summary.recommendations.push('Implement DMARC policy for email authentication');
  }
  
  if (mxAnalysis.spfRecord?.strength === 'weak') {
    summary.recommendations.push('Strengthen SPF policy (use -all instead of +all)');
  }
  
  return summary;
}

// ===== GEOGRAPHIC DISTRIBUTION ANALYSIS =====
function analyzeGeoDistribution(mxAnalysis) {
  const distribution = {
    countries: new Set(),
    regions: new Set(),
    infrastructure: {
      web: new Set(),
      email: new Set(),
      dns: new Set()
    },
    usPresence: {
      web: false,
      email: false,
      dns: false,
      overall: false
    }
  };
  
  // Analyze web infrastructure (A records)
  if (mxAnalysis.reverseIpAnalysis) {
    for (const [ip, data] of Object.entries(mxAnalysis.reverseIpAnalysis)) {
      if (data.geo) {
        distribution.countries.add(data.geo.country);
        distribution.regions.add(data.geo.region);
        distribution.infrastructure.web.add(data.geo.country);
        
        if (data.geo.country === 'US') {
          distribution.usPresence.web = true;
        }
      }
    }
  }
  
  // Analyze email infrastructure (MX records)
  if (mxAnalysis.mxRecords?.insights) {
    for (const insight of mxAnalysis.mxRecords.insights) {
      distribution.countries.add(insight.country);
      distribution.infrastructure.email.add(insight.country);
      
      if (insight.country === 'US') {
        distribution.usPresence.email = true;
      }
    }
  }
  
  // Analyze DNS infrastructure (NS records)
  if (mxAnalysis.dnsRecords?.NS) {
    for (const ns of mxAnalysis.dnsRecords.NS) {
      if (ns.includes('cloudflare') || ns.includes('amazon') || ns.includes('google')) {
        distribution.infrastructure.dns.add('US');
        distribution.usPresence.dns = true;
      }
    }
  }
  
  // Overall US presence
  distribution.usPresence.overall = 
    distribution.usPresence.web || 
    distribution.usPresence.email || 
    distribution.usPresence.dns;
  
  return {
    countries: Array.from(distribution.countries),
    regions: Array.from(distribution.regions),
    infrastructure: {
      web: Array.from(distribution.infrastructure.web),
      email: Array.from(distribution.infrastructure.email),
      dns: Array.from(distribution.infrastructure.dns)
    },
    usPresence: distribution.usPresence
  };
}

// ===== EMAIL SECURITY ANALYSIS =====
function analyzeEmailSecurity(mxAnalysis) {
  const security = {
    overallRating: 'Unknown',
    spfStatus: 'Not Configured',
    dmarcStatus: 'Not Configured',
    tlsSupport: 'Unknown',
    vulnerabilities: [],
    strengths: [],
    recommendations: []
  };
  
  // SPF Analysis
  if (mxAnalysis.spfRecord?.exists) {
    security.spfStatus = `Configured (${mxAnalysis.spfRecord.strength})`;
    if (mxAnalysis.spfRecord.strength === 'strict') {
      security.strengths.push('Strong SPF policy (-all)');
    } else if (mxAnalysis.spfRecord.strength === 'weak') {
      security.vulnerabilities.push('Weak SPF policy (+all allows any server)');
    }
  } else {
    security.vulnerabilities.push('No SPF record - vulnerable to email spoofing');
  }
  
  // DMARC Analysis
  if (mxAnalysis.dmarcRecord?.exists) {
    security.dmarcStatus = `Configured (${mxAnalysis.dmarcRecord.policy})`;
    if (mxAnalysis.dmarcRecord.policy === 'reject') {
      security.strengths.push('Strong DMARC policy (reject)');
    } else if (mxAnalysis.dmarcRecord.policy === 'none') {
      security.vulnerabilities.push('DMARC policy set to none (monitoring only)');
    }
  } else {
    security.vulnerabilities.push('No DMARC record - no email authentication policy');
  }
  
  // TLS Support (inferred from provider)
  if (mxAnalysis.mxRecords?.providers?.some(p => 
    p.includes('Google') || p.includes('Microsoft') || p.includes('Amazon') || p.includes('Cloudflare')
  )) {
    security.tlsSupport = 'Supported';
    security.strengths.push('TLS encryption supported by email provider');
  }
  
  // Calculate overall rating
  const strengthScore = security.strengths.length * 2;
  const vulnerabilityScore = security.vulnerabilities.length;
  
  if (strengthScore >= 4 && vulnerabilityScore === 0) {
    security.overallRating = 'Excellent';
  } else if (strengthScore >= 2 && vulnerabilityScore <= 1) {
    security.overallRating = 'Good';
  } else if (strengthScore >= 1 && vulnerabilityScore <= 2) {
    security.overallRating = 'Fair';
  } else {
    security.overallRating = 'Poor';
  }
  
  return security;
}

// ===== REGISTRAR ANALYSIS (US DETECTION) =====
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
  if (analysis.privacyAnalysis?.privacyDomains?.length > 0) flags.push('CHECK_PRIVACY_DOMAINS');
  if (analysis.geoData?.primaryLocation?.country === 'US') flags.push('US_HOSTED');
  
  // Add recursive analysis flags
  if (analysis.privacyAnalysis?.recursiveAnalysis) {
    let hasUSPrivacyInfrastructure = false;
    let hasActualCompanyDetected = false;
    
    for (const [domain, recursiveData] of Object.entries(analysis.privacyAnalysis.recursiveAnalysis)) {
      if (recursiveData.geoIntelligence?.usPresence) {
        hasUSPrivacyInfrastructure = true;
        flags.push('US_PRIVACY_INFRASTRUCTURE');
      }
      
      if (recursiveData.companyIntelligence?.actualCompany) {
        hasActualCompanyDetected = true;
        flags.push('ACTUAL_COMPANY_DETECTED');
      }
      
      if (recursiveData.registrarIntelligence?.isUSBased) {
        flags.push('US_PRIVACY_REGISTRAR');
      }
    }
  }
  
  return {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    registrarCategory: analysis.registrarInfo?.category || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    privacyDomains: analysis.privacyAnalysis?.privacyDomains || [],
    privacyEmails: analysis.privacyAnalysis?.privacyEmails || [],
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null,
    needsPrivacyDomainCheck: analysis.privacyAnalysis?.isPrivate && analysis.privacyAnalysis?.privacyDomains?.length > 0,
    recursiveAnalysisResults: analysis.privacyAnalysis?.recursiveAnalysis || {},
    quickAssessment: {
      flags,
      priority: flags.includes('ACTUAL_COMPANY_DETECTED') || flags.includes('US_PRIVACY_INFRASTRUCTURE') ? 'high' : 
                flags.includes('CHECK_PRIVACY_DOMAINS') ? 'high' : 'normal',
      recommendation: generateEnhancedWorkflowRecommendation(flags, analysis.privacyAnalysis?.recursiveAnalysis)
    }
  };
}

function generateEnhancedWorkflowRecommendation(flags, recursiveAnalysis) {
  // Priority recommendations based on recursive analysis
  if (flags.includes('ACTUAL_COMPANY_DETECTED')) {
    const actualCompanies = [];
    if (recursiveAnalysis) {
      for (const [domain, data] of Object.entries(recursiveAnalysis)) {
        if (data.companyIntelligence?.actualCompany) {
          actualCompanies.push(`${domain}: ${data.companyIntelligence.actualCompany}`);
        }
      }
    }
    return `High Priority: Actual company detected behind privacy service - ${actualCompanies.join(', ')}`;
  }
  
  if (flags.includes('US_PRIVACY_INFRASTRUCTURE')) {
    return 'High Priority: Privacy service uses US-based infrastructure - likely US jurisdiction applies';
  }
  
  if (flags.includes('CHECK_PRIVACY_DOMAINS')) {
    return 'High Priority: Multiple privacy domains found - perform recursive investigation on each';
  }
  
  if (flags.includes('PRIVACY_PROTECTED')) {
    return 'Medium Priority: Domain uses privacy protection - check privacy contact domains for actual registrant';
  }
  
  if (flags.includes('US_REGISTRAR')) {
    return 'US-based registrar - UDRP procedures and US legal remedies available';
  }
  
  return 'Standard domain registration - proceed with normal verification process';
}

// ===== UTILITY FUNCTIONS =====
function cleanDomainName(domain) {
  return domain.trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .toLowerCase();
}

function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return domainRegex.test(domain) && domain.includes('.') && domain.length <= 253;
}

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

// ===== ERROR HANDLING MIDDLEWARE =====
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.stack);
  res.status(500).json({ 
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    error: 'Endpoint not found',
    availableEndpoints: ['/health', '/api/status', '/api/analyze', '/api/bulk-analyze', '/api/mx-analysis']
  });
});

// ===== SERVER STARTUP =====
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('🚀 WHOIS Intelligence Backend Server');
  console.log('='.repeat(60));
  console.log(`📡 Server running on port: ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API status: http://localhost:${PORT}/api/status`);
  console.log(`💾 Cache TTL: 6 hours`);
  console.log(`⚡ Rate limit: 300 requests per 15 minutes`);
  console.log(`🔍 Features: Recursive privacy analysis, MX Toolbox integration`);
  console.log('='.repeat(60));
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  process.exit(0);
});

module.exports = app;