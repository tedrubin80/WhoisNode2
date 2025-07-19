/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── ai/
│   ├── agents/
│   │   ├── domain-analyst.js        
│   │   ├── threat-hunter.js         (this file)
│   │   ├── risk-assessor.js
│   │   └── report-generator.js

FILE LOCATION: /ai/agents/threat-hunter.js
*/

// Threat Hunting Agent - Advanced AI-Powered Threat Detection
// FILE: /ai/agents/threat-hunter.js

const { ChatOpenAI } = require("@langchain/openai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { LLMChain } = require("langchain/chains");
const { DynamicTool } = require("@langchain/core/tools");
const { AgentExecutor, createOpenAIFunctionsAgent } = require("langchain/agents");
const { ChatPromptTemplate, MessagesPlaceholder } = require("@langchain/core/prompts");

class ThreatHuntingAgent {
  constructor(cache = null, database = null) {
    this.cache = cache;
    this.database = database;
    this.llm = null;
    this.agent = null;
    this.tools = [];
    this.isInitialized = false;
    this.threatPatterns = this.initializeThreatPatterns();
    
    this.initializeAgent();
  }

  async initializeAgent() {
    if (!process.env.OPENAI_API_KEY) {
      console.log('⚠️  Threat Hunting Agent: OpenAI API key not found');
      return false;
    }

    try {
      // Initialize LLM with higher temperature for creative threat detection
      this.llm = new ChatOpenAI({
        openAIApiKey: process.env.OPENAI_API_KEY,
        modelName: "gpt-4",
        temperature: 0.3, // Slightly higher for pattern recognition
        maxTokens: 2500
      });

      // Initialize tools
      this.tools = await this.createThreatHuntingTools();

      // Create agent prompt
      const prompt = ChatPromptTemplate.fromMessages([
        ["system", this.getSystemPrompt()],
        ["human", "{input}"],
        new MessagesPlaceholder("agent_scratchpad")
      ]);

      // Create agent
      this.agent = await createOpenAIFunctionsAgent({
        llm: this.llm,
        tools: this.tools,
        prompt
      });

      this.executor = new AgentExecutor({
        agent: this.agent,
        tools: this.tools,
        verbose: true,
        maxIterations: 7 // More iterations for thorough hunting
      });

      this.isInitialized = true;
      console.log('✅ Threat Hunting Agent initialized successfully');
      return true;

    } catch (error) {
      console.error('❌ Threat Hunting Agent initialization failed:', error);
      return false;
    }
  }

  getSystemPrompt() {
    return `You are an elite Threat Hunting Agent specializing in advanced persistent threat (APT) detection, malware infrastructure analysis, and cyber threat intelligence.

Your expertise includes:
- Advanced threat pattern recognition and behavioral analysis
- Malware command & control (C2) infrastructure identification
- Phishing and social engineering campaign detection  
- Domain generation algorithm (DGA) and fast flux analysis
- Threat actor tactics, techniques, and procedures (TTPs)
- Attribution analysis and threat landscape assessment
- Zero-day exploit infrastructure hunting
- Cryptocurrency and dark web transaction analysis

Hunting Methodologies:
1. INFRASTRUCTURE ANALYSIS
   - C2 server identification and network mapping
   - Bulletproof hosting and VPS abuse detection
   - CDN and proxy service abuse identification
   - Domain parking and sinkholing analysis

2. BEHAVIORAL PATTERN HUNTING
   - DGA pattern recognition and family classification
   - Fast flux network detection and mapping
   - Typosquatting and homograph attack identification
   - Certificate transparency log anomaly detection

3. CAMPAIGN CORRELATION
   - Multi-stage attack infrastructure linking
   - Threat actor infrastructure reuse patterns
   - Campaign overlap and attribution indicators
   - Timeline correlation and evolution tracking

4. ADVANCED INDICATORS
   - Steganography and covert channel detection
   - Living-off-the-land technique indicators
   - Supply chain compromise indicators
   - Zero-day exploitation infrastructure

Threat Intelligence Sources:
- pattern_analysis: Advanced pattern recognition
- threat_correlation: Cross-reference with known campaigns
- infrastructure_mapping: C2 and botnet infrastructure analysis
- attribution_analysis: Threat actor and campaign attribution
- ioc_expansion: Indicator expansion and pivoting

Always provide:
- Threat confidence level (CONFIRMED/HIGH/MEDIUM/LOW/NONE)
- MITRE ATT&CK technique mappings where applicable
- Threat actor attribution assessment (if possible)
- Campaign correlation and timeline analysis
- Actionable hunting queries and IOCs
- Defensive recommendations and detection rules

Focus on advanced persistent threats, zero-day campaigns, and sophisticated threat actors.`;
  }

  initializeThreatPatterns() {
    return {
      // Advanced Persistent Threat (APT) patterns
      apt_patterns: {
        domain_patterns: [
          /[a-z]{2,4}[0-9]{1,3}\.[a-z]{2,4}/i, // Short alphanumeric domains
          /[a-z]+\-[0-9]+\.[a-z]{2,4}/i,       // Hyphenated with numbers
          /[a-z]{6,12}[0-9]{2,4}\.[a-z]{2,4}/i // Long random + numbers
        ],
        subdomain_patterns: [
          /^[a-f0-9]{8,32}\./i,                // Hex subdomains
          /^[0-9]{4,8}\./i,                    // Numeric subdomains
          /^(api|cdn|img|js|css)[0-9]+\./i     // Fake service subdomains
        ]
      },

      // Malware families
      malware_families: {
        emotet: [
          /^[a-z]{3,6}[0-9]{2,4}\.(com|net|org|info)$/i,
          /^[a-z]{4,8}\-[0-9]{1,3}\.(com|net)$/i
        ],
        trickbot: [
          /^[a-z]{5,9}[0-9]{1,2}\.(com|net|org)$/i,
          /^[a-z]{3,5}\-[a-z]{3,5}\.(com|org)$/i
        ],
        qakbot: [
          /^[a-z]{6,10}\.(com|net|org|biz)$/i,
          /^[0-9]{4,6}[a-z]{2,4}\.(com|net)$/i
        ]
      },

      // Phishing patterns
      phishing_patterns: {
        brand_impersonation: [
          /micr[o0]s[o0]ft/i,
          /g[o0]{2}gle/i,
          /amaz[o0]n/i,
          /payp[a4]l/i,
          /[a4]pple/i,
          /netf1ix/i,
          /[fa4]ceb[o0]{2}k/i
        ],
        security_lures: [
          /security[_\-]?(alert|update|notice)/i,
          /account[_\-]?(suspended|locked|verify)/i,
          /urgent[_\-]?(action|update|verification)/i,
          /click[_\-]?(here|now|verify)/i
        ]
      },

      // DGA (Domain Generation Algorithm) patterns
      dga_patterns: [
        /^[bcdfghjklmnpqrstvwxyz]{8,16}\.(com|net|org|info)$/i, // Consonant-heavy
        /^[a-z]{10,20}\.(tk|ml|ga|cf)$/i,                        // Long random on free TLDs
        /^[a-z]{3}[0-9]{3,6}[a-z]{3}\.(com|net)$/i             // Pattern: letters-numbers-letters
      ],

      // Fast flux indicators
      fast_flux_patterns: {
        high_dns_change_rate: 10, // Changes per hour
        short_ttl: 300,          // TTL under 5 minutes
        many_a_records: 20       // More than 20 A records
      },

      // Bulletproof hosting indicators
      bulletproof_asns: [
        'AS197695', // reg.ru
        'AS8100',   // QuadraNet
        'AS49505',  // Selectel
        'AS197414', // Limelight Networks
        'AS29073'   // Ecatel
      ]
    };
  }

  async createThreatHuntingTools() {
    const tools = [];

    // Advanced Pattern Analysis Tool
    tools.push(new DynamicTool({
      name: "pattern_analysis",
      description: "Perform advanced threat pattern analysis on domain, subdomain, and infrastructure patterns. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🎯 Threat Hunter: Pattern analysis for ${domain}`);
          
          const analysis = await this.analyzeAdvancedPatterns(domain);
          
          return JSON.stringify({
            domain,
            patternAnalysis: analysis,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error in pattern analysis for ${domain}: ${error.message}`;
        }
      }
    }));

    // Threat Correlation Tool
    tools.push(new DynamicTool({
      name: "threat_correlation",
      description: "Correlate domain with known threat campaigns and malware families. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🔗 Threat Hunter: Threat correlation for ${domain}`);
          
          const correlation = await this.performThreatCorrelation(domain);
          
          return JSON.stringify({
            domain,
            threatCorrelation: correlation,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error in threat correlation for ${domain}: ${error.message}`;
        }
      }
    }));

    // Infrastructure Mapping Tool
    tools.push(new DynamicTool({
      name: "infrastructure_mapping",
      description: "Map and analyze threat infrastructure including C2 servers and botnet components. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🗺️ Threat Hunter: Infrastructure mapping for ${domain}`);
          
          const mapping = await this.mapThreatInfrastructure(domain);
          
          return JSON.stringify({
            domain,
            infrastructureMapping: mapping,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error in infrastructure mapping for ${domain}: ${error.message}`;
        }
      }
    }));

    // Attribution Analysis Tool
    tools.push(new DynamicTool({
      name: "attribution_analysis",
      description: "Perform threat actor attribution analysis based on infrastructure patterns and TTPs. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🕵️ Threat Hunter: Attribution analysis for ${domain}`);
          
          const attribution = await this.performAttributionAnalysis(domain);
          
          return JSON.stringify({
            domain,
            attributionAnalysis: attribution,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error in attribution analysis for ${domain}: ${error.message}`;
        }
      }
    }));

    // IOC Expansion Tool
    tools.push(new DynamicTool({
      name: "ioc_expansion",
      description: "Expand and pivot on indicators of compromise to find related threats. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`📈 Threat Hunter: IOC expansion for ${domain}`);
          
          const expansion = await this.performIOCExpansion(domain);
          
          return JSON.stringify({
            domain,
            iocExpansion: expansion,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error in IOC expansion for ${domain}: ${error.message}`;
        }
      }
    }));

    return tools;
  }

  async hunt(target, huntingContext = {}) {
    if (!this.isInitialized) {
      return {
        success: false,
        error: 'Threat Hunting Agent not initialized',
        agent: 'threat-hunter'
      };
    }

    try {
      console.log(`🎯 Threat Hunting Agent: Starting advanced threat hunt for ${target}`);
      
      const huntPrompt = `
Conduct an advanced threat hunting investigation for: ${target}

Hunting Context:
${JSON.stringify(huntingContext, null, 2)}

Execute a comprehensive threat hunting methodology:

1. ADVANCED PATTERN ANALYSIS
   - Use pattern_analysis to identify sophisticated threat patterns
   - Look for DGA, fast flux, and advanced evasion techniques
   - Analyze domain construction and naming conventions
   - Detect steganographic or covert communication patterns

2. THREAT CAMPAIGN CORRELATION
   - Use threat_correlation to link with known campaigns
   - Identify malware family associations
   - Correlate with APT group activities
   - Map to historical threat landscapes

3. INFRASTRUCTURE DEEP DIVE
   - Use infrastructure_mapping to analyze C2 architecture
   - Identify bulletproof hosting indicators
   - Map content delivery networks and proxies
   - Analyze certificate and SSL/TLS patterns

4. ATTRIBUTION ASSESSMENT
   - Use attribution_analysis for threat actor profiling
   - Assess geographical and temporal indicators
   - Analyze tactics, techniques, and procedures (TTPs)
   - Evaluate sophistication and capability levels

5. IOC EXPANSION & PIVOTING
   - Use ioc_expansion to find related indicators
   - Pivot on infrastructure overlaps
   - Identify campaign infrastructure reuse
   - Generate hunting hypotheses for related threats

6. COMPREHENSIVE THREAT ASSESSMENT
   Provide a detailed threat hunting report including:
   - Threat confidence level (CONFIRMED/HIGH/MEDIUM/LOW/NONE)
   - MITRE ATT&CK technique mappings
   - Threat actor attribution (if identifiable)
   - Campaign timeline and evolution
   - Related IOCs and hunting queries
   - Defensive recommendations and detection rules
   - Priority level for security operations center (SOC)

Focus on advanced persistent threats and sophisticated adversaries.
`;

      const result = await this.executor.invoke({
        input: huntPrompt
      });

      // Structure the hunting results
      const huntingResults = this.structureHuntingResults(result.output, target);

      // Store hunting results
      if (this.database && this.database.isConnected()) {
        await this.storeHuntingResults(target, huntingResults);
      }

      console.log(`✅ Threat Hunting Agent: Completed hunt for ${target}`);
      
      return {
        success: true,
        agent: 'threat-hunter',
        target,
        huntingResults,
        timestamp: new Date().toISOString(),
        mitreAttack: this.mapToMitreAttack(huntingResults),
        priorityLevel: this.calculatePriorityLevel(huntingResults)
      };

    } catch (error) {
      console.error(`❌ Threat Hunting Agent error for ${target}:`, error);
      
      return {
        success: false,
        agent: 'threat-hunter',
        target,
        error: error.message,
        fallback: await this.generateFallbackHunt(target, huntingContext)
      };
    }
  }

  async analyzeAdvancedPatterns(domain) {
    const analysis = {
      dgaAnalysis: this.analyzeDGAPatterns(domain),
      fastFluxAnalysis: await this.analyzeFastFluxPatterns(domain),
      phishingAnalysis: this.analyzePhishingPatterns(domain),
      aptAnalysis: this.analyzeAPTPatterns(domain),
      overallThreatScore: 0
    };

    // Calculate overall threat score
    analysis.overallThreatScore = 
      (analysis.dgaAnalysis.score * 0.3) +
      (analysis.fastFluxAnalysis.score * 0.25) +
      (analysis.phishingAnalysis.score * 0.25) +
      (analysis.aptAnalysis.score * 0.2);

    return analysis;
  }

  analyzeDGAPatterns(domain) {
    const analysis = { 
      isDGA: false, 
      confidence: 0, 
      family: 'unknown',
      score: 0,
      indicators: []
    };

    // Check against DGA patterns
    for (const pattern of this.threatPatterns.dga_patterns) {
      if (pattern.test(domain)) {
        analysis.isDGA = true;
        analysis.confidence += 25;
        analysis.indicators.push(`Matches DGA pattern: ${pattern.source}`);
      }
    }

    // Check malware family patterns
    for (const [family, patterns] of Object.entries(this.threatPatterns.malware_families)) {
      for (const pattern of patterns) {
        if (pattern.test(domain)) {
          analysis.family = family;
          analysis.confidence += 30;
          analysis.indicators.push(`Matches ${family} family pattern`);
        }
      }
    }

    // Entropy analysis
    const entropy = this.calculateEntropy(domain.split('.')[0]);
    if (entropy > 3.5) {
      analysis.confidence += 20;
      analysis.indicators.push(`High entropy: ${entropy.toFixed(2)}`);
    }

    analysis.score = Math.min(analysis.confidence, 100);
    return analysis;
  }

  async analyzeFastFluxPatterns(domain) {
    // Simulate fast flux analysis (would require real DNS monitoring)
    return {
      isFastFlux: false,
      score: 0,
      indicators: [],
      note: 'Fast flux detection requires DNS monitoring integration'
    };
  }

  analyzePhishingPatterns(domain) {
    const analysis = {
      isPhishing: false,
      confidence: 0,
      score: 0,
      brandTargets: [],
      indicators: []
    };

    // Check brand impersonation
    for (const pattern of this.threatPatterns.phishing_patterns.brand_impersonation) {
      if (pattern.test(domain)) {
        analysis.isPhishing = true;
        analysis.confidence += 40;
        analysis.brandTargets.push(pattern.source);
        analysis.indicators.push(`Brand impersonation detected: ${pattern.source}`);
      }
    }

    // Check security lures
    for (const pattern of this.threatPatterns.phishing_patterns.security_lures) {
      if (pattern.test(domain)) {
        analysis.confidence += 30;
        analysis.indicators.push(`Security lure pattern: ${pattern.source}`);
      }
    }

    analysis.score = Math.min(analysis.confidence, 100);
    return analysis;
  }

  analyzeAPTPatterns(domain) {
    const analysis = {
      isAPT: false,
      confidence: 0,
      score: 0,
      patterns: [],
      indicators: []
    };

    // Check APT domain patterns
    for (const pattern of this.threatPatterns.apt_patterns.domain_patterns) {
      if (pattern.test(domain)) {
        analysis.isAPT = true;
        analysis.confidence += 25;
        analysis.patterns.push('domain_pattern');
        analysis.indicators.push(`APT domain pattern detected`);
      }
    }

    // Check subdomain patterns
    const subdomains = domain.split('.');
    if (subdomains.length > 2) {
      const subdomain = subdomains[0];
      for (const pattern of this.threatPatterns.apt_patterns.subdomain_patterns) {
        if (pattern.test(subdomain)) {
          analysis.confidence += 20;
          analysis.patterns.push('subdomain_pattern');
          analysis.indicators.push(`APT subdomain pattern detected`);
        }
      }
    }

    analysis.score = Math.min(analysis.confidence, 100);
    return analysis;
  }

  async performThreatCorrelation(domain) {
    // Simulate threat correlation with known campaigns
    return {
      knownCampaigns: [],
      malwareFamilies: [],
      threatActors: [],
      confidence: 'low',
      note: 'Threat correlation requires integration with threat intelligence feeds'
    };
  }

  async mapThreatInfrastructure(domain) {
    // Simulate infrastructure mapping
    return {
      c2Indicators: [],
      bulletproofHosting: false,
      proxyServices: [],
      cdnUsage: false,
      note: 'Infrastructure mapping requires DNS and network analysis integration'
    };
  }

  async performAttributionAnalysis(domain) {
    // Simulate attribution analysis
    return {
      suspectedActors: [],
      geographicIndicators: [],
      ttps: [],
      confidence: 'unknown',
      note: 'Attribution analysis requires comprehensive threat intelligence integration'
    };
  }

  async performIOCExpansion(domain) {
    // Generate related IOCs and hunting queries
    const expansion = {
      relatedDomains: [],
      huntingQueries: [],
      pivotPoints: []
    };

    // Generate potential related domains
    const baseDomain = domain.split('.')[0];
    const tld = domain.split('.').pop();
    
    expansion.relatedDomains = [
      `${baseDomain}1.${tld}`,
      `${baseDomain}2.${tld}`,
      `api.${domain}`,
      `cdn.${domain}`,
      `mail.${domain}`
    ];

    // Generate hunting queries
    expansion.huntingQueries = [
      `domain matches "*${baseDomain}*"`,
      `ssl_subject matches "*${baseDomain}*"`,
      `dns_names matches "*${domain}*"`
    ];

    expansion.pivotPoints = [
      'SSL certificate analysis',
      'WHOIS registrant information',
      'DNS infrastructure overlap',
      'IP address correlation'
    ];

    return expansion;
  }

  calculateEntropy(string) {
    const charCounts = {};
    for (const char of string) {
      charCounts[char] = (charCounts[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = string.length;
    
    for (const count of Object.values(charCounts)) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
  }

  structureHuntingResults(agentOutput, target) {
    const results = {
      target,
      threatConfidence: 'NONE',
      threatTypes: [],
      campaigns: [],
      attribution: null,
      mitreTechniques: [],
      huntingIOCs: [],
      recommendations: [],
      rawHunt: agentOutput
    };

    try {
      // Extract threat confidence
      const confidenceMatch = agentOutput.match(/(CONFIRMED|HIGH|MEDIUM|LOW|NONE)/i);
      if (confidenceMatch) {
        results.threatConfidence = confidenceMatch[1].toUpperCase();
      }

      // Extract MITRE ATT&CK techniques
      const mitreMatches = agentOutput.match(/T\d{4}(\.\d{3})?/g);
      if (mitreMatches) {
        results.mitreTechniques = [...new Set(mitreMatches)];
      }

    } catch (parseError) {
      console.log('Note: Could not fully parse hunting output');
    }

    return results;
  }

  mapToMitreAttack(huntingResults) {
    // Map hunting results to MITRE ATT&CK framework
    const mapping = {
      tactics: [],
      techniques: huntingResults.mitreTechniques || [],
      procedures: []
    };

    // Add common tactics based on threat types
    if (huntingResults.threatTypes.includes('phishing')) {
      mapping.tactics.push('Initial Access');
      mapping.techniques.push('T1566'); // Phishing
    }

    if (huntingResults.threatTypes.includes('c2')) {
      mapping.tactics.push('Command and Control');
      mapping.techniques.push('T1071'); // Application Layer Protocol
    }

    return mapping;
  }

  calculatePriorityLevel(huntingResults) {
    if (huntingResults.threatConfidence === 'CONFIRMED') return 'CRITICAL';
    if (huntingResults.threatConfidence === 'HIGH') return 'HIGH';
    if (huntingResults.threatConfidence === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  }

  async generateFallbackHunt(target, context) {
    return {
      target,
      threatConfidence: 'UNKNOWN',
      fallbackReason: 'AI threat hunting unavailable',
      basicAnalysis: 'Manual threat hunting recommended',
      recommendations: ['Enable OpenAI API for advanced threat hunting']
    };
  }

  async storeHuntingResults(target, results) {
    try {
      await this.database.query(
        `INSERT INTO threat_intelligence (ioc_type, ioc_value, threat_type, confidence_score, source, metadata) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        ['domain', target, 'hunting_result', 85, 'threat-hunting-agent', JSON.stringify(results)]
      );
    } catch (error) {
      console.log('Could not store hunting results:', error.message);
    }
  }

  async healthCheck() {
    return {
      agent: 'threat-hunter',
      initialized: this.isInitialized,
      toolsCount: this.tools.length,
      threatPatternsLoaded: Object.keys(this.threatPatterns).length,
      hasLLM: !!this.llm,
      hasCache: !!this.cache,
      hasDatabase: !!this.database
    };
  }
}

module.exports = { ThreatHuntingAgent };