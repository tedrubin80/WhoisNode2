/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── ai/
│   ├── agents/
│   │   ├── domain-analyst.js        (this file)
│   │   ├── threat-hunter.js
│   │   ├── risk-assessor.js
│   │   └── report-generator.js
│   ├── chains/
│   │   ├── domain-analysis-chain.js
│   │   └── threat-detection-chain.js
│   ├── tools/
│   │   ├── whois-tool.js
│   │   └── threat-intel-tool.js
│   └── orchestrator.js

FILE LOCATION: /ai/agents/domain-analyst.js
*/

// Domain Analysis Agent - Advanced AI-Powered Domain Intelligence
// FILE: /ai/agents/domain-analyst.js

const { ChatOpenAI } = require("@langchain/openai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { LLMChain } = require("langchain/chains");
const { DynamicTool } = require("@langchain/core/tools");
const { AgentExecutor, createOpenAIFunctionsAgent } = require("langchain/agents");
const { ChatPromptTemplate, MessagesPlaceholder } = require("@langchain/core/prompts");

class DomainAnalysisAgent {
  constructor(cache = null, database = null) {
    this.cache = cache;
    this.database = database;
    this.llm = null;
    this.agent = null;
    this.tools = [];
    this.isInitialized = false;
    
    this.initializeAgent();
  }

  async initializeAgent() {
    if (!process.env.OPENAI_API_KEY) {
      console.log('⚠️  Domain Analysis Agent: OpenAI API key not found');
      return false;
    }

    try {
      // Initialize LLM
      this.llm = new ChatOpenAI({
        openAIApiKey: process.env.OPENAI_API_KEY,
        modelName: "gpt-4",
        temperature: 0.1, // Low temperature for factual analysis
        maxTokens: 2000
      });

      // Initialize tools
      this.tools = await this.createAnalysisTools();

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
        maxIterations: 5
      });

      this.isInitialized = true;
      console.log('✅ Domain Analysis Agent initialized successfully');
      return true;

    } catch (error) {
      console.error('❌ Domain Analysis Agent initialization failed:', error);
      return false;
    }
  }

  getSystemPrompt() {
    return `You are an expert Domain Analysis Agent specializing in cybersecurity intelligence and domain reputation analysis.

Your expertise includes:
- WHOIS data interpretation and anomaly detection
- DNS infrastructure analysis and security implications
- Domain registration pattern analysis
- Privacy protection service identification
- Registrar reputation and trustworthiness assessment
- Temporal analysis of domain lifecycle
- Cross-reference analysis with threat intelligence

Analysis Framework:
1. REGISTRATION INTELLIGENCE
   - Registrar reputation and compliance history
   - Registration date anomalies and patterns
   - Contact information authenticity assessment
   - Privacy protection service analysis

2. INFRASTRUCTURE ASSESSMENT  
   - DNS configuration security analysis
   - IP address reputation and geolocation assessment
   - Name server infrastructure evaluation
   - Email infrastructure (MX records) analysis

3. BEHAVIORAL PATTERNS
   - Domain age vs. activity patterns
   - Subdomain proliferation analysis
   - Content delivery network usage patterns
   - Certificate authority and SSL/TLS configuration

4. RISK INDICATORS
   - Fast flux DNS patterns
   - Bulletproof hosting indicators
   - Domain generation algorithm (DGA) characteristics
   - Typosquatting and brand impersonation indicators

Tools Available:
- whois_lookup: Retrieve and analyze WHOIS data
- dns_analysis: Perform comprehensive DNS record analysis  
- historical_lookup: Check domain history and changes
- threat_intelligence: Query threat intelligence databases

Always provide:
- Confidence score (1-100)
- Key findings with evidence
- Risk assessment with specific indicators
- Actionable recommendations
- Technical details for security professionals

Maintain objectivity and base all assessments on observable data and established threat intelligence indicators.`;
  }

  async createAnalysisTools() {
    const tools = [];

    // WHOIS Analysis Tool
    tools.push(new DynamicTool({
      name: "whois_lookup",
      description: "Retrieve and analyze WHOIS data for a domain. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🔍 Domain Agent: Analyzing WHOIS for ${domain}`);
          
          // Use existing WHOIS analysis from main server
          if (global.performDomainAnalysis) {
            const analysis = await global.performDomainAnalysis(domain);
            return JSON.stringify({
              domain,
              whoisData: analysis.whoisData,
              registrarInfo: analysis.registrarInfo,
              privacyAnalysis: analysis.privacyAnalysis,
              summary: analysis.summary
            }, null, 2);
          } else {
            return `WHOIS analysis tool not available for ${domain}`;
          }
        } catch (error) {
          return `Error analyzing WHOIS for ${domain}: ${error.message}`;
        }
      }
    }));

    // DNS Analysis Tool
    tools.push(new DynamicTool({
      name: "dns_analysis", 
      description: "Perform comprehensive DNS record analysis. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🌐 Domain Agent: Analyzing DNS for ${domain}`);
          
          if (global.getDNSRecords) {
            const dnsData = await global.getDNSRecords(domain);
            
            // Enhanced DNS analysis
            const analysis = this.analyzeDNSPatterns(dnsData, domain);
            
            return JSON.stringify({
              domain,
              dnsRecords: dnsData,
              securityAnalysis: analysis,
              timestamp: new Date().toISOString()
            }, null, 2);
          } else {
            return `DNS analysis tool not available for ${domain}`;
          }
        } catch (error) {
          return `Error analyzing DNS for ${domain}: ${error.message}`;
        }
      }
    }));

    // Historical Domain Lookup Tool
    tools.push(new DynamicTool({
      name: "historical_lookup",
      description: "Check domain registration history and changes. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`📚 Domain Agent: Historical lookup for ${domain}`);
          
          // Check cache for historical data
          const cacheKey = `historical:${domain}`;
          if (this.cache) {
            const cached = this.cache.get(cacheKey);
            if (cached) {
              return JSON.stringify(cached, null, 2);
            }
          }

          // Simulate historical analysis (in real implementation, would use archives)
          const historical = await this.generateHistoricalAnalysis(domain);
          
          if (this.cache) {
            this.cache.set(cacheKey, historical, 7200); // 2 hour cache
          }
          
          return JSON.stringify(historical, null, 2);
        } catch (error) {
          return `Error retrieving historical data for ${domain}: ${error.message}`;
        }
      }
    }));

    // Threat Intelligence Tool
    tools.push(new DynamicTool({
      name: "threat_intelligence",
      description: "Query threat intelligence databases for domain reputation. Input should be a domain name.",
      func: async (domain) => {
        try {
          console.log(`🛡️ Domain Agent: Threat intel lookup for ${domain}`);
          
          // Use existing blacklist checker if available
          if (global.blacklistChecker) {
            const emails = [`info@${domain}`, `admin@${domain}`];
            const ips = []; // Would be populated from DNS lookup
            
            const blacklistResults = await global.blacklistChecker.checkEmailAndIPs(emails, ips);
            
            return JSON.stringify({
              domain,
              threatIntelligence: blacklistResults,
              reputation: this.calculateDomainReputation(blacklistResults),
              timestamp: new Date().toISOString()
            }, null, 2);
          } else {
            return `Threat intelligence not available for ${domain}`;
          }
        } catch (error) {
          return `Error querying threat intelligence for ${domain}: ${error.message}`;
        }
      }
    }));

    return tools;
  }

  async analyze(domain, context = {}) {
    if (!this.isInitialized) {
      return {
        success: false,
        error: 'Domain Analysis Agent not initialized',
        agent: 'domain-analyst'
      };
    }

    try {
      console.log(`🤖 Domain Analysis Agent: Starting comprehensive analysis for ${domain}`);
      
      const analysisPrompt = `
Conduct a comprehensive cybersecurity-focused domain analysis for: ${domain}

Context provided:
${JSON.stringify(context, null, 2)}

Please perform the following analysis steps:

1. REGISTRATION ANALYSIS
   - Use whois_lookup to gather registration data
   - Assess registrar reputation and compliance
   - Analyze registration patterns and anomalies
   - Evaluate contact information authenticity

2. INFRASTRUCTURE ASSESSMENT
   - Use dns_analysis to examine DNS configuration
   - Assess IP address reputation and geolocation
   - Evaluate name server infrastructure
   - Analyze email infrastructure security

3. HISTORICAL CONTEXT
   - Use historical_lookup to understand domain evolution
   - Identify significant changes or red flags
   - Assess domain lifecycle patterns

4. THREAT INTELLIGENCE
   - Use threat_intelligence to check reputation
   - Cross-reference with known threat indicators
   - Assess current threat landscape positioning

5. COMPREHENSIVE ASSESSMENT
   Provide a detailed analysis including:
   - Overall security posture (SAFE/CAUTION/WARNING/DANGER)
   - Confidence score (1-100)
   - Key security findings with evidence
   - Specific risk indicators identified
   - Technical recommendations for security teams
   - Suggested monitoring or investigation actions

Focus on actionable intelligence for cybersecurity professionals.
`;

      const result = await this.executor.invoke({
        input: analysisPrompt
      });

      // Parse and structure the agent's response
      const structuredResult = this.structureAnalysisResult(result.output, domain);

      // Store result if database is available
      if (this.database && this.database.isConnected()) {
        await this.storeAnalysisResult(domain, structuredResult);
      }

      console.log(`✅ Domain Analysis Agent: Completed analysis for ${domain}`);
      
      return {
        success: true,
        agent: 'domain-analyst',
        domain,
        analysis: structuredResult,
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - Date.now() // Would be calculated properly
      };

    } catch (error) {
      console.error(`❌ Domain Analysis Agent error for ${domain}:`, error);
      
      return {
        success: false,
        agent: 'domain-analyst',
        domain,
        error: error.message,
        fallback: await this.generateFallbackAnalysis(domain, context)
      };
    }
  }

  structureAnalysisResult(agentOutput, domain) {
    // Parse the agent's natural language output into structured data
    const analysis = {
      domain,
      overallAssessment: 'UNKNOWN',
      confidenceScore: 0,
      keyFindings: [],
      riskIndicators: [],
      recommendations: [],
      technicalDetails: {},
      rawAnalysis: agentOutput
    };

    try {
      // Extract security posture
      const postureMatch = agentOutput.match(/(SAFE|CAUTION|WARNING|DANGER)/i);
      if (postureMatch) {
        analysis.overallAssessment = postureMatch[1].toUpperCase();
      }

      // Extract confidence score
      const confidenceMatch = agentOutput.match(/confidence[:\s]+(\d+)/i);
      if (confidenceMatch) {
        analysis.confidenceScore = parseInt(confidenceMatch[1]);
      }

      // Extract key findings (basic pattern matching)
      const findingsSection = agentOutput.match(/key findings?[:\s]+(.*?)(?=recommendations?|risk|$)/is);
      if (findingsSection) {
        analysis.keyFindings = findingsSection[1]
          .split(/[•\-\n]/)
          .map(f => f.trim())
          .filter(f => f.length > 10);
      }

      // Extract recommendations
      const recommendationsSection = agentOutput.match(/recommendations?[:\s]+(.*?)$/is);
      if (recommendationsSection) {
        analysis.recommendations = recommendationsSection[1]
          .split(/[•\-\n]/)
          .map(r => r.trim())
          .filter(r => r.length > 10);
      }

    } catch (parseError) {
      console.log('Note: Could not fully parse agent output, returning raw analysis');
    }

    return analysis;
  }

  analyzeDNSPatterns(dnsData, domain) {
    const analysis = {
      securityScore: 100,
      issues: [],
      observations: []
    };

    // Check for suspicious DNS patterns
    if (dnsData.A && dnsData.A.length > 10) {
      analysis.issues.push('Unusually high number of A records - possible fast flux');
      analysis.securityScore -= 20;
    }

    if (dnsData.NS && dnsData.NS.length < 2) {
      analysis.issues.push('Insufficient name server redundancy');
      analysis.securityScore -= 10;
    }

    if (dnsData.MX && dnsData.MX.length === 0) {
      analysis.observations.push('No MX records - domain may not handle email');
    }

    // Check for security-related TXT records
    if (dnsData.TXT) {
      const hasSpf = dnsData.TXT.some(record => 
        record.join('').toLowerCase().includes('spf'));
      const hasDmarc = dnsData.TXT.some(record => 
        record.join('').toLowerCase().includes('dmarc'));
      
      if (!hasSpf) {
        analysis.observations.push('No SPF record found - email security concern');
        analysis.securityScore -= 5;
      }
      
      if (!hasDmarc) {
        analysis.observations.push('No DMARC record found - email authentication concern');
        analysis.securityScore -= 5;
      }
    }

    return analysis;
  }

  calculateDomainReputation(blacklistResults) {
    if (!blacklistResults || !blacklistResults.summary) {
      return { score: 50, level: 'unknown', reason: 'Insufficient data' };
    }

    let score = 100;
    const issues = [];

    if (blacklistResults.summary.blacklistedEmails > 0) {
      score -= 30;
      issues.push(`${blacklistResults.summary.blacklistedEmails} blacklisted emails`);
    }

    if (blacklistResults.summary.blacklistedIPs > 0) {
      score -= 40;
      issues.push(`${blacklistResults.summary.blacklistedIPs} blacklisted IPs`);
    }

    if (blacklistResults.summary.privacyEmails > 0) {
      score -= 10;
      issues.push('Privacy protection detected');
    }

    let level = 'good';
    if (score < 30) level = 'poor';
    else if (score < 60) level = 'concerning';
    else if (score < 80) level = 'moderate';

    return {
      score: Math.max(score, 0),
      level,
      issues,
      overallRisk: blacklistResults.summary.overallRisk
    };
  }

  async generateHistoricalAnalysis(domain) {
    // Simplified historical analysis - in production would use actual historical data
    return {
      domain,
      registrationHistory: {
        changes: 0,
        suspiciousChanges: false,
        registrarChanges: 0
      },
      dnsHistory: {
        ipChanges: 'unknown',
        nsChanges: 'unknown',
        suspiciousPatterns: false
      },
      contentHistory: {
        hasArchive: false,
        suspiciousContent: false
      },
      confidence: 'low',
      note: 'Historical analysis requires integration with archive services'
    };
  }

  async generateFallbackAnalysis(domain, context) {
    return {
      domain,
      overallAssessment: 'UNKNOWN',
      confidenceScore: 30,
      keyFindings: ['AI analysis unavailable - using fallback assessment'],
      recommendations: ['Manual review recommended', 'Enable OpenAI API for enhanced analysis'],
      fallbackReason: 'AI agent execution failed'
    };
  }

  async storeAnalysisResult(domain, analysis) {
    try {
      await this.database.query(
        `INSERT INTO domain_analyses (domain, ai_analysis, analyzed_by, created_at) 
         VALUES ($1, $2, $3, NOW())`,
        [domain, JSON.stringify(analysis), 'domain-analyst-agent']
      );
    } catch (error) {
      console.log('Could not store domain analysis result:', error.message);
    }
  }

  // Health check for the agent
  async healthCheck() {
    return {
      agent: 'domain-analyst',
      initialized: this.isInitialized,
      toolsCount: this.tools.length,
      hasLLM: !!this.llm,
      hasCache: !!this.cache,
      hasDatabase: !!this.database
    };
  }
}

module.exports = { DomainAnalysisAgent };