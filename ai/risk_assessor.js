/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── ai/
│   ├── agents/
│   │   ├── domain-analyst.js        
│   │   ├── threat-hunter.js         
│   │   ├── risk-assessor.js         (this file)
│   │   └── report-generator.js

FILE LOCATION: /ai/agents/risk-assessor.js
*/

// Risk Assessment Agent - Advanced AI-Powered Risk Analysis
// FILE: /ai/agents/risk-assessor.js

const { ChatOpenAI } = require("@langchain/openai");
const { PromptTemplate } = require("@langchain/core/prompts");
const { LLMChain } = require("langchain/chains");
const { DynamicTool } = require("@langchain/core/tools");
const { AgentExecutor, createOpenAIFunctionsAgent } = require("langchain/agents");
const { ChatPromptTemplate, MessagesPlaceholder } = require("@langchain/core/prompts");

class RiskAssessmentAgent {
  constructor(cache = null, database = null) {
    this.cache = cache;
    this.database = database;
    this.llm = null;
    this.agent = null;
    this.tools = [];
    this.isInitialized = false;
    this.riskMatrix = this.initializeRiskMatrix();
    
    this.initializeAgent();
  }

  async initializeAgent() {
    if (!process.env.OPENAI_API_KEY) {
      console.log('⚠️  Risk Assessment Agent: OpenAI API key not found');
      return false;
    }

    try {
      // Initialize LLM with balanced temperature for risk assessment
      this.llm = new ChatOpenAI({
        openAIApiKey: process.env.OPENAI_API_KEY,
        modelName: "gpt-4",
        temperature: 0.2, // Balanced for analytical reasoning
        maxTokens: 3000
      });

      // Initialize tools
      this.tools = await this.createRiskAssessmentTools();

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
        maxIterations: 6
      });

      this.isInitialized = true;
      console.log('✅ Risk Assessment Agent initialized successfully');
      return true;

    } catch (error) {
      console.error('❌ Risk Assessment Agent initialization failed:', error);
      return false;
    }
  }

  getSystemPrompt() {
    return `You are an expert Risk Assessment Agent specializing in cybersecurity risk quantification, business impact analysis, and strategic security decision support.

Your expertise includes:
- Quantitative and qualitative cybersecurity risk assessment
- Business impact analysis and financial risk modeling
- Threat likelihood estimation and vulnerability assessment
- Risk appetite and tolerance framework development
- Regulatory compliance and legal risk evaluation
- Third-party and supply chain risk assessment
- Incident response and business continuity planning
- Risk communication and executive reporting

Risk Assessment Framework:
1. THREAT LANDSCAPE ANALYSIS
   - Current threat environment assessment
   - Threat actor capability and intent evaluation
   - Attack vector and technique likelihood
   - Emerging threat trend analysis

2. VULNERABILITY ASSESSMENT
   - Technical vulnerability identification
   - Configuration and operational weaknesses
   - Human factor and process vulnerabilities
   - Supply chain and third-party risks

3. IMPACT ANALYSIS
   - Financial impact quantification (direct and indirect)
   - Operational disruption assessment
   - Reputational and brand damage evaluation
   - Regulatory and legal consequence analysis
   - Customer and stakeholder impact assessment

4. RISK QUANTIFICATION
   - Probability and impact matrix development
   - Monte Carlo simulation and scenario modeling
   - Risk exposure calculation and trending
   - Cost-benefit analysis for risk treatments

5. CONTROL EFFECTIVENESS
   - Current security control assessment
   - Control gap analysis and recommendations
   - Compensating control identification
   - Risk treatment option evaluation

Risk Assessment Tools Available:
- threat_likelihood: Assess threat probability and actor capabilities
- vulnerability_analysis: Evaluate technical and operational vulnerabilities
- impact_modeling: Quantify business and financial impacts
- control_assessment: Analyze current security control effectiveness
- compliance_evaluation: Assess regulatory and compliance risks
- scenario_modeling: Run risk scenarios and simulations

Always provide:
- Quantified risk scores with confidence intervals
- Risk ranking and prioritization matrix
- Business impact assessment in financial terms
- Risk treatment recommendations with cost-benefit analysis
- Residual risk evaluation post-treatment
- Executive summary with key risk indicators
- Compliance and regulatory risk assessment

Focus on actionable risk insights for business decision-makers and security executives.`;
  }

  initializeRiskMatrix() {
    return {
      // Impact levels (1-5 scale)
      impactLevels: {
        1: { name: 'Minimal', financial: '< $10K', description: 'Negligible business impact' },
        2: { name: 'Minor', financial: '$10K - $100K', description: 'Limited operational impact' },
        3: { name: 'Moderate', financial: '$100K - $1M', description: 'Significant business disruption' },
        4: { name: 'Major', financial: '$1M - $10M', description: 'Severe operational impact' },
        5: { name: 'Catastrophic', financial: '> $10M', description: 'Business-threatening impact' }
      },

      // Likelihood levels (1-5 scale)
      likelihoodLevels: {
        1: { name: 'Very Low', percentage: '< 5%', description: 'Highly unlikely to occur' },
        2: { name: 'Low', percentage: '5% - 20%', description: 'Unlikely to occur' },
        3: { name: 'Medium', percentage: '20% - 50%', description: 'Possible to occur' },
        4: { name: 'High', percentage: '50% - 80%', description: 'Likely to occur' },
        5: { name: 'Very High', percentage: '> 80%', description: 'Almost certain to occur' }
      },

      // Risk levels (calculated from impact × likelihood)
      riskLevels: {
        'very_low': { range: [1, 4], color: 'green', action: 'Accept' },
        'low': { range: [5, 8], color: 'yellow', action: 'Monitor' },
        'medium': { range: [9, 15], color: 'orange', action: 'Mitigate' },
        'high': { range: [16, 20], color: 'red', action: 'Mitigate Immediately' },
        'critical': { range: [21, 25], color: 'dark_red', action: 'Emergency Response' }
      },

      // Industry risk factors
      industryFactors: {
        'financial': { multiplier: 1.5, reason: 'High-value target, regulatory requirements' },
        'healthcare': { multiplier: 1.4, reason: 'Protected health information, life safety' },
        'government': { multiplier: 1.6, reason: 'National security, citizen data' },
        'technology': { multiplier: 1.3, reason: 'IP theft, supply chain attacks' },
        'retail': { multiplier: 1.2, reason: 'Payment data, customer information' },
        'default': { multiplier: 1.0, reason: 'Standard risk profile' }
      },

      // Compliance frameworks
      complianceFrameworks: {
        'pci_dss': { criticality: 'high', penalties: 'Financial penalties, license loss' },
        'hipaa': { criticality: 'high', penalties: 'Fines up to $1.5M per incident' },
        'gdpr': { criticality: 'high', penalties: 'Up to 4% of annual revenue' },
        'sox': { criticality: 'medium', penalties: 'Criminal liability, fines' },
        'nist': { criticality: 'medium', penalties: 'Regulatory oversight' }
      }
    };
  }

  async createRiskAssessmentTools() {
    const tools = [];

    // Threat Likelihood Assessment Tool
    tools.push(new DynamicTool({
      name: "threat_likelihood",
      description: "Assess threat probability and actor capabilities for specific threats. Input should be a threat description or domain.",
      func: async (input) => {
        try {
          console.log(`📊 Risk Assessor: Threat likelihood analysis for ${input}`);
          
          const likelihood = await this.assessThreatLikelihood(input);
          
          return JSON.stringify({
            input,
            threatLikelihood: likelihood,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error assessing threat likelihood for ${input}: ${error.message}`;
        }
      }
    }));

    // Vulnerability Analysis Tool
    tools.push(new DynamicTool({
      name: "vulnerability_analysis",
      description: "Evaluate technical and operational vulnerabilities. Input should be a system or domain description.",
      func: async (input) => {
        try {
          console.log(`🔍 Risk Assessor: Vulnerability analysis for ${input}`);
          
          const vulnerabilities = await this.analyzeVulnerabilities(input);
          
          return JSON.stringify({
            input,
            vulnerabilityAnalysis: vulnerabilities,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error analyzing vulnerabilities for ${input}: ${error.message}`;
        }
      }
    }));

    // Impact Modeling Tool
    tools.push(new DynamicTool({
      name: "impact_modeling",
      description: "Quantify business and financial impacts of security incidents. Input should be an incident scenario.",
      func: async (input) => {
        try {
          console.log(`💰 Risk Assessor: Impact modeling for ${input}`);
          
          const impact = await this.modelBusinessImpact(input);
          
          return JSON.stringify({
            scenario: input,
            impactModeling: impact,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error modeling impact for ${input}: ${error.message}`;
        }
      }
    }));

    // Control Assessment Tool
    tools.push(new DynamicTool({
      name: "control_assessment",
      description: "Analyze current security control effectiveness. Input should be a control category or domain.",
      func: async (input) => {
        try {
          console.log(`🛡️ Risk Assessor: Control assessment for ${input}`);
          
          const controls = await this.assessSecurityControls(input);
          
          return JSON.stringify({
            input,
            controlAssessment: controls,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error assessing controls for ${input}: ${error.message}`;
        }
      }
    }));

    // Compliance Evaluation Tool
    tools.push(new DynamicTool({
      name: "compliance_evaluation",
      description: "Assess regulatory and compliance risks. Input should be a compliance framework or requirement.",
      func: async (input) => {
        try {
          console.log(`📋 Risk Assessor: Compliance evaluation for ${input}`);
          
          const compliance = await this.evaluateCompliance(input);
          
          return JSON.stringify({
            framework: input,
            complianceEvaluation: compliance,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error evaluating compliance for ${input}: ${error.message}`;
        }
      }
    }));

    // Scenario Modeling Tool
    tools.push(new DynamicTool({
      name: "scenario_modeling",
      description: "Run risk scenarios and simulations. Input should be a risk scenario description.",
      func: async (input) => {
        try {
          console.log(`🎯 Risk Assessor: Scenario modeling for ${input}`);
          
          const scenarios = await this.runScenarioModeling(input);
          
          return JSON.stringify({
            scenario: input,
            scenarioModeling: scenarios,
            timestamp: new Date().toISOString()
          }, null, 2);
        } catch (error) {
          return `Error modeling scenarios for ${input}: ${error.message}`;
        }
      }
    }));

    return tools;
  }

  async assess(target, assessmentContext = {}) {
    if (!this.isInitialized) {
      return {
        success: false,
        error: 'Risk Assessment Agent not initialized',
        agent: 'risk-assessor'
      };
    }

    try {
      console.log(`📊 Risk Assessment Agent: Starting comprehensive risk assessment for ${target}`);
      
      const assessmentPrompt = `
Conduct a comprehensive cybersecurity risk assessment for: ${target}

Assessment Context:
${JSON.stringify(assessmentContext, null, 2)}

Execute a thorough risk assessment methodology:

1. THREAT LANDSCAPE ANALYSIS
   - Use threat_likelihood to assess current threat environment
   - Evaluate threat actor capabilities and intent
   - Analyze attack vectors and technique probabilities
   - Assess emerging threat trends and their relevance

2. VULNERABILITY ASSESSMENT
   - Use vulnerability_analysis to identify weaknesses
   - Evaluate technical, operational, and process vulnerabilities
   - Assess human factors and social engineering risks
   - Analyze supply chain and third-party risks

3. BUSINESS IMPACT ANALYSIS
   - Use impact_modeling to quantify potential impacts
   - Calculate direct and indirect financial costs
   - Assess operational disruption scenarios
   - Evaluate reputational and regulatory consequences

4. SECURITY CONTROL EVALUATION
   - Use control_assessment to analyze current defenses
   - Identify control gaps and weaknesses
   - Evaluate compensating controls
   - Assess defense-in-depth effectiveness

5. COMPLIANCE AND REGULATORY ASSESSMENT
   - Use compliance_evaluation for applicable frameworks
   - Assess regulatory compliance risks
   - Evaluate legal and contractual obligations
   - Identify compliance gaps and requirements

6. SCENARIO-BASED RISK MODELING
   - Use scenario_modeling for realistic attack scenarios
   - Run Monte Carlo simulations for risk exposure
   - Model risk treatment options and their effectiveness
   - Calculate residual risk after treatments

7. COMPREHENSIVE RISK REPORT
   Provide a detailed risk assessment including:
   - Executive summary with key risk indicators
   - Quantified risk scores with confidence intervals
   - Risk ranking and prioritization matrix
   - Business impact assessment in financial terms
   - Risk treatment recommendations with cost-benefit analysis
   - Residual risk evaluation post-treatment
   - Key performance indicators for risk monitoring
   - Compliance and regulatory risk summary

Focus on actionable recommendations for executive decision-making.
`;

      const result = await this.executor.invoke({
        input: assessmentPrompt
      });

      // Structure the risk assessment results
      const riskAssessment = this.structureRiskAssessment(result.output, target, assessmentContext);

      // Store assessment results
      if (this.database && this.database.isConnected()) {
        await this.storeRiskAssessment(target, riskAssessment);
      }

      console.log(`✅ Risk Assessment Agent: Completed assessment for ${target}`);
      
      return {
        success: true,
        agent: 'risk-assessor',
        target,
        riskAssessment,
        executiveSummary: this.generateExecutiveSummary(riskAssessment),
        timestamp: new Date().toISOString(),
        nextReviewDate: this.calculateNextReviewDate(riskAssessment)
      };

    } catch (error) {
      console.error(`❌ Risk Assessment Agent error for ${target}:`, error);
      
      return {
        success: false,
        agent: 'risk-assessor',
        target,
        error: error.message,
        fallback: await this.generateFallbackAssessment(target, assessmentContext)
      };
    }
  }

  async assessThreatLikelihood(input) {
    // Simulate threat likelihood assessment
    const assessment = {
      threatLevel: 'medium',
      likelihood: 3, // 1-5 scale
      confidence: 75,
      factors: [
        'Current threat landscape',
        'Target attractiveness',
        'Historical attack patterns'
      ],
      threatActors: [
        { type: 'Cybercriminals', capability: 'medium', intent: 'high' },
        { type: 'State-sponsored', capability: 'high', intent: 'low' },
        { type: 'Insider threats', capability: 'medium', intent: 'low' }
      ],
      timeframe: '12 months'
    };

    return assessment;
  }

  async analyzeVulnerabilities(input) {
    // Simulate vulnerability analysis
    const analysis = {
      overallRisk: 'medium',
      vulnerabilityCount: {
        critical: 2,
        high: 5,
        medium: 12,
        low: 8
      },
      categories: {
        technical: {
          score: 6,
          issues: ['Unpatched systems', 'Weak encryption', 'Open ports']
        },
        operational: {
          score: 4,
          issues: ['Insufficient monitoring', 'Backup gaps']
        },
        human: {
          score: 7,
          issues: ['Phishing susceptibility', 'Weak passwords']
        },
        process: {
          score: 5,
          issues: ['Incomplete procedures', 'Access control gaps']
        }
      },
      prioritizedActions: [
        'Patch critical vulnerabilities within 48 hours',
        'Implement multi-factor authentication',
        'Enhance security awareness training'
      ]
    };

    return analysis;
  }

  async modelBusinessImpact(scenario) {
    // Simulate business impact modeling
    const impact = {
      scenario,
      impactCategories: {
        financial: {
          direct: { min: 50000, max: 500000, expected: 200000 },
          indirect: { min: 25000, max: 250000, expected: 100000 },
          regulatory: { min: 0, max: 1000000, expected: 50000 }
        },
        operational: {
          downtime: { hours: 24, costPerHour: 10000 },
          recovery: { days: 7, costPerDay: 5000 },
          productivity: { lossPercentage: 30, duration: 14 }
        },
        reputational: {
          customerLoss: { percentage: 5, revenue: 2000000 },
          brandDamage: { duration: 'months', severity: 'moderate' }
        },
        legal: {
          litigation: { probability: 0.3, averageCost: 150000 },
          compliance: { fines: 75000, remediation: 100000 }
        }
      },
      totalExpectedLoss: 450000,
      confidenceInterval: '±30%',
      timeframe: '12 months'
    };

    return impact;
  }

  async assessSecurityControls(input) {
    // Simulate security control assessment
    const assessment = {
      controlCategories: {
        preventive: {
          effectiveness: 75,
          controls: ['Firewall', 'Access controls', 'Encryption'],
          gaps: ['DLP', 'Advanced threat protection']
        },
        detective: {
          effectiveness: 60,
          controls: ['SIEM', 'IDS/IPS', 'Log monitoring'],
          gaps: ['User behavior analytics', 'Threat hunting']
        },
        corrective: {
          effectiveness: 70,
          controls: ['Incident response', 'Backup systems'],
          gaps: ['Automated response', 'Forensics capability']
        }
      },
      overallMaturity: 68,
      recommendations: [
        'Implement user behavior analytics',
        'Enhance automated incident response',
        'Deploy advanced threat protection'
      ],
      controlGaps: 15,
      priorityImprovements: 3
    };

    return assessment;
  }

  async evaluateCompliance(framework) {
    // Simulate compliance evaluation
    const evaluation = {
      framework,
      complianceScore: 82,
      status: 'substantially_compliant',
      gaps: [
        { control: 'Access management', severity: 'medium', effort: 'moderate' },
        { control: 'Data encryption', severity: 'low', effort: 'minimal' },
        { control: 'Incident logging', severity: 'high', effort: 'significant' }
      ],
      nextAudit: '2024-09-15',
      estimatedCost: 150000,
      timeline: '6 months',
      riskOfNonCompliance: {
        financial: 500000,
        operational: 'moderate',
        reputational: 'high'
      }
    };

    return evaluation;
  }

  async runScenarioModeling(scenario) {
    // Simulate scenario modeling
    const modeling = {
      scenario,
      probability: 0.15, // 15% chance per year
      simulations: 10000,
      outcomes: {
        noImpact: { probability: 0.70, cost: 0 },
        minorImpact: { probability: 0.20, cost: 75000 },
        moderateImpact: { probability: 0.08, cost: 350000 },
        majorImpact: { probability: 0.02, cost: 2000000 }
      },
      expectedAnnualLoss: 67500,
      valueAtRisk95: 450000,
      riskTolerance: 'within_acceptable_limits',
      mitigation: {
        cost: 120000,
        effectiveness: 0.60,
        reducedEAL: 27000
      }
    };

    return modeling;
  }

  structureRiskAssessment(agentOutput, target, context) {
    const assessment = {
      target,
      assessmentDate: new Date().toISOString(),
      overallRiskLevel: 'MEDIUM',
      riskScore: 65, // 0-100 scale
      confidenceLevel: 80,
      keyRisks: [],
      businessImpact: {},
      recommendations: [],
      residualRisk: {},
      rawAssessment: agentOutput
    };

    try {
      // Extract overall risk level
      const riskMatch = agentOutput.match(/(CRITICAL|HIGH|MEDIUM|LOW)/i);
      if (riskMatch) {
        assessment.overallRiskLevel = riskMatch[1].toUpperCase();
      }

      // Extract risk score
      const scoreMatch = agentOutput.match(/risk\s+score[:\s]+(\d+)/i);
      if (scoreMatch) {
        assessment.riskScore = parseInt(scoreMatch[1]);
      }

      // Calculate matrix-based risk level
      assessment.matrixRiskLevel = this.calculateMatrixRisk(
        assessment.riskScore,
        context.threatLevel || 3
      );

    } catch (parseError) {
      console.log('Note: Could not fully parse risk assessment output');
    }

    return assessment;
  }

  calculateMatrixRisk(impact, likelihood) {
    const riskValue = impact * likelihood;
    
    for (const [level, config] of Object.entries(this.riskMatrix.riskLevels)) {
      if (riskValue >= config.range[0] && riskValue <= config.range[1]) {
        return {
          level: level,
          value: riskValue,
          action: config.action,
          color: config.color
        };
      }
    }
    
    return { level: 'unknown', value: riskValue, action: 'Review', color: 'gray' };
  }

  generateExecutiveSummary(riskAssessment) {
    return {
      overallRisk: riskAssessment.overallRiskLevel,
      keyFindings: [
        `Overall risk level: ${riskAssessment.overallRiskLevel}`,
        `Risk score: ${riskAssessment.riskScore}/100`,
        `Assessment confidence: ${riskAssessment.confidenceLevel}%`
      ],
      criticalActions: [
        'Implement high-priority security controls',
        'Address identified compliance gaps',
        'Enhance threat detection capabilities'
      ],
      businessImpact: {
        expectedLoss: '$450,000 annually',
        worstCase: '$2,000,000',
        mitigationCost: '$120,000'
      },
      timeline: '90 days for critical items',
      nextReview: this.calculateNextReviewDate(riskAssessment)
    };
  }

  calculateNextReviewDate(riskAssessment) {
    const reviewIntervals = {
      'CRITICAL': 30,  // 30 days
      'HIGH': 60,      // 60 days
      'MEDIUM': 90,    // 90 days
      'LOW': 180       // 180 days
    };

    const interval = reviewIntervals[riskAssessment.overallRiskLevel] || 90;
    const nextReview = new Date();
    nextReview.setDate(nextReview.getDate() + interval);
    
    return nextReview.toISOString().split('T')[0];
  }

  async generateFallbackAssessment(target, context) {
    return {
      target,
      overallRiskLevel: 'UNKNOWN',
      riskScore: 50,
      confidenceLevel: 30,
      fallbackReason: 'AI risk assessment unavailable',
      basicAssessment: 'Manual risk assessment recommended',
      recommendations: [
        'Enable OpenAI API for comprehensive risk assessment',
        'Conduct manual risk evaluation',
        'Implement basic security controls'
      ]
    };
  }

  async storeRiskAssessment(target, assessment) {
    try {
      await this.database.query(
        `INSERT INTO domain_analyses (domain, risk_score, analyzed_by, created_at) 
         VALUES ($1, $2, $3, NOW())`,
        [target, JSON.stringify(assessment), 'risk-assessment-agent']
      );
    } catch (error) {
      console.log('Could not store risk assessment:', error.message);
    }
  }

  // Risk calculation utilities
  calculateCVSS(baseScore, temporalScore = 1.0, environmentalScore = 1.0) {
    return Math.round(baseScore * temporalScore * environmentalScore * 10) / 10;
  }

  calculateAnnualLossExpectancy(assetValue, exposureFactor, annualRateOccurrence) {
    const singleLossExpectancy = assetValue * exposureFactor;
    return singleLossExpectancy * annualRateOccurrence;
  }

  calculateRiskTreatmentCost(treatmentType, riskLevel) {
    const baseCosts = {
      'accept': 0,
      'mitigate': 100000,
      'transfer': 50000,
      'avoid': 200000
    };

    const riskMultipliers = {
      'CRITICAL': 2.0,
      'HIGH': 1.5,
      'MEDIUM': 1.0,
      'LOW': 0.5
    };

    const baseCost = baseCosts[treatmentType] || 100000;
    const multiplier = riskMultipliers[riskLevel] || 1.0;
    
    return baseCost * multiplier;
  }

  async healthCheck() {
    return {
      agent: 'risk-assessor',
      initialized: this.isInitialized,
      toolsCount: this.tools.length,
      riskMatrixLoaded: !!this.riskMatrix,
      hasLLM: !!this.llm,
      hasCache: !!this.cache,
      hasDatabase: !!this.database,
      riskLevels: Object.keys(this.riskMatrix.riskLevels).length,
      complianceFrameworks: Object.keys(this.riskMatrix.complianceFrameworks).length
    };
  }
}

module.exports = { RiskAssessmentAgent };