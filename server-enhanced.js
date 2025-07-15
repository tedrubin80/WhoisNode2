const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Health endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// API Status
app.get('/api/status', (req, res) => {
  res.json({
    api: 'WHOIS Intelligence Tool',
    version: '2.0.0',
    status: 'operational',
    endpoints: ['/api/analyze', '/api/status', '/health']
  });
});

// Basic analyze endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }

    // Simple mock response for now
    res.json({
      success: true,
      domain: domain,
      timestamp: new Date().toISOString(),
      summary: {
        registrar: 'Unknown',
        isUSRegistrar: false,
        isPrivacyProtected: false,
        primaryIP: '127.0.0.1',
        creationDate: 'Unknown'
      }
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({
      success: false,
      error: 'Analysis failed',
      message: error.message
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health: http://localhost:${PORT}/health`);
  console.log(`🔧 Status: http://localhost:${PORT}/api/status`);
});