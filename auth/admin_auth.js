/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── auth/
│   ├── admin-auth.js            (this file)
│   └── jwt-middleware.js

FILE LOCATION: /auth/admin-auth.js
*/

// Admin Authentication System for WHOIS Intelligence
// FILE: /auth/admin-auth.js

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Auth configuration
const AUTH_CONFIG = {
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  jwtExpiration: '24h',
  saltRounds: 12,
  maxFailedAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
  sessionTimeout: 24 * 60 * 60 * 1000 // 24 hours
};

// In-memory user store (for Week 1 - will move to PostgreSQL later)
const USERS = new Map();
const FAILED_ATTEMPTS = new Map();
const ACTIVE_SESSIONS = new Map();

// Default admin user
const DEFAULT_ADMIN = {
  id: 'admin-001',
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'secure_admin_password_123',
  role: 'admin',
  permissions: ['read', 'write', 'admin'],
  createdAt: new Date().toISOString(),
  lastLogin: null,
  isActive: true
};

// Initialize admin authentication
async function initializeAuth() {
  try {
    console.log('🔐 Initializing admin authentication...');
    
    // Hash default admin password
    const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, AUTH_CONFIG.saltRounds);
    
    // Store default admin user
    USERS.set(DEFAULT_ADMIN.username, {
      ...DEFAULT_ADMIN,
      passwordHash: hashedPassword
    });
    
    console.log('✅ Admin authentication initialized');
    console.log(`👤 Default admin user: ${DEFAULT_ADMIN.username}`);
    console.log('🔑 JWT secret configured');
    
    // Security warning for default credentials
    if (DEFAULT_ADMIN.username === 'admin' && DEFAULT_ADMIN.password === 'secure_admin_password_123') {
      console.log('⚠️  WARNING: Using default admin credentials!');
      console.log('🔒 Please change ADMIN_USERNAME and ADMIN_PASSWORD in .env');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Auth initialization failed:', error);
    return false;
  }
}

// Login function
async function login(username, password, clientInfo = {}) {
  try {
    // Check for too many failed attempts
    const attempts = FAILED_ATTEMPTS.get(username) || { count: 0, lastAttempt: 0 };
    const now = Date.now();
    
    if (attempts.count >= AUTH_CONFIG.maxFailedAttempts) {
      const timeSinceLastAttempt = now - attempts.lastAttempt;
      if (timeSinceLastAttempt < AUTH_CONFIG.lockoutDuration) {
        const remainingLockout = Math.ceil((AUTH_CONFIG.lockoutDuration - timeSinceLastAttempt) / 1000 / 60);
        return {
          success: false,
          error: 'Account temporarily locked',
          message: `Too many failed attempts. Try again in ${remainingLockout} minutes.`,
          lockoutRemaining: remainingLockout
        };
      } else {
        // Reset failed attempts after lockout period
        FAILED_ATTEMPTS.delete(username);
      }
    }
    
    // Get user
    const user = USERS.get(username);
    if (!user || !user.isActive) {
      await recordFailedAttempt(username);
      return {
        success: false,
        error: 'Invalid credentials',
        message: 'Username or password incorrect'
      };
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      await recordFailedAttempt(username);
      return {
        success: false,
        error: 'Invalid credentials',
        message: 'Username or password incorrect'
      };
    }
    
    // Clear failed attempts on successful login
    FAILED_ATTEMPTS.delete(username);
    
    // Generate JWT token
    const tokenPayload = {
      userId: user.id,
      username: user.username,
      role: user.role,
      permissions: user.permissions,
      loginTime: now
    };
    
    const token = jwt.sign(tokenPayload, AUTH_CONFIG.jwtSecret, {
      expiresIn: AUTH_CONFIG.jwtExpiration
    });
    
    // Create session
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session = {
      sessionId,
      userId: user.id,
      username: user.username,
      role: user.role,
      permissions: user.permissions,
      createdAt: now,
      lastActivity: now,
      clientInfo: {
        ip: clientInfo.ip || 'unknown',
        userAgent: clientInfo.userAgent || 'unknown'
      }
    };
    
    ACTIVE_SESSIONS.set(sessionId, session);
    
    // Update user last login
    user.lastLogin = new Date().toISOString();
    
    console.log(`✅ Admin login successful: ${username} from ${clientInfo.ip || 'unknown'}`);
    
    return {
      success: true,
      token,
      sessionId,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        permissions: user.permissions,
        lastLogin: user.lastLogin
      },
      expiresIn: AUTH_CONFIG.jwtExpiration
    };
    
  } catch (error) {
    console.error('❌ Login error:', error);
    return {
      success: false,
      error: 'Authentication failed',
      message: 'An error occurred during login'
    };
  }
}

// Record failed login attempt
async function recordFailedAttempt(username) {
  const attempts = FAILED_ATTEMPTS.get(username) || { count: 0, lastAttempt: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  FAILED_ATTEMPTS.set(username, attempts);
  
  console.log(`⚠️  Failed login attempt for: ${username} (${attempts.count}/${AUTH_CONFIG.maxFailedAttempts})`);
}

// Logout function
function logout(sessionId) {
  try {
    const session = ACTIVE_SESSIONS.get(sessionId);
    if (session) {
      ACTIVE_SESSIONS.delete(sessionId);
      console.log(`🔒 Admin logout: ${session.username}`);
      return { success: true, message: 'Logged out successfully' };
    } else {
      return { success: false, error: 'Session not found' };
    }
  } catch (error) {
    console.error('❌ Logout error:', error);
    return { success: false, error: 'Logout failed' };
  }
}

// Verify JWT token
function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, AUTH_CONFIG.jwtSecret);
    
    // Check if user still exists and is active
    const user = USERS.get(decoded.username);
    if (!user || !user.isActive) {
      return { valid: false, error: 'User no longer active' };
    }
    
    return {
      valid: true,
      decoded,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        permissions: user.permissions
      }
    };
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return { valid: false, error: 'Token expired' };
    } else if (error.name === 'JsonWebTokenError') {
      return { valid: false, error: 'Invalid token' };
    } else {
      return { valid: false, error: 'Token verification failed' };
    }
  }
}

// Verify session
function verifySession(sessionId) {
  try {
    const session = ACTIVE_SESSIONS.get(sessionId);
    if (!session) {
      return { valid: false, error: 'Session not found' };
    }
    
    const now = Date.now();
    const sessionAge = now - session.createdAt;
    
    // Check session timeout
    if (sessionAge > AUTH_CONFIG.sessionTimeout) {
      ACTIVE_SESSIONS.delete(sessionId);
      return { valid: false, error: 'Session expired' };
    }
    
    // Update last activity
    session.lastActivity = now;
    
    return {
      valid: true,
      session: {
        userId: session.userId,
        username: session.username,
        role: session.role,
        permissions: session.permissions,
        lastActivity: session.lastActivity
      }
    };
  } catch (error) {
    return { valid: false, error: 'Session verification failed' };
  }
}

// Check permission
function hasPermission(user, requiredPermission) {
  if (!user || !user.permissions) {
    return false;
  }
  
  // Admin role has all permissions
  if (user.role === 'admin') {
    return true;
  }
  
  return user.permissions.includes(requiredPermission);
}

// Get active sessions
function getActiveSessions() {
  const sessions = [];
  const now = Date.now();
  
  for (const [sessionId, session] of ACTIVE_SESSIONS.entries()) {
    // Clean up expired sessions
    const sessionAge = now - session.createdAt;
    if (sessionAge > AUTH_CONFIG.sessionTimeout) {
      ACTIVE_SESSIONS.delete(sessionId);
      continue;
    }
    
    sessions.push({
      sessionId,
      username: session.username,
      role: session.role,
      createdAt: new Date(session.createdAt).toISOString(),
      lastActivity: new Date(session.lastActivity).toISOString(),
      clientInfo: session.clientInfo
    });
  }
  
  return sessions;
}

// Get authentication statistics
function getAuthStats() {
  return {
    totalUsers: USERS.size,
    activeSessions: ACTIVE_SESSIONS.size,
    failedAttempts: FAILED_ATTEMPTS.size,
    config: {
      jwtExpiration: AUTH_CONFIG.jwtExpiration,
      maxFailedAttempts: AUTH_CONFIG.maxFailedAttempts,
      lockoutDuration: AUTH_CONFIG.lockoutDuration / 1000 / 60 + ' minutes'
    }
  };
}

// Cleanup expired sessions (run periodically)
function cleanupExpiredSessions() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [sessionId, session] of ACTIVE_SESSIONS.entries()) {
    const sessionAge = now - session.createdAt;
    if (sessionAge > AUTH_CONFIG.sessionTimeout) {
      ACTIVE_SESSIONS.delete(sessionId);
      cleaned++;
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned up ${cleaned} expired sessions`);
  }
  
  return cleaned;
}

// Set up periodic cleanup
setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Every hour

module.exports = {
  initializeAuth,
  login,
  logout,
  verifyToken,
  verifySession,
  hasPermission,
  getActiveSessions,
  getAuthStats,
  cleanupExpiredSessions,
  AUTH_CONFIG
};