/*
FOLDER STRUCTURE:
whois-intelligence-server/
├── database/
│   ├── postgres-config.js       (this file)
│   ├── migrations/
│   │   ├── 001_create_users.sql
│   │   └── 002_create_analyses.sql
│   └── models/
│       ├── User.js
│       └── Analysis.js

FILE LOCATION: /database/postgres-config.js
*/

// PostgreSQL Database Configuration for WHOIS Intelligence
// FILE: /database/postgres-config.js

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Database configuration - Railway PostgreSQL compatible
const dbConfig = process.env.DATABASE_URL 
  ? {
      // Railway PostgreSQL connection string
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
      ssl: {
        rejectUnauthorized: false // Required for Railway
      }
    }
  : {
      // Fallback to individual parameters
      host: process.env.POSTGRES_HOST || 'localhost',
      port: process.env.POSTGRES_PORT || 5432,
      database: process.env.POSTGRES_DB || 'whois_intelligence',
      user: process.env.POSTGRES_USER || 'whois_user',
      password: process.env.POSTGRES_PASSWORD || 'secure_password_here',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    };

// Create connection pool
const pool = new Pool(dbConfig);

// Database connection class
class Database {
  constructor() {
    this.pool = pool;
    this.connected = false;
  }

  // Initialize database connection
  async connect() {
    try {
      const client = await this.pool.connect();
      console.log('✅ PostgreSQL connected successfully to Railway');
      console.log(`📊 Database: ${process.env.DATABASE_URL ? 'Railway PostgreSQL' : dbConfig.database}`);
      
      // Test query
      const result = await client.query('SELECT NOW()');
      console.log(`🕐 Database time: ${result.rows[0].now}`);
      
      client.release();
      this.connected = true;
      return true;
    } catch (error) {
      console.error('❌ PostgreSQL connection failed:', error.message);
      console.log('ℹ️  Continuing without database persistence (cache-only mode)');
      this.connected = false;
      return false;
    }
  }

  // Check if database is connected
  isConnected() {
    return this.connected;
  }

  // Execute query
  async query(text, params = []) {
    if (!this.connected) {
      throw new Error('Database not connected');
    }

    try {
      const start = Date.now();
      const result = await this.pool.query(text, params);
      const duration = Date.now() - start;
      
      console.log(`🔍 Query executed in ${duration}ms`);
      return result;
    } catch (error) {
      console.error('❌ Database query error:', error);
      throw error;
    }
  }

  // Get a client from the pool
  async getClient() {
    if (!this.connected) {
      throw new Error('Database not connected');
    }
    return await this.pool.connect();
  }

  // Run migrations
  async runMigrations() {
    if (!this.connected) {
      console.log('⚠️  Skipping migrations - database not connected');
      return false;
    }

    try {
      console.log('🔄 Running database migrations...');
      
      // Create migrations table if it doesn't exist
      await this.query(`
        CREATE TABLE IF NOT EXISTS migrations (
          id SERIAL PRIMARY KEY,
          filename VARCHAR(255) NOT NULL UNIQUE,
          executed_at TIMESTAMP DEFAULT NOW()
        )
      `);

      // Get list of migration files
      const migrationsDir = path.join(__dirname, 'migrations');
      const migrationFiles = fs.readdirSync(migrationsDir)
        .filter(file => file.endsWith('.sql'))
        .sort();

      for (const file of migrationFiles) {
        // Check if migration already executed
        const result = await this.query(
          'SELECT id FROM migrations WHERE filename = $1',
          [file]
        );

        if (result.rows.length === 0) {
          console.log(`📄 Running migration: ${file}`);
          
          // Read and execute migration
          const migrationSQL = fs.readFileSync(
            path.join(migrationsDir, file),
            'utf8'
          );
          
          const client = await this.getClient();
          try {
            await client.query('BEGIN');
            await client.query(migrationSQL);
            await client.query(
              'INSERT INTO migrations (filename) VALUES ($1)',
              [file]
            );
            await client.query('COMMIT');
            console.log(`✅ Migration completed: ${file}`);
          } catch (error) {
            await client.query('ROLLBACK');
            throw error;
          } finally {
            client.release();
          }
        } else {
          console.log(`⏭️  Migration already executed: ${file}`);
        }
      }

      console.log('✅ All migrations completed successfully');
      return true;
    } catch (error) {
      console.error('❌ Migration failed:', error);
      return false;
    }
  }

  // Close all connections
  async close() {
    try {
      await this.pool.end();
      console.log('🔒 Database connections closed');
    } catch (error) {
      console.error('❌ Error closing database:', error);
    }
  }

  // Health check
  async healthCheck() {
    if (!this.connected) {
      return {
        status: 'disconnected',
        message: 'Database not connected'
      };
    }

    try {
      const result = await this.query('SELECT 1 as health_check');
      return {
        status: 'healthy',
        message: 'Database connection is healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'error',
        message: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Get database statistics
  async getStats() {
    if (!this.connected) {
      return null;
    }

    try {
      const queries = await Promise.all([
        this.query(`
          SELECT 
            schemaname,
            tablename,
            n_tup_ins as inserts,
            n_tup_upd as updates,
            n_tup_del as deletes
          FROM pg_stat_user_tables
          ORDER BY tablename
        `),
        this.query(`
          SELECT 
            datname as database,
            numbackends as active_connections,
            xact_commit as transactions_committed,
            xact_rollback as transactions_rolled_back
          FROM pg_stat_database 
          WHERE datname = $1
        `, [dbConfig.database])
      ]);

      return {
        tables: queries[0].rows,
        database: queries[1].rows[0] || {},
        pool: {
          totalCount: this.pool.totalCount,
          idleCount: this.pool.idleCount,
          waitingCount: this.pool.waitingCount
        }
      };
    } catch (error) {
      console.error('❌ Error getting database stats:', error);
      return null;
    }
  }
}

// Create singleton instance
const database = new Database();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🛑 Graceful shutdown: closing database connections...');
  await database.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Graceful shutdown: closing database connections...');
  await database.close();
  process.exit(0);
});

module.exports = {
  database,
  pool,
  dbConfig
};