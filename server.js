require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const crypto = require('crypto');

const app = express();

// ===== CONFIGURATION =====
const CONFIG = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
  isDevelopment: process.env.NODE_ENV !== 'production',
  saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
  version: '2.2.0'
};

const DB_CONFIG = {
  auth: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '0000',
    database: process.env.DB_NAME_AUTH || 'flutter_auth',
    charset: 'utf8mb4',
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000
  },
  categories: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '0000',
    database: process.env.DB_NAME_CATEGORIES || 'townzy',
    charset: 'utf8mb4',
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000
  }
};

// ===== MIDDLEWARE =====
app.use(helmet({ crossOriginEmbedderPolicy: false }));

const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] || req.connection?.remoteAddress || req.ip || 'unknown';
};

const createRateLimiter = (windowMs, max, prefix = '') => rateLimit({
  windowMs, max,
  keyGenerator: (req) => {
    const ip = getClientIP(req);
    const deviceHash = crypto.createHash('md5').update(req.headers['user-agent'] || '').digest('hex').substring(0, 8);
    return `${prefix}${ip}-${deviceHash}`;
  },
  message: { error: 'Too many requests from this device, please try again later.' },
});

app.use(createRateLimiter(15 * 60 * 1000, 200));
app.use(cors({ 
  origin: CONFIG.isDevelopment ? true : (process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']), 
  credentials: true 
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced request logging
app.use((req, res, next) => {
  const start = Date.now();
  const ip = getClientIP(req);
  const deviceHash = crypto.createHash('md5').update(req.get('User-Agent') || '').digest('hex').substring(0, 8);
  
  console.log(`📨 ${req.method} ${req.path} - IP: ${ip} - ${new Date().toISOString()}`);
  
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const logBody = { ...req.body };
    if (logBody.password) logBody.password = '[HIDDEN]';
    console.log(`📝 Request Body:`, logBody);
  }
  
  req.deviceInfo = { ip, deviceHash };
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`📤 ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
});

// ===== DATABASE UTILITIES =====
class Database {
  static async connect(config) {
    try {
      console.log(`🔗 Connecting to database: ${config.database} at ${config.host}`);
      const connection = await mysql.createConnection(config);
      console.log(`✅ Connected to database: ${config.database}`);
      return connection;
    } catch (error) {
      console.error(`❌ Database connection failed for ${config.database}:`, {
        message: error.message,
        code: error.code,
        errno: error.errno
      });
      throw error;
    }
  }

  static async initialize() {
    console.log('🔍 Initializing databases...');
    try {
      await this.initAuthDatabase();
      await this.initCategoriesDatabase();
      console.log('✅ Database initialization complete');
    } catch (error) {
      console.error('❌ Database initialization failed:', error.message);
      throw error;
    }
  }

  static async initAuthDatabase() {
    let connection;
    try {
      console.log('🔧 Initializing auth database...');
      
      connection = await mysql.createConnection({
        host: DB_CONFIG.auth.host,
        user: DB_CONFIG.auth.user,
        password: DB_CONFIG.auth.password,
        charset: 'utf8mb4'
      });

      await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_CONFIG.auth.database}\``);
      await connection.query(`USE \`${DB_CONFIG.auth.database}\``);
      
      // Create users table only if it doesn't exist
      await connection.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          email VARCHAR(100) UNIQUE NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          last_login TIMESTAMP NULL,
          is_active BOOLEAN DEFAULT TRUE,
          INDEX idx_username (username), 
          INDEX idx_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);

      // Create sellers table only if it doesn't exist
      await connection.query(`
        CREATE TABLE IF NOT EXISTS sellers (
          id INT AUTO_INCREMENT PRIMARY KEY,
          seller_id VARCHAR(20) UNIQUE NOT NULL,
          business_name VARCHAR(100) NOT NULL,
          shop_address TEXT NOT NULL,
          mobile_number VARCHAR(15) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          email VARCHAR(100) NULL,
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          last_login TIMESTAMP NULL,
          INDEX idx_seller_id (seller_id), 
          INDEX idx_mobile (mobile_number)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);
      
      console.log('✅ Auth database initialized successfully');
    } catch (error) {
      console.error('❌ Auth database initialization error:', {
        message: error.message,
        code: error.code,
        sqlState: error.sqlState,
        sqlMessage: error.sqlMessage
      });
      throw error;
    } finally {
      if (connection) {
        await connection.end();
        console.log('🔌 Auth database connection closed');
      }
    }
  }

  static async initCategoriesDatabase() {
    let connection;
    try {
      console.log('🔧 Initializing categories database...');
      
      connection = await mysql.createConnection({
        host: DB_CONFIG.categories.host,
        user: DB_CONFIG.categories.user,
        password: DB_CONFIG.categories.password,
        charset: 'utf8mb4'
      });

      await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_CONFIG.categories.database}\``);
      await connection.query(`USE \`${DB_CONFIG.categories.database}\``);
      
      await connection.query(`
        CREATE TABLE IF NOT EXISTS categories (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          description TEXT,
          color VARCHAR(7) DEFAULT '#2196F3',
          parent_id INT NULL,
          seller_id VARCHAR(20) NULL,
          sort_order INT DEFAULT 0,
          icon VARCHAR(50) DEFAULT 'category',
          image_url VARCHAR(255),
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (parent_id) REFERENCES categories(id) ON DELETE CASCADE,
          INDEX idx_parent_id (parent_id), 
          INDEX idx_seller_id (seller_id), 
          INDEX idx_is_active (is_active)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);

      await this.insertSampleCategories(connection);
      
      console.log('✅ Categories database initialized successfully');
    } catch (error) {
      console.error('❌ Categories database initialization error:', {
        message: error.message,
        code: error.code,
        sqlState: error.sqlState
      });
      throw error;
    } finally {
      if (connection) {
        await connection.end();
        console.log('🔌 Categories database connection closed');
      }
    }
  }

  static async insertSampleCategories(connection) {
    try {
      console.log('📦 Inserting sample categories...');
      
      const mainCategories = [
        { id: 1, name: 'Tailoring', description: 'Professional tailoring services', color: '#FF6B6B', icon: 'scissors' },
        { id: 2, name: 'Electronics', description: 'Electronics repair services', color: '#4ECDC4', icon: 'smartphone' },
        { id: 3, name: 'Home Services', description: 'Home maintenance services', color: '#45B7D1', icon: 'home' },
        { id: 4, name: 'Beauty & Wellness', description: 'Beauty and personal care', color: '#FFA07A', icon: 'heart' },
        { id: 5, name: 'Automotive', description: 'Car repair services', color: '#98D8C8', icon: 'car' }
      ];

      for (const category of mainCategories) {
        await connection.execute(
          'INSERT INTO categories (id, name, description, color, icon, sort_order, seller_id) VALUES (?, ?, ?, ?, ?, ?, NULL)',
          [category.id, category.name, category.description, category.color, category.icon, category.id]
        );
      }
      
      console.log('✅ Sample categories inserted successfully');
    } catch (error) {
      console.error('❌ Sample categories insertion error:', error.message);
    }
  }
}

// ===== UTILITIES =====
const generateSellerId = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = 'S';
  for (let i = 0; i < 7; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

// Consolidated validation object
const validate = {
  username: (username) => username && /^[a-zA-Z0-9_]{3,50}$/.test(username),
  password: (password) => password && password.length >= 6 && password.length <= 128,
  email: (email) => !email || validator.isEmail(email),
  mobile: (mobile) => mobile && /^[0-9]{10,15}$/.test(mobile),
  id: (id) => !isNaN(parseInt(id)) && parseInt(id) > 0,
  categoryName: (name) => name && name.trim().length > 0 && name.trim().length <= 100
};

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  
  jwt.verify(token, CONFIG.jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const authenticateSeller = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Seller access token required' });
  
  jwt.verify(token, CONFIG.jwtSecret, (err, seller) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired seller token' });
    if (!seller.sellerId) return res.status(403).json({ error: 'Invalid seller token' });
    req.seller = seller;
    next();
  });
};

const generateImageUrl = (req, categoryId) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const imageMap = {
    1: `${baseUrl}/images/categories/tailoring.jpg`,
    2: `${baseUrl}/images/categories/electronics.jpg`,
    3: `${baseUrl}/images/categories/home-services.jpg`,
    4: `${baseUrl}/images/categories/beauty-wellness.jpg`,
    5: `${baseUrl}/images/categories/automotive.jpg`
  };
  return imageMap[categoryId] || `${baseUrl}/images/default/category.jpg`;
};

const handleError = (res, error, operation = 'Operation') => {
  console.error(`❌ ${operation} error:`, {
    message: error.message,
    code: error.code,
    sqlState: error.sqlState,
    sqlMessage: error.sqlMessage
  });
  
  if (error.code === 'ECONNREFUSED') {
    return res.status(500).json({ error: 'Database connection failed' });
  }
  if (error.code === 'ER_DUP_ENTRY') {
    return res.status(400).json({ error: 'Resource already exists' });
  }
  if (error.code === 'ER_BAD_DB_ERROR') {
    return res.status(500).json({ error: 'Database not found' });
  }
  
  res.status(500).json({ error: `${operation} failed` });
};

// Consolidated database operations
const dbOperations = {
  async executeQuery(config, query, params = []) {
    let connection;
    try {
      connection = await Database.connect(config);
      const [result] = await connection.execute(query, params);
      return result;
    } finally {
      if (connection) await connection.end();
    }
  },

  async checkOwnership(sellerId, categoryId) {
    const [category] = await this.executeQuery(
      DB_CONFIG.categories,
      'SELECT id, parent_id, seller_id FROM categories WHERE id = ? AND is_active = TRUE',
      [categoryId]
    );
    
    if (category.length === 0) return { exists: false };
    
    const cat = category[0];
    if (cat.seller_id !== sellerId) return { exists: true, owned: false };
    
    return { exists: true, owned: true, category: cat };
  },

  async getCategoryLevel(categoryId) {
    let level = 0;
    let currentId = categoryId;
    
    while (currentId) {
      const [parent] = await this.executeQuery(
        DB_CONFIG.categories,
        'SELECT parent_id FROM categories WHERE id = ?',
        [currentId]
      );
      
      if (parent.length === 0) break;
      
      level++;
      currentId = parent[0].parent_id;
      
      if (level > 10) break; // Safety check
    }
    
    return level;
  }
};

const authLimiter = createRateLimiter(15 * 60 * 1000, 15, 'auth-');

// ===== ROUTES =====

// Basic Routes
app.get('/', (req, res) => {
  res.json({
    message: 'Townzy Backend API',
    version: CONFIG.version,
    status: 'running',
    timestamp: new Date().toISOString(),
    features: ['Authentication', 'Seller Registration', 'Categories Management', 'Seller Category CRUD'],
    endpoints: {
      public: ['GET /', 'GET /test', 'GET /categories', 'GET /debug/db-test'],
      auth: ['POST /auth/login', 'POST /auth/register'],
      seller: [
        'POST /seller/register', 'POST /seller/login', 
        'GET /seller/categories', 'POST /seller/categories',
        'PUT /seller/categories/:id', 'DELETE /seller/categories/:id'
      ],
      admin: ['POST /categories', 'POST /seller/categories']
    }
  });
});

app.get('/test', (req, res) => {
  res.json({ 
    message: 'Server working!', 
    timestamp: new Date().toISOString(),
    environment: CONFIG.isDevelopment ? 'development' : 'production'
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  const checkDatabase = async (config) => {
    try {
      const connection = await Database.connect(config);
      await connection.execute('SELECT 1');
      await connection.end();
      return 'connected';
    } catch (error) {
      console.error(`Health check failed for ${config.database}:`, error.message);
      return 'disconnected';
    }
  };

  const health = {
    status: 'healthy',
    version: CONFIG.version,
    timestamp: new Date().toISOString(),
    databases: {
      auth: await checkDatabase(DB_CONFIG.auth),
      categories: await checkDatabase(DB_CONFIG.categories)
    }
  };

  const isHealthy = Object.values(health.databases).every(status => status === 'connected');
  res.status(isHealthy ? 200 : 503).json(health);
});

// Debug endpoints
app.get('/debug/db-test', async (req, res) => {
  try {
    console.log('🔍 Testing database connections...');
    
    const authTest = await dbOperations.executeQuery(DB_CONFIG.auth, 'SELECT COUNT(*) as count FROM users');
    const catTest = await dbOperations.executeQuery(DB_CONFIG.categories, 'SELECT COUNT(*) as count FROM categories');
    
    res.json({
      message: 'Database connections successful',
      timestamp: new Date().toISOString(),
      auth_db: { status: 'connected', users_count: authTest[0].count },
      categories_db: { status: 'connected', categories_count: catTest[0].count }
    });
    
  } catch (error) {
    console.error('❌ DB Test Error:', {
      message: error.message,
      code: error.code,
      sqlState: error.sqlState
    });
    res.status(500).json({ 
      error: 'Database test failed', 
      details: error.message,
      code: error.code,
      timestamp: new Date().toISOString()
    });
  }
});

// ===== USER AUTHENTICATION =====
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    if (!validate.username(username)) return res.status(400).json({ error: 'Invalid username (3-50 chars, alphanumeric + underscore only)' });
    if (!validate.password(password)) return res.status(400).json({ error: 'Invalid password (6-128 characters)' });
    if (!validate.email(email)) return res.status(400).json({ error: 'Invalid email format' });

    const existing = await dbOperations.executeQuery(
      DB_CONFIG.auth,
      'SELECT id FROM users WHERE username = ? OR (email IS NOT NULL AND email = ?)',
      [username, email || '']
    );
    if (existing.length > 0) return res.status(400).json({ error: 'Username or email already exists' });

    const hashedPassword = await bcrypt.hash(password, CONFIG.saltRounds);
    const result = await dbOperations.executeQuery(
      DB_CONFIG.auth,
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email || null]
    );

    const token = jwt.sign(
      { userId: result.insertId, username, role: 'user' }, 
      CONFIG.jwtSecret, 
      { expiresIn: '24h' }
    );

    console.log(`✅ User registered: ${username} (ID: ${result.insertId})`);
    res.status(201).json({
      message: 'Registration successful',
      token,
      user: { id: result.insertId, username, email: email || null }
    });

  } catch (error) {
    handleError(res, error, 'User Registration');
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!validate.username(username) || !validate.password(password)) {
      return res.status(400).json({ error: 'Invalid credentials format' });
    }

    const users = await dbOperations.executeQuery(
      DB_CONFIG.auth,
      'SELECT id, username, password, email FROM users WHERE username = ? AND is_active = TRUE',
      [username]
    );

    if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    await dbOperations.executeQuery(DB_CONFIG.auth, 'UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: 'user' }, 
      CONFIG.jwtSecret, 
      { expiresIn: '24h' }
    );

    console.log(`✅ User logged in: ${user.username}`);
    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });

  } catch (error) {
    handleError(res, error, 'User Login');
  }
});

// ===== SELLER AUTHENTICATION =====
app.post('/seller/register', authLimiter, async (req, res) => {
  try {
    const { business_name, shop_address, mobile_number, password, email } = req.body;
    
    if (!business_name?.trim()) return res.status(400).json({ error: 'Business name is required' });
    if (!shop_address?.trim()) return res.status(400).json({ error: 'Shop address is required' });
    if (!validate.mobile(mobile_number)) return res.status(400).json({ error: 'Invalid mobile number (10-15 digits only)' });
    if (!validate.password(password)) return res.status(400).json({ error: 'Invalid password (6-128 characters)' });
    if (!validate.email(email)) return res.status(400).json({ error: 'Invalid email format' });

    const existing = await dbOperations.executeQuery(
      DB_CONFIG.auth,
      'SELECT id FROM sellers WHERE mobile_number = ?',
      [mobile_number]
    );
    if (existing.length > 0) return res.status(400).json({ error: 'Mobile number already registered' });

    // Generate unique seller ID
    let sellerId;
    let attempts = 0;
    do {
      sellerId = generateSellerId();
      attempts++;
      const check = await dbOperations.executeQuery(
        DB_CONFIG.auth, 
        'SELECT id FROM sellers WHERE seller_id = ?', 
        [sellerId]
      );
      if (check.length === 0) break;
    } while (attempts < 10);

    if (attempts >= 10) return res.status(500).json({ error: 'Unable to generate unique seller ID' });

    const hashedPassword = await bcrypt.hash(password, CONFIG.saltRounds);
    const result = await dbOperations.executeQuery(
      DB_CONFIG.auth,
      'INSERT INTO sellers (seller_id, business_name, shop_address, mobile_number, password, email) VALUES (?, ?, ?, ?, ?, ?)',
      [sellerId, business_name.trim(), shop_address.trim(), mobile_number, hashedPassword, email || null]
    );

    const token = jwt.sign(
      { 
        sellerId, 
        businessName: business_name.trim(), 
        role: 'seller',
        id: result.insertId
      }, 
      CONFIG.jwtSecret, 
      { expiresIn: '24h' }
    );

    console.log(`✅ Seller registered: ${business_name} (ID: ${sellerId})`);
    res.status(201).json({
      message: 'Seller registration successful',
      token,
      seller: { 
        id: result.insertId, 
        seller_id: sellerId, 
        business_name: business_name.trim(), 
        shop_address: shop_address.trim(), 
        mobile_number, 
        email: email || null 
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller Registration');
  }
});

app.post('/seller/login', authLimiter, async (req, res) => {
  try {
    const { seller_id, mobile_number, password } = req.body;
    
    if (!password) return res.status(400).json({ error: 'Password is required' });
    if (!seller_id && !mobile_number) {
      return res.status(400).json({ error: 'Either seller ID or mobile number is required' });
    }

    let query = 'SELECT * FROM sellers WHERE is_active = TRUE AND ';
    let params = [];
    
    if (seller_id) {
      query += 'seller_id = ?';
      params = [seller_id];
    } else {
      query += 'mobile_number = ?';
      params = [mobile_number];
    }

    const sellers = await dbOperations.executeQuery(DB_CONFIG.auth, query, params);
    if (sellers.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const seller = sellers[0];
    const isValidPassword = await bcrypt.compare(password, seller.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

    await dbOperations.executeQuery(DB_CONFIG.auth, 'UPDATE sellers SET last_login = NOW() WHERE id = ?', [seller.id]);

    const token = jwt.sign(
      { 
        sellerId: seller.seller_id, 
        businessName: seller.business_name, 
        role: 'seller',
        id: seller.id
      }, 
      CONFIG.jwtSecret, 
      { expiresIn: '24h' }
    );

    console.log(`✅ Seller logged in: ${seller.business_name} (${seller.seller_id})`);
    res.json({
      message: 'Seller login successful',
      token,
      seller: { 
        id: seller.id, 
        seller_id: seller.seller_id, 
        business_name: seller.business_name, 
        shop_address: seller.shop_address,
        mobile_number: seller.mobile_number,
        email: seller.email 
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller Login');
  }
});

// ===== CATEGORIES (PUBLIC) =====
app.get('/categories', async (req, res) => {
  try {
    const rows = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      `SELECT c.*, COUNT(sub.id) as subcategory_count
       FROM categories c
       LEFT JOIN categories sub ON c.id = sub.parent_id
       WHERE c.parent_id IS NULL AND c.is_active = TRUE
       GROUP BY c.id
       ORDER BY c.sort_order`
    );
    
    const categories = rows.map(cat => ({
      ...cat,
      image_url: cat.image_url || generateImageUrl(req, cat.id),
      has_subcategories: cat.subcategory_count > 0,
      seller_name: cat.seller_id ? 'Seller' : 'System'
    }));
    
    console.log(`✅ Categories retrieved: ${rows.length} items`);
    res.json({ data: categories, total_count: rows.length });

  } catch (error) {
    handleError(res, error, 'Categories fetch');
  }
});

app.get('/categories/:id', async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });
    
    const subcategories = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT * FROM categories WHERE parent_id = ? AND is_active = TRUE ORDER BY sort_order',
      [categoryId]
    );
    
    if (subcategories.length === 0) {
      const category = await dbOperations.executeQuery(
        DB_CONFIG.categories,
        'SELECT * FROM categories WHERE id = ? AND is_active = TRUE',
        [categoryId]
      );
      
      if (category.length === 0) {
        return res.status(404).json({ error: 'Category not found' });
      }
      
      return res.json({ 
        success: true, 
        data: [{
          ...category[0],
          image_url: category[0].image_url || generateImageUrl(req, category[0].id),
          seller_name: category[0].seller_id ? 'Seller' : 'System'
        }], 
        total_count: 1,
        is_leaf: true
      });
    }
    
    const enhancedSubs = subcategories.map(sub => ({
      ...sub,
      image_url: sub.image_url || generateImageUrl(req, sub.id),
      seller_name: sub.seller_id ? 'Seller' : 'System'
    }));
    
    console.log(`✅ Subcategories for category ${categoryId}: ${subcategories.length} items`);
    res.json({ success: true, data: enhancedSubs, total_count: subcategories.length });

  } catch (error) {
    handleError(res, error, 'Category/Subcategories fetch');
  }
});

app.get('/categories/:id/subcategories', async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });
    
    const subcategories = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT * FROM categories WHERE parent_id = ? AND is_active = TRUE ORDER BY sort_order',
      [categoryId]
    );
    
    const enhancedSubs = subcategories.map(sub => ({
      ...sub,
      image_url: sub.image_url || generateImageUrl(req, sub.id),
      seller_name: sub.seller_id ? 'Seller' : 'System'
    }));
    
    console.log(`✅ Subcategories for category ${categoryId}: ${subcategories.length} items`);
    res.json({ success: true, data: enhancedSubs, total_count: subcategories.length });

  } catch (error) {
    handleError(res, error, 'Subcategories fetch');
  }
});

// ===== SELLER CATEGORIES MANAGEMENT =====
app.get('/seller/categories', authenticateSeller, async (req, res) => {
  try {
    const rows = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      `SELECT c.*, COUNT(sub.id) as subcategory_count
       FROM categories c
       LEFT JOIN categories sub ON c.id = sub.parent_id
       WHERE c.seller_id = ? AND c.parent_id IS NULL AND c.is_active = TRUE
       GROUP BY c.id
       ORDER BY c.sort_order`,
      [req.seller.sellerId]
    );
    
    const categories = rows.map(cat => ({
      ...cat,
      image_url: cat.image_url || generateImageUrl(req, cat.id),
      has_subcategories: cat.subcategory_count > 0
    }));
    
    console.log(`✅ Seller categories for ${req.seller.sellerId}: ${rows.length} items`);
    res.json({ success: true, data: categories, total_count: rows.length });

  } catch (error) {
    handleError(res, error, 'Seller categories fetch');
  }
});

app.post('/seller/categories', authenticateSeller, async (req, res) => {
  try {
    const { name, description, color, icon, parent_id } = req.body;
    
    if (!validate.categoryName(name)) {
      return res.status(400).json({ error: 'Category name is required and must be 1-100 characters' });
    }

    const existing = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id FROM categories WHERE name = ? AND seller_id = ? AND parent_id = ? AND is_active = TRUE',
      [name.trim(), req.seller.sellerId, parent_id || null]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'You already have a category with this name at this level' });
    }

    const result = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'INSERT INTO categories (name, description, color, parent_id, seller_id, icon, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name.trim(), description || '', color || '#2196F3', parent_id || null, req.seller.sellerId, icon || 'category', 0]
    );

    console.log(`✅ Category created by seller ${req.seller.sellerId}: ${name.trim()}`);
    res.status(201).json({
      message: 'Category created successfully',
      category: { 
        id: result.insertId, 
        name: name.trim(), 
        description: description || '',
        color: color || '#2196F3',
        seller_id: req.seller.sellerId,
        parent_id: parent_id || null
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller category creation');
  }
});

// NEW: Edit seller category/subcategory (switch between categories)
app.put('/seller/categories/:id', authenticateSeller, async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });

    const { name, description, color, icon, parent_id } = req.body;
    
    // Check ownership and get current category details
    const ownership = await dbOperations.checkOwnership(req.seller.sellerId, categoryId);
    if (!ownership.exists) return res.status(404).json({ error: 'Category not found' });
    if (!ownership.owned) return res.status(403).json({ error: 'You can only edit your own categories' });

    // Get category level to determine what can be edited
    const level = await dbOperations.getCategoryLevel(categoryId);
    
    // Only allow editing sub-subcategories (level 2) - the deepest level with product data
    if (level < 2) {
      return res.status(400).json({ 
        error: 'You can only edit sub-subcategories (the deepest level containing product data)' 
      });
    }

    // Validate new parent if provided
    if (parent_id && parent_id !== ownership.category.parent_id) {
      const newParent = await dbOperations.executeQuery(
        DB_CONFIG.categories,
        'SELECT id, parent_id FROM categories WHERE id = ? AND is_active = TRUE',
        [parent_id]
      );
      
      if (newParent.length === 0) {
        return res.status(400).json({ error: 'New parent category not found' });
      }
      
      // Ensure new parent is a subcategory (level 1), not main category (level 0)
      const newParentLevel = await dbOperations.getCategoryLevel(parent_id);
      if (newParentLevel !== 1) {
        return res.status(400).json({ error: 'Can only move sub-subcategories under subcategories' });
      }
    }

    // Check for duplicate names in new location
    if (name && name.trim() !== ownership.category.name) {
      const targetParentId = parent_id || ownership.category.parent_id;
      const duplicate = await dbOperations.executeQuery(
        DB_CONFIG.categories,
        'SELECT id FROM categories WHERE name = ? AND parent_id = ? AND seller_id = ? AND id != ? AND is_active = TRUE',
        [name.trim(), targetParentId, req.seller.sellerId, categoryId]
      );
      
      if (duplicate.length > 0) {
        return res.status(400).json({ error: 'A category with this name already exists in the target location' });
      }
    }

    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];
    
    if (name && validate.categoryName(name)) {
      updateFields.push('name = ?');
      updateValues.push(name.trim());
    }
    if (description !== undefined) {
      updateFields.push('description = ?');
      updateValues.push(description || '');
    }
    if (color) {
      updateFields.push('color = ?');
      updateValues.push(color);
    }
    if (icon) {
      updateFields.push('icon = ?');
      updateValues.push(icon);
    }
    if (parent_id && parent_id !== ownership.category.parent_id) {
      updateFields.push('parent_id = ?');
      updateValues.push(parent_id);
    }
    
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    updateFields.push('updated_at = NOW()');
    updateValues.push(categoryId, req.seller.sellerId);

    await dbOperations.executeQuery(
      DB_CONFIG.categories,
      `UPDATE categories SET ${updateFields.join(', ')} WHERE id = ? AND seller_id = ?`,
      updateValues
    );

    // Get updated category
    const updated = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT * FROM categories WHERE id = ? AND seller_id = ?',
      [categoryId, req.seller.sellerId]
    );

    console.log(`✅ Category updated by seller ${req.seller.sellerId}: ID ${categoryId}`);
    res.json({
      message: 'Category updated successfully',
      category: {
        ...updated[0],
        image_url: updated[0].image_url || generateImageUrl(req, updated[0].id)
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller category update');
  }
});

// NEW: Delete seller sub-subcategory (contains product data)
app.delete('/seller/categories/:id', authenticateSeller, async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });

    // Check ownership
    const ownership = await dbOperations.checkOwnership(req.seller.sellerId, categoryId);
    if (!ownership.exists) return res.status(404).json({ error: 'Category not found' });
    if (!ownership.owned) return res.status(403).json({ error: 'You can only delete your own categories' });

    // Get category level to ensure only sub-subcategories can be deleted
    const level = await dbOperations.getCategoryLevel(categoryId);
    
    // Only allow deleting sub-subcategories (level 2) - the deepest level with product data
    if (level < 2) {
      return res.status(400).json({ 
        error: 'You can only delete sub-subcategories (the deepest level containing product data)' 
      });
    }

    // Check if this category has children (shouldn't for sub-subcategories, but safety check)
    const children = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT COUNT(*) as count FROM categories WHERE parent_id = ? AND is_active = TRUE',
      [categoryId]
    );

    if (children[0].count > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete category that has subcategories. Delete subcategories first.' 
      });
    }

    // Store category info before deletion for response
    const categoryInfo = ownership.category;

    // Hard delete the category (this will cascade delete any linked product data via foreign keys)
    await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'DELETE FROM categories WHERE id = ? AND seller_id = ?',
      [categoryId, req.seller.sellerId]
    );

    console.log(`✅ Sub-subcategory deleted by seller ${req.seller.sellerId}: ID ${categoryId}`);
    res.json({
      message: 'Sub-subcategory and all linked product data deleted successfully',
      deleted_category: {
        id: categoryId,
        name: categoryInfo.name,
        parent_id: categoryInfo.parent_id,
        seller_id: categoryInfo.seller_id
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller category deletion');
  }
});

// Get seller subcategories for specific category
app.get('/seller/categories/:id/subcategories', authenticateSeller, async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });
    
    // Verify parent category ownership
    const parent = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id FROM categories WHERE id = ? AND seller_id = ? AND is_active = TRUE',
      [categoryId, req.seller.sellerId]
    );
    if (parent.length === 0) {
      return res.status(404).json({ error: 'Parent category not found or not owned by seller' });
    }
    
    const subcategories = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT * FROM categories WHERE parent_id = ? AND seller_id = ? AND is_active = TRUE ORDER BY sort_order',
      [categoryId, req.seller.sellerId]
    );
    
    const enhancedSubs = subcategories.map(sub => ({
      ...sub,
      image_url: sub.image_url || generateImageUrl(req, sub.id)
    }));
    
    console.log(`✅ Subcategories for seller ${req.seller.sellerId}, category ${categoryId}: ${subcategories.length} items`);
    res.json({ success: true, data: enhancedSubs, total_count: subcategories.length });

  } catch (error) {
    handleError(res, error, 'Seller subcategories fetch');
  }
});

// Create seller subcategory
app.post('/seller/categories/:id/subcategories', authenticateSeller, async (req, res) => {
  try {
    const categoryId = parseInt(req.params.id);
    if (!validate.id(categoryId)) return res.status(400).json({ error: 'Invalid category ID' });
    
    const { name, description, color, icon } = req.body;
    if (!validate.categoryName(name)) {
      return res.status(400).json({ error: 'Subcategory name is required and must be 1-100 characters' });
    }

    // Verify parent category ownership
    const parent = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id FROM categories WHERE id = ? AND seller_id = ? AND is_active = TRUE',
      [categoryId, req.seller.sellerId]
    );
    if (parent.length === 0) return res.status(404).json({ error: 'Parent category not found or not owned by seller' });

    // Check if subcategory already exists for this seller
    const existingSub = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id FROM categories WHERE name = ? AND parent_id = ? AND seller_id = ? AND is_active = TRUE',
      [name.trim(), categoryId, req.seller.sellerId]
    );
    if (existingSub.length > 0) {
      return res.status(400).json({ error: 'Subcategory with this name already exists' });
    }

    const result = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'INSERT INTO categories (name, description, color, parent_id, seller_id, icon, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name.trim(), description || '', color || '#2196F3', categoryId, req.seller.sellerId, icon || 'category', 0]
    );

    console.log(`✅ Subcategory created by seller ${req.seller.sellerId}: ${name.trim()}`);
    res.status(201).json({
      message: 'Subcategory created successfully',
      subcategory: { 
        id: result.insertId, 
        name: name.trim(), 
        parent_id: categoryId, 
        seller_id: req.seller.sellerId,
        description: description || '',
        color: color || '#2196F3'
      }
    });

  } catch (error) {
    handleError(res, error, 'Seller subcategory creation');
  }
});

// NEW: Get all available main categories and subcategories for switching
app.get('/seller/categories/available', authenticateSeller, async (req, res) => {
  try {
    // Get all main categories (level 0)
    const mainCategories = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id, name, description, color, icon FROM categories WHERE parent_id IS NULL AND is_active = TRUE ORDER BY sort_order'
    );

    // Get all subcategories (level 1) 
    const subCategories = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT id, name, description, color, icon, parent_id FROM categories WHERE parent_id IS NOT NULL AND is_active = TRUE ORDER BY parent_id, sort_order'
    );

    // Group subcategories under their main categories
    const categoriesWithSubs = mainCategories.map(main => ({
      ...main,
      subcategories: subCategories.filter(sub => sub.parent_id === main.id)
    }));

    console.log(`✅ Available categories for switching retrieved for seller ${req.seller.sellerId}`);
    res.json({ 
      success: true, 
      data: categoriesWithSubs,
      message: 'Available categories for switching retrieved successfully'
    });

  } catch (error) {
    handleError(res, error, 'Available categories fetch');
  }
});

// ===== DEBUG ENDPOINTS =====
app.get('/debug/categories-raw', async (req, res) => {
  try {
    console.log('🔍 Testing raw categories query...');
    
    const rows = await dbOperations.executeQuery(
      DB_CONFIG.categories,
      'SELECT * FROM categories WHERE parent_id IS NULL LIMIT 5'
    );
    
    res.json({
      message: 'Raw categories query successful',
      data: rows,
      count: rows.length,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Raw Categories Error:', {
      message: error.message,
      code: error.code,
      sqlState: error.sqlState
    });
    res.status(500).json({ 
      error: 'Raw categories test failed', 
      details: error.message,
      code: error.code,
      sqlState: error.sqlState,
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/debug/config', (req, res) => {
  const sanitizedConfig = {
    server: {
      port: CONFIG.port,
      environment: CONFIG.isDevelopment ? 'development' : 'production',
      version: CONFIG.version
    },
    database: {
      auth: {
        host: DB_CONFIG.auth.host,
        database: DB_CONFIG.auth.database,
        user: DB_CONFIG.auth.user,
        password: DB_CONFIG.auth.password ? '[SET]' : '[NOT SET]'
      },
      categories: {
        host: DB_CONFIG.categories.host,
        database: DB_CONFIG.categories.database,
        user: DB_CONFIG.categories.user,
        password: DB_CONFIG.categories.password ? '[SET]' : '[NOT SET]'
      }
    },
    env_variables: {
      NODE_ENV: process.env.NODE_ENV || '[NOT SET]',
      JWT_SECRET: process.env.JWT_SECRET ? '[SET]' : '[NOT SET]',
      DB_HOST: process.env.DB_HOST || '[NOT SET]',
      DB_USER: process.env.DB_USER || '[NOT SET]',
      DB_PASSWORD: process.env.DB_PASSWORD ? '[SET]' : '[NOT SET]'
    }
  };
  
  res.json({
    message: 'Configuration debug info',
    config: sanitizedConfig,
    timestamp: new Date().toISOString()
  });
});

// ===== ERROR HANDLING =====
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found', 
    requested: `${req.method} ${req.originalUrl}`,
    available_routes: [
      'GET /',
      'GET /test', 
      'GET /api/health',
      'GET /debug/db-test',
      'GET /debug/categories-raw',
      'GET /debug/config',
      'POST /auth/register',
      'POST /auth/login', 
      'POST /seller/register',
      'POST /seller/login',
      'GET /categories',
      'GET /categories/:id',
      'GET /categories/:id/subcategories',
      'GET /seller/categories',
      'POST /seller/categories',
      'PUT /seller/categories/:id',
      'DELETE /seller/categories/:id',
      'GET /seller/categories/available',
      'GET /seller/categories/:id/subcategories',
      'POST /seller/categories/:id/subcategories'
    ],
    timestamp: new Date().toISOString()
  });
});

app.use((error, req, res, next) => {
  console.error('❌ Global error handler:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  res.status(500).json({ 
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// ===== SERVER STARTUP =====
async function startServer() {
  try {
    console.log('🚀 Starting Townzy Backend Server...');
    console.log(`📊 Node.js version: ${process.version}`);
    console.log(`🔧 Environment: ${CONFIG.isDevelopment ? 'development' : 'production'}`);
    console.log(`📡 Port: ${CONFIG.port}`);
    console.log(`🔑 JWT Secret: ${CONFIG.jwtSecret.length > 10 ? '[SET]' : '[WEAK/DEFAULT]'}`);
    
    console.log('🔍 Testing database connections...');
    
    try {
      const authTest = await Database.connect(DB_CONFIG.auth);
      await authTest.execute('SELECT 1');
      await authTest.end();
      console.log('✅ Auth database connection test passed');
    } catch (error) {
      console.error('❌ Auth database connection test failed:', {
        message: error.message,
        code: error.code,
        host: DB_CONFIG.auth.host,
        database: DB_CONFIG.auth.database,
        user: DB_CONFIG.auth.user
      });
      throw new Error(`Auth database connection failed: ${error.message}`);
    }

    try {
      const categoriesTest = await Database.connect(DB_CONFIG.categories);
      await categoriesTest.execute('SELECT 1');
      await categoriesTest.end();
      console.log('✅ Categories database connection test passed');
    } catch (error) {
      console.error('❌ Categories database connection test failed:', {
        message: error.message,
        code: error.code,
        host: DB_CONFIG.categories.host,
        database: DB_CONFIG.categories.database,
        user: DB_CONFIG.categories.user
      });
      throw new Error(`Categories database connection failed: ${error.message}`);
    }
    
    console.log('🔧 Initializing databases...');
    await Database.initialize();
    
    const server = app.listen(CONFIG.port, () => {
      console.log('');
      console.log('🎉 =================================');
      console.log('✅ TOWNZY BACKEND SERVER STARTED');
      console.log('🎉 =================================');
      console.log(`📡 Server URL: http://localhost:${CONFIG.port}`);
      console.log(`🔧 Environment: ${CONFIG.isDevelopment ? 'development' : 'production'}`);
      console.log(`📊 Node.js: ${process.version}`);
      console.log(`🏪 Features: Users + Sellers + Categories + CRUD Operations`);
      console.log('');
      console.log('📋 Available endpoints:');
      console.log('  🔓 Public:');
      console.log('    GET  /                      - API info');
      console.log('    GET  /test                  - Server status');
      console.log('    GET  /categories            - All categories');
      console.log('    GET  /categories/:id        - Category/subcategories');
      console.log('    GET  /categories/:id/subcategories');
      console.log('  👤 User Auth:');
      console.log('    POST /auth/register         - User registration');
      console.log('    POST /auth/login            - User login');
      console.log('  🏪 Seller Auth & CRUD:');
      console.log('    POST /seller/register       - Seller registration');
      console.log('    POST /seller/login          - Seller login');
      console.log('    GET  /seller/categories     - Seller categories');
      console.log('    POST /seller/categories     - Create category');
      console.log('    PUT  /seller/categories/:id - Edit/switch sub-subcategory');
      console.log('    DELETE /seller/categories/:id - Delete sub-subcategory');
      console.log('    GET  /seller/categories/available - Available categories for switching');
      console.log('    GET  /seller/categories/:id/subcategories');
      console.log('    POST /seller/categories/:id/subcategories');
      console.log('  📊 Debug:');
      console.log('    GET  /debug/db-test         - Database test');
      console.log('    GET  /debug/categories-raw  - Raw categories');
      console.log('    GET  /debug/config          - Config info');
      console.log('    GET  /api/health            - Health check');
      console.log('');
      console.log('🚀 Ready for connections!');
      console.log('🎉 =================================');
      console.log('');
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${CONFIG.port} is already in use`);
        console.error('💡 Try changing the PORT in your .env file or stop the other process');
      } else {
        console.error('❌ Server error:', error.message);
      }
      process.exit(1);
    });
    
  } catch (error) {
    console.error('');
    console.error('❌ ===================================');
    console.error('💥 SERVER STARTUP FAILED');
    console.error('❌ ===================================');
    console.error(`💥 Error: ${error.message}`);
    console.error('');
    console.error('🔍 Error Details:', {
      message: error.message,
      code: error.code,
      errno: error.errno,
      stack: error.stack?.split('\n')[0]
    });
    console.error('');
    console.error('🛠️  Troubleshooting Steps:');
    console.error('   1. ✅ Check if MySQL server is running');
    console.error('      - Windows: Services → MySQL');
    console.error('      - Mac: brew services list | grep mysql');
    console.error('      - Linux: sudo systemctl status mysql');
    console.error('');
    console.error('   2. ✅ Verify database credentials in .env:');
    console.error(`      - DB_HOST=${DB_CONFIG.auth.host}`);
    console.error(`      - DB_USER=${DB_CONFIG.auth.user}`);
    console.error(`      - DB_PASSWORD=${DB_CONFIG.auth.password ? '[SET]' : '[EMPTY]'}`);
    console.error('');
    console.error('   3. ✅ Test MySQL connection manually:');
    console.error(`      mysql -h ${DB_CONFIG.auth.host} -u ${DB_CONFIG.auth.user} -p`);
    console.error('');
    console.error('   4. ✅ Check MySQL user permissions:');
    console.error('      - User must have CREATE, DROP, INSERT, SELECT privileges');
    console.error('      - Grant with: GRANT ALL PRIVILEGES ON *.* TO \'user\'@\'localhost\';');
    console.error('');
    console.error('   5. ✅ Verify .env file exists and is properly formatted');
    console.error('');
    console.error('❌ ===================================');
    process.exit(1);
  }
}

// Graceful shutdown handlers
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT signal (Ctrl+C)');
  console.log('🔄 Shutting down gracefully...');
  console.log('👋 Goodbye!');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM signal');
  console.log('🔄 Shutting down gracefully...');
  console.log('👋 Goodbye!');
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('💥 ===================================');
  console.error('💥 UNCAUGHT EXCEPTION');
  console.error('💥 ===================================');
  console.error('💥 Error:', error.message);
  console.error('📍 Stack:', error.stack);
  console.error('💥 ===================================');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 ===================================');
  console.error('💥 UNHANDLED PROMISE REJECTION');
  console.error('💥 ===================================');
  console.error('💥 Promise:', promise);
  console.error('💥 Reason:', reason);
  console.error('💥 ===================================');
  process.exit(1);
});

console.log('🏁 ===================================');
console.log('🏁 INITIALIZING TOWNZY BACKEND');
console.log('🏁 ===================================');
console.log(`🕐 Timestamp: ${new Date().toISOString()}`);
console.log(`🌍 Working Directory: ${process.cwd()}`);
console.log(`📄 Script: ${__filename}`);
console.log('🏁 ===================================');

startServer().catch((error) => {
  console.error('💥 Fatal startup error:', error.message);
  process.exit(1);
});