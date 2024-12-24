import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import winston from 'winston';
import { KiteConnect } from 'kiteconnect';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Ignore SSL certificate errors (for development purposes only)
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

dotenv.config();

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

const app = express();
const port = process.env.NODE_PORT || 80;

// Middleware
app.use(cors());
app.use(express.json());

// Kite Connect instance store
const kiteInstances = new Map();

// Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { apiKey, apiSecret } = req.body;
    const kite = new KiteConnect({ api_key: apiKey });
    const loginUrl = kite.getLoginURL();
    
    // Store kite instance
    kiteInstances.set(apiKey, { kite, apiSecret });
    
    res.json({ loginUrl });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Failed to generate login URL' });
  }
});

app.post('/api/auth/callback', async (req, res) => {
  try {
    const { requestToken, apiKey } = req.body;
    const instance = kiteInstances.get(apiKey);
    
    if (!instance) {
      return res.status(400).json({ error: 'Invalid API key' });
    }

    const { kite, apiSecret } = instance;
    const response = await kite.generateSession(requestToken, apiSecret);
    
    // Update kite instance with access token
    kite.setAccessToken(response.access_token);
    
    res.json({ accessToken: response.access_token });
  } catch (error) {
    logger.error('Callback error:', error);
    res.status(500).json({ error: 'Failed to generate session' });
  }
});

app.get('/api/market/instruments', async (req, res) => {
  try {
    const { apiKey, apikey } = req.headers;
    const instance = kiteInstances.get(apiKey || apikey);
    
    if (!instance) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const instruments = await instance.kite.getInstruments(['NSE']);
    res.json(instruments);
  } catch (error) {
    logger.error('Get instruments error:', error);
    res.status(500).json({ error: 'Failed to fetch instruments' });
  }
});

app.get('/api/user/profile', async (req, res) => {
  try {
    const { apiKey, apikey } = req.headers;
    const { symbol } = req.params;
    const instance = kiteInstances.get(apiKey || apikey);
    
    if (!instance) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const quote = await instance.kite.getProfile();
    res.json(quote);
  } catch (error) {
    logger.error('Get quote error:', error);
    res.status(500).json({ error: 'Failed to fetch quote' });
  }
});

app.get('/api/market/quote/:symbol', async (req, res) => {
  try {
    const { apiKey, apikey } = req.headers;
    const { symbol } = req.params;
    const instance = kiteInstances.get(apiKey || apikey);
    
    if (!instance) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const quote = await instance.kite.getQuote([symbol]);
    res.json(quote[symbol]);
  } catch (error) {
    logger.error('Get quote error:', error);
    res.status(500).json({ error: 'Failed to fetch quote' });
  }
});

app.get('/api/trading/positions', async (req, res) => {
  try {
    const { apiKey, apikey } = req.headers;
    const instance = kiteInstances.get(apiKey || apikey);
    
    if (!instance) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const positions = await instance.kite.getPositions();
    res.json(positions);
  } catch (error) {
    logger.error('Get positions error:', error);
    res.status(500).json({ error: 'Failed to fetch positions' });
  }
});

app.post('/api/trading/orders', async (req, res) => {
  try {
    const { apiKey, apikey } = req.headers;
    const { symbol, type, quantity, price } = req.body;
    const instance = kiteInstances.get(apiKey || apikey);
    
    if (!instance) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const order = await instance.kite.placeOrder('regular', {
      tradingsymbol: symbol,
      exchange: 'NSE',
      transaction_type: type,
      quantity,
      price,
      product: 'CNC',
      order_type: 'LIMIT'
    });

    res.json(order);
  } catch (error) {
    logger.error('Place order error:', error);
    res.status(500).json({ error: 'Failed to place order' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
  logger.info(`Server running on port ${port}`);
});