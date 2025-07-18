const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config(); // Load environment variables from .env

const app = express();
const PORT = process.env.PORT || 8080;
const WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;

// Middleware to get raw body
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

// Purchase Webhook Endpoint
app.post('/webhook/purchase', (req, res) => {
  try {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    const rawBody = req.rawBody;

    if (!WEBHOOK_SECRET) {
      console.error('❌ SHOPIFY_WEBHOOK_SECRET is missing in .env');
      return res.status(500).send('Server misconfigured');
    }

    if (!hmacHeader || !rawBody) {
      console.warn('⚠️ Missing HMAC header or body');
      return res.status(400).send('Bad Request');
    }

    const generatedHmac = crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(rawBody, 'utf8')
      .digest('base64');

    const isVerified = crypto.timingSafeEqual(
      Buffer.from(generatedHmac, 'utf8'),
      Buffer.from(hmacHeader, 'utf8')
    );

    if (!isVerified) {
      console.warn('❌ Invalid HMAC verification failed');
      return res.status(401).send('Unauthorized');
    }

    // ✅ HMAC verified
    console.log('✅ Webhook Verified');
    console.log('📦 Purchase Webhook Data:', req.body);

    // TODO: Send data to Meta CAPI, DB, etc.
    return res.status(200).send('Webhook verified & received');
  } catch (error) {
    console.error('❌ Internal server error:', error.message);
    return res.status(500).send('Internal Server Error');
  }
});

// Health Check
app.get('/', (req, res) => {
  res.send('✅ Meta CAPI Purchase Webhook is live!');
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});



