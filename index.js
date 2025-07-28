const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const META_PIXEL_ID = process.env.META_PIXEL_ID;
const META_CAPI_TOKEN = process.env.META_CAPI_TOKEN;

// Middleware: Parse raw body for HMAC validation
app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString('utf8');
    }
  })
);

// ✅ Purchase Webhook
app.post('/webhook/purchase', async (req, res) => {
  try {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256') || '';
    const rawBody = req.rawBody || '';

    const isTestRequest = !hmacHeader || hmacHeader === 'dummy_hmac';

    if (!isTestRequest) {
      if (!SHOPIFY_WEBHOOK_SECRET) {
        console.error('❌ Missing SHOPIFY_WEBHOOK_SECRET');
        return res.status(500).send('Server misconfigured');
      }

      const generatedHmac = crypto
        .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
        .update(rawBody, 'utf8')
        .digest('base64');

      const isVerified = crypto.timingSafeEqual(
        Buffer.from(generatedHmac, 'utf8'),
        Buffer.from(hmacHeader, 'utf8')
      );

      if (!isVerified) {
        console.warn('❌ Webhook HMAC validation failed');
        return res.status(401).send('Unauthorized');
      }
    } else {
      console.log('🧪 Skipping HMAC – Test Mode Enabled');
    }

    const data = req.body;
    const event_id = `purchase-${data.id}-${Date.now()}`;
    const hashedEmail = crypto.createHash('sha256').update(data.email || '').digest('hex');
    const hashedPhone = crypto.createHash('sha256')
      .update((data.phone || '').replace(/[^0-9]/g, ''))
      .digest('hex');

    const payload = {
      data: [
        {
          event_name: 'Purchase',
          event_time: Math.floor(new Date(data.created_at || Date.now()).getTime() / 1000),
          event_id,
          action_source: 'website',
          event_source_url: data.checkout_id
            ? `https://${data.source_name}/checkouts/${data.checkout_id}`
            : '',
          user_data: {
            em: [hashedEmail],
            ph: [hashedPhone],
            fbp: data.fbp || undefined,
            fbc: data.fbc || undefined
          },
          custom_data: {
            currency: data.currency || 'INR',
            value: parseFloat(data.total_price || 0)
          }
        }
      ]
    };

    const url = `https://graph.facebook.com/v19.0/${META_PIXEL_ID}/events?access_token=${META_CAPI_TOKEN}`;

    // 🔍 Debug Logs
    console.log('📤 Sending to Meta CAPI:', JSON.stringify(payload, null, 2));
    console.log('🔗 Endpoint:', url);

    const fbRes = await axios.post(url, payload);

    console.log('✅ Meta CAPI Response:', fbRes.data);
    return res.status(200).send('✅ Webhook processed and Meta event sent');
  } catch (err) {
    console.error('❌ Error:', err.message);
    console.error('❌ Full Error:', err);
    return res.status(500).send('Internal Server Error');
  }
});

// ✅ Health Check Route
app.get('/', (req, res) => {
  res.send('✅ Meta CAPI Purchase Webhook is live!');
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});







