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

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString('utf8');
    }
  })
);

app.post('/webhook/purchase', async (req, res) => {
  try {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    const rawBody = req.rawBody;

    // ⚠️ Skip HMAC validation during manual test
    const isTest = req.headers['x-shopify-hmac-sha256'] === 'dummy_hmac';
    const isVerified = isTest || (SHOPIFY_WEBHOOK_SECRET && crypto.timingSafeEqual(
      Buffer.from(crypto.createHmac('sha256', SHOPIFY_WEBHOOK_SECRET).update(rawBody, 'utf8').digest('base64')),
      Buffer.from(hmacHeader || '', 'utf8')
    ));

    if (!isVerified) {
      console.warn('❌ Invalid HMAC – Unauthorized');
      return res.status(401).send('Unauthorized');
    }

    const data = req.body;
    const event_id = `purchase-${data.id}-${Date.now()}`;
    const emailHash = crypto.createHash('sha256').update(data.email || '').digest('hex');
    const phoneHash = crypto.createHash('sha256').update((data.phone || '').replace(/\D/g, '')).digest('hex');

    const payload = {
      data: [
        {
          event_name: 'Purchase',
          event_time: Math.floor(new Date(data.created_at || Date.now()).getTime() / 1000),
          event_id: event_id,
          action_source: 'website',
          event_source_url: data.checkout_id
            ? `https://${data.source_name}/checkouts/${data.checkout_id}`
            : '',
          user_data: {
            em: [emailHash],
            ph: [phoneHash],
            fbp: data.fbp || '',
            fbc: data.fbc || ''
          },
          custom_data: {
            currency: data.currency || 'INR',
            value: parseFloat(data.total_price || 0)
          }
        }
      ]
    };

    const url = `https://graph.facebook.com/v19.0/${META_PIXEL_ID}/events?access_token=${META_CAPI_TOKEN}`;

    const fbRes = await axios.post(url, payload);

    console.log('✅ Meta CAPI Success:', fbRes.data);
    res.status(200).send('✅ Webhook Received & Sent to Meta CAPI');
  } catch (err) {
    console.error('❌ Internal Error:', err.message);
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/', (req, res) => {
  res.send('✅ Meta CAPI Webhook is live!');
});

app.listen(PORT, () => {
  console.log(`🚀 Server live on port ${PORT}`);
});








