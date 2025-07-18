const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Validate HMAC
function verifyShopifyWebhook(req, buf) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;

  const digest = crypto
    .createHmac('sha256', secret)
    .update(buf, 'utf8')
    .digest('base64');

  return digest === hmacHeader;
}

// Middleware for raw buffer parsing (for HMAC)
app.use('/webhook/purchase', bodyParser.raw({ type: 'application/json' }));

app.post('/webhook/purchase', async (req, res) => {
  try {
    // Verify HMAC
    const isValid = verifyShopifyWebhook(req, req.body);
    if (!isValid) {
      console.error('❌ HMAC verification failed');
      return res.status(401).send('Unauthorized');
    }

    // Parse JSON safely
    let data;
    try {
      data = JSON.parse(req.body.toString());
    } catch (err) {
      console.error('❌ JSON parse error:', err.message);
      return res.status(400).send('Invalid JSON payload');
    }

    // Debug logging
    console.log('✅ Webhook data received:', data);

    const event_id = `purchase-${data.id}-${Date.now()}`;
    const payload = {
      data: {
        event_name: 'Purchase',
        event_time: Math.floor(new Date(data.created_at).getTime() / 1000),
        event_source_url: data.checkout_id
          ? `https://${data.source_name}/checkouts/${data.checkout_id}`
          : '',
        action_source: 'website',
        event_id: event_id,
        user_data: {
          em: [crypto.createHash('sha256').update(data.email || '').digest('hex')],
          ph: [crypto.createHash('sha256').update((data.phone || '').replace(/\D/g, '')).digest('hex')]
        },
        custom_data: {
          currency: data.currency,
          value: data.total_price
        }
      }
    };

    const fbResponse = await axios.post(
      `https://graph.facebook.com/v19.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_CAPI_TOKEN}`,
      payload
    );

    console.log('✅ Meta CAPI success:', fbResponse.data);
    res.status(200).send('Webhook received and sent to Meta');
  } catch (err) {
    console.error('🔥 Webhook handler error:', err.stack);
    res.status(500).send('Server error');
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});


