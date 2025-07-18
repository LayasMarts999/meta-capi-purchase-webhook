const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to capture raw body
app.use(
  '/webhook/purchase',
  bodyParser.raw({ type: 'application/json' })
);

// ✅ Secure HMAC verification (skipped in development mode)
function verifyShopifyWebhook(req, rawBody) {
  if (process.env.NODE_ENV === 'development') return true;

  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  const digest = crypto
    .createHmac('sha256', secret)
    .update(rawBody, 'utf8')
    .digest('base64');

  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
}

// ✅ Webhook endpoint
app.post('/webhook/purchase', (req, res) => {
  try {
    // Bypass HMAC in development
    const isVerified = verifyShopifyWebhook(req, req.body);
    if (!isVerified) {
      console.error('❌ Invalid HMAC signature');
      return res.status(401).send('Unauthorized');
    }

    const data = JSON.parse(req.body.toString());

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
          em: [crypto.createHash('sha256').update(data.email).digest('hex')],
          ph: [
            crypto.createHash('sha256')
              .update(data.phone.replace(/[^0-9]/g, ''))
              .digest('hex'),
          ],
        },
        custom_data: {
          currency: data.currency,
          value: data.total_price,
        },
      },
    };

    axios
      .post(
        `https://graph.facebook.com/v19.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_CAPI_TOKEN}`,
        payload
      )
      .then((response) => {
        console.log('✅ Meta CAPI success:', response.data);
      })
      .catch((error) => {
        console.error('❌ Meta CAPI error:', error.response?.data || error.message);
      });

    res.status(200).send('✅ Webhook received and processed');
  } catch (error) {
    console.error('❌ Error:', error.message);
    res.status(500).send('Server error');
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});


