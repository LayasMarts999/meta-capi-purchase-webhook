const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware: parse raw body for Shopify HMAC verification
app.use(bodyParser.raw({ type: 'application/json' }));

// HMAC Verification
function isFromShopify(req) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const body = req.body.toString('utf8');
  const hash = crypto
    .createHmac('sha256', process.env.SHOPIFY_WEBHOOK_SECRET)
    .update(body, 'utf8')
    .digest('base64');
  return hash === hmacHeader;
}

// Shopify purchase webhook endpoint
app.post('/webhook/purchase', async (req, res) => {
  if (!isFromShopify(req)) return res.status(401).send('Unauthorized');

  const order = JSON.parse(req.body.toString('utf8'));

  const external_id = crypto.createHash('sha256').update(order.email).digest('hex');
  const fbp = order.note_attributes?.find(n => n.name === '_fbp')?.value || '';
  const fbc = order.note_attributes?.find(n => n.name === '_fbc')?.value || '';
  const eventID = 'ss_' + order.id;

  try {
    await axios.post(
      `https://graph.facebook.com/v18.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_CAPI_TOKEN}`,
      {
        data: [
          {
            event_name: 'Purchase',
            event_time: Math.floor(new Date(order.processed_at).getTime() / 1000),
            event_id: eventID,
            event_source_url: 'https://layasmarts.com/',
            action_source: 'website',
            user_data: {
              em: [external_id],
              fbp: fbp,
              fbc: fbc,
            },
            custom_data: {
              currency: order.currency,
              value: parseFloat(order.total_price),
              order_id: order.id,
            },
          },
        ]
      }
    );

    res.status(200).send('CAPI Purchase Event Sent');
  } catch (err) {
    console.error('CAPI Error:', err?.response?.data || err.message);
    res.status(500).send('Failed to send CAPI event');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Webhook server running on port ${PORT}`);
});

