const express = require('express');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

const SHOPIFY_SHOP = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const API_VERSION = process.env.SHOPIFY_API_VERSION || '2026-07';

// Store access token (will be set after OAuth)
let ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN || '';

app.use(express.json({ limit: '50kb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Accept');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// ============================================
// OAuth Install Route
// ============================================
app.get('/install', (req, res) => {
  const shop = req.query.shop || SHOPIFY_SHOP;
  const scopes = 'read_products,write_products,read_orders,read_customers';
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
  
  const authUrl = `https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_CLIENT_ID}&scope=${scopes}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  
  res.redirect(authUrl);
});

// ============================================
// OAuth Callback
// ============================================
app.get('/auth/callback', async (req, res) => {
  const { code, shop, hmac } = req.query;
  
  // Verify HMAC
  const message = Object.keys(req.query).filter(k => k !== 'hmac').sort().map(k => `${k}=${req.query[k]}`).join('&');
  const calculatedHmac = crypto.createHmac('sha256', SHOPIFY_CLIENT_SECRET).update(message).digest('hex');
  
  if (calculatedHmac !== hmac) {
    return res.status(401).send('Invalid HMAC');
  }
  
  // Exchange code for token
  const tokenUrl = `https://${shop}/admin/oauth/access_token`;
  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: SHOPIFY_CLIENT_ID,
      client_secret: SHOPIFY_CLIENT_SECRET,
      code: code
    })
  });
  
  const tokenData = await tokenRes.json();
  
  if (tokenData.access_token) {
    ACCESS_TOKEN = tokenData.access_token;
    console.log('✅ Access token obtained:', ACCESS_TOKEN.substring(0, 20) + '...');
    console.log('⚠️ Copy this token and add it to your .env file as SHOPIFY_ACCESS_TOKEN');
    
    res.json({
      success: true,
      message: 'App installed successfully!',
      access_token: ACCESS_TOKEN,
      instruction: 'Copy the access_token above and add it to your .env file as SHOPIFY_ACCESS_TOKEN'
    });
  } else {
    res.status(500).json({ error: 'Failed to get access token', details: tokenData });
  }
});

// ============================================
// Shopify GraphQL Helper
// ============================================
async function shopifyGraphQL(query, variables = {}) {
  if (!ACCESS_TOKEN) {
    throw new Error('No access token. Visit /install first to authenticate.');
  }
  
  const url = `https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });
  const data = await res.json();
  if (data.errors) throw new Error(JSON.stringify(data.errors));
  return data.data;
}

// ============================================
// Proxy Verification Middleware
// ============================================
function verifyProxy(req, res, next) {
  const { signature, ...params } = req.query;

  if (!signature) {
    return res.status(401).json({ success: false, message: 'Missing signature.' });
  }

  const message = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('');
  const hmac = crypto.createHmac('sha256', SHOPIFY_CLIENT_SECRET).update(message).digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(signature))) {
    return res.status(401).json({ success: false, message: 'Invalid signature.' });
  }

  const cid = req.query.logged_in_customer_id;
  req.customerId = (cid && cid !== '') ? cid : null;
  next();
}

// ============================================
// GET /product - Fetch reviews
// ============================================
app.get('/product', verifyProxy, async (req, res) => {
  try {
    const productId = req.query.product_id;
    if (!productId) return res.status(400).json({ success: false, message: 'Missing product_id' });

    const query = `
      query GetProductReviews($id: ID!) {
        product(id: $id) {
          metafield(namespace: "custom", key: "reviews_list") { value }
        }
      }
    `;
    const data = await shopifyGraphQL(query, { id: `gid://shopify/Product/${productId}` });

    let reviews = [];
    if (data.product && data.product.metafield && data.product.metafield.value) {
      try { reviews = JSON.parse(data.product.metafield.value); } catch (e) { reviews = []; }
      if (!Array.isArray(reviews)) reviews = [];
    }

    let alreadyReviewed = false;
    if (req.customerId) {
      alreadyReviewed = reviews.some(r => r.customer_id === req.customerId);
    }

    let eligible = false;
    if (req.customerId) eligible = await checkPurchase(req.customerId, productId);

    res.json({
      success: true,
      reviews: reviews.map(r => ({ name: r.name, rating: r.rating, title: r.title, body: r.body, date: r.date, verified: r.verified || false })),
      customer: { logged_in: !!req.customerId, eligible: eligible, already_reviewed: alreadyReviewed }
    });
  } catch (err) {
    console.error('[GET] Error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to load reviews.' });
  }
});

// ============================================
// POST /submit - Create review
// ============================================
app.post('/submit', verifyProxy, async (req, res) => {
  try {
    const customerId = req.customerId;
    if (!customerId) return res.status(401).json({ success: false, message: 'Please sign in to write a review.' });

    const { product_id, rating, title, body, name } = req.body;

    if (!product_id) return res.status(400).json({ success: false, message: 'Missing product ID.' });
    const r = parseInt(rating, 10);
    if (isNaN(r) || r < 1 || r > 5) return res.status(400).json({ success: false, message: 'Rating must be 1-5.' });
    if (!title || !title.trim()) return res.status(400).json({ success: false, message: 'Title is required.' });
    if (!body || !body.trim()) return res.status(400).json({ success: false, message: 'Review body is required.' });

    const purchased = await checkPurchase(customerId, product_id);
    if (!purchased) return res.status(403).json({ success: false, message: 'You must purchase this product before reviewing it.' });

    const readQuery = `
      query GetReviews($id: ID!) {
        product(id: $id) { metafield(namespace: "custom", key: "reviews_list") { value } }
      }
    `;
    const readData = await shopifyGraphQL(readQuery, { id: `gid://shopify/Product/${product_id}` });

    let reviews = [];
    if (readData.product && readData.product.metafield && readData.product.metafield.value) {
      try { reviews = JSON.parse(readData.product.metafield.value); } catch(e) { reviews = []; }
      if (!Array.isArray(reviews)) reviews = [];
    }

    if (reviews.some(rv => rv.customer_id === customerId)) {
      return res.status(409).json({ success: false, message: 'You have already reviewed this product.' });
    }

    const cleanTitle = title.trim().replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cleanBody = body.trim().replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cleanName = (name || 'Customer').trim().replace(/</g, '&lt;').replace(/>/g, '&gt;');

    reviews.push({
      customer_id: customerId,
      name: cleanName,
      rating: r,
      title: cleanTitle,
      body: cleanBody,
      date: new Date().toISOString(),
      verified: true
    });

    const writeMutation = `
      mutation UpdateProductMetafield($input: ProductInput!) {
        productUpdate(input: $input) {
          product { id }
          userErrors { field message }
        }
      }
    `;
    const writeData = await shopifyGraphQL(writeMutation, {
      input: {
        id: `gid://shopify/Product/${product_id}`,
        metafields: [{ namespace: 'custom', key: 'reviews_list', type: 'json', value: JSON.stringify(reviews) }]
      }
    });

    if (writeData.productUpdate.userErrors.length > 0) {
      throw new Error(writeData.productUpdate.userErrors.map(e => e.message).join(', '));
    }

    res.json({ success: true, message: 'Thank you for your review! Your verified review has been published.' });
  } catch (err) {
    console.error('[POST] Error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to save review. Please try again.' });
  }
});

// ============================================
// Check Purchase
// ============================================
async function checkPurchase(customerId, productId) {
  try {
    const query = `
      query CheckPurchase($customerId: ID!) {
        customer(id: $customerId) {
          orders(first: 50, reverse: true, query: "financial_status:paid") {
            edges { node { lineItems(first: 50) { edges { node { product { id } } } } } }
          }
        }
      }
    `;
    const data = await shopifyGraphQL(query, { id: `gid://shopify/Customer/${customerId}` });
    if (!data.customer) return false;
    const productGid = `gid://shopify/Product/${productId}`;
    for (const orderEdge of data.customer.orders.edges) {
      for (const lineEdge of orderEdge.node.lineItems.edges) {
        if (lineEdge.node.product && lineEdge.node.product.id === productGid) return true;
      }
    }
    return false;
  } catch (err) {
    console.error('[PURCHASE] Error:', err.message);
    return false;
  }
}

app.use((req, res) => {
  console.log('[404]', req.method, req.path);
  res.status(404).json({ success: false, message: 'Route not found: ' + req.path });
});

app.listen(PORT, () => {
  console.log('✅ Reviews server running on port', PORT);
  console.log('📦 Shop:', SHOPIFY_SHOP || 'MISSING');
  console.log('🔑 Client ID:', SHOPIFY_CLIENT_ID ? 'Set ✓' : 'MISSING ✗');
  console.log('🔐 Secret:', SHOPIFY_CLIENT_SECRET ? 'Set ✓' : 'MISSING ✗');
  console.log('🎫 Access Token:', ACCESS_TOKEN ? 'Set ✓' : 'NOT SET - Visit /install to authenticate');
});
