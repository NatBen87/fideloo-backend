const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'fideloo-dev-secret';

const app = express();
app.use(cors());
app.use(express.json());

// --- HMAC token (no extra deps, uses Node built-in crypto) ---
function generateToken(merchantId) {
  const payload = `${merchantId}:${Date.now()}`;
  const b64 = Buffer.from(payload).toString('base64').replace(/=/g, '');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(b64).digest('hex');
  return `${b64}.${sig}`;
}

function verifyToken(token) {
  try {
    const dot = token.indexOf('.');
    if (dot === -1) return null;
    const b64 = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(b64).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    return Buffer.from(b64, 'base64').toString().split(':')[0]; // merchantId
  } catch {
    return null;
  }
}

// --- Auth middleware ---
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ message: 'Non autorisé.' });
  const merchantId = verifyToken(header.slice(7));
  if (!merchantId) return res.status(401).json({ message: 'Token invalide.' });
  req.merchantId = merchantId;
  next();
}

// --- In-memory rate limiter ---
const _rateMap = new Map();
function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key = (req.ip || '') + req.path;
    const now = Date.now();
    const r = _rateMap.get(key) || { n: 0, t: now };
    if (now - r.t > windowMs) { r.n = 1; r.t = now; } else { r.n++; }
    _rateMap.set(key, r);
    if (r.n > max) return res.status(429).json({ message: 'Trop de requêtes. Réessayez dans un moment.' });
    next();
  };
}

function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e));
}

// ========================== ROUTES ==========================

app.get('/', (req, res) => res.json({ message: 'Serveur Fideloo opérationnel ✅' }));

// --- Merchants ---

app.post('/merchants/register', async (req, res) => {
  const { email, password, business_name, business_type } = req.body;
  if (!email || !password || !business_name) {
    return res.status(400).json({ error: 'Email, mot de passe et nom du commerce sont requis.' });
  }
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 caractères minimum).' });

  const bcrypt = require('bcrypt');
  const password_hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('merchants')
    .insert([{ email, password_hash, business_name, business_type, name: business_name }])
    .select();

  if (error) return res.status(400).json({ error: error.message });
  const merchant = data[0];
  res.json({ success: true, merchant, token: generateToken(merchant.id) });
});

app.post('/merchants/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });

  const bcrypt = require('bcrypt');
  const { data, error } = await supabase
    .from('merchants')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !data) return res.status(400).json({ error: 'Compte introuvable' });
  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) return res.status(400).json({ error: 'Mot de passe incorrect' });

  res.json({ success: true, merchant: data, token: generateToken(data.id) });
});

// Public — no auth (used by /join page)
app.get('/merchants/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('merchants')
    .select('id, business_name, business_type, primary_color, reward_threshold, reward_description, points_per_visit')
    .eq('id', req.params.id)
    .single();
  if (error || !data) return res.status(404).json({ message: 'Commerce introuvable.' });
  res.json(data);
});

app.put('/merchants/:id', auth, async (req, res) => {
  const { id } = req.params;
  if (req.merchantId !== id) return res.status(403).json({ message: 'Accès refusé.' });
  const { business_name, business_type, primary_color, reward_threshold, reward_description, points_per_visit } = req.body;
  const { data, error } = await supabase
    .from('merchants')
    .update({ business_name, business_type, primary_color, reward_threshold, reward_description, points_per_visit })
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true, merchant: data });
});

// --- Customers ---

// Must be before /customers/:merchantId (3 segments vs 2 segments — no real conflict, but explicit ordering is clearer)
app.get('/customers/find/:query', auth, async (req, res) => {
  const q = req.params.query;
  try {
    let data = null;
    // ID exact
    ({ data } = await supabase.from('customers').select('*').eq('id', q).eq('merchant_id', req.merchantId).maybeSingle());
    // Email exact
    if (!data) ({ data } = await supabase.from('customers').select('*').eq('email', q).eq('merchant_id', req.merchantId).maybeSingle());
    // Name partial
    if (!data) {
      const r = await supabase.from('customers').select('*').eq('merchant_id', req.merchantId).ilike('name', `%${q}%`).limit(1).maybeSingle();
      data = r.data;
    }
    if (!data) return res.status(404).json({ message: 'Client introuvable.' });
    res.json(data);
  } catch {
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

// Public — customer bookmarkable card page
app.get('/customers/card/:customerId', async (req, res) => {
  const { data: customer, error } = await supabase
    .from('customers')
    .select('id, name, points, merchant_id')
    .eq('id', req.params.customerId)
    .single();

  if (error || !customer) return res.status(404).json({ message: 'Client introuvable.' });

  const { data: merchant } = await supabase
    .from('merchants')
    .select('business_name, primary_color, reward_threshold, reward_description')
    .eq('id', customer.merchant_id)
    .single();

  res.json({ ...customer, merchant: merchant || {} });
});

app.get('/customers/:merchantId', auth, async (req, res) => {
  const { merchantId } = req.params;
  if (req.merchantId !== merchantId) return res.status(403).json({ message: 'Accès refusé.' });
  const { data, error } = await supabase
    .from('customers')
    .select('*')
    .eq('merchant_id', merchantId)
    .order('created_at', { ascending: false });
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// Public — rate limited (customer self-registration from /join page)
app.post('/customers', rateLimit(60_000, 10), async (req, res) => {
  const { merchant_id, name, email } = req.body;
  if (!merchant_id || !name?.trim() || !email?.trim()) {
    return res.status(400).json({ message: 'merchant_id, nom et email sont requis.' });
  }
  if (!isValidEmail(email)) return res.status(400).json({ message: 'Email invalide.' });

  const normalizedEmail = email.toLowerCase().trim();
  const { data: existing } = await supabase
    .from('customers')
    .select('*')
    .eq('email', normalizedEmail)
    .eq('merchant_id', merchant_id)
    .maybeSingle();

  if (existing) {
    return res.status(400).json({ message: 'Ce client existe déjà pour ce commerce.', customer: existing });
  }

  const { data, error } = await supabase
    .from('customers')
    .insert([{ merchant_id, name: name.trim(), email: normalizedEmail, points: 0 }])
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });

  // Welcome email — only runs if RESEND_API_KEY is set in .env
  if (process.env.RESEND_API_KEY) {
    const { data: mData } = await supabase
      .from('merchants').select('business_name').eq('id', merchant_id).single();
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        },
        body: JSON.stringify({
          from: 'Fideloo <noreply@fideloo.com>',
          to: [normalizedEmail],
          subject: `Bienvenue chez ${mData?.business_name || 'notre commerce'} !`,
          html: `<p>Bonjour ${name.trim()},</p><p>Votre carte fidélité chez <strong>${mData?.business_name || 'notre commerce'}</strong> est activée. Vous avez actuellement <strong>0 point</strong>.</p>`,
        }),
      });
    } catch {} // fail silently — email is best-effort
  }

  res.json(data);
});

app.post('/customers/:id/redeem', auth, async (req, res) => {
  const { data: customer, error } = await supabase
    .from('customers').select('*').eq('id', req.params.id).single();

  if (error || !customer) return res.status(404).json({ message: 'Client introuvable.' });
  if (req.merchantId !== customer.merchant_id) return res.status(403).json({ message: 'Accès refusé.' });

  const { data: merchant } = await supabase
    .from('merchants').select('reward_threshold').eq('id', customer.merchant_id).single();

  const threshold = merchant?.reward_threshold || 10;
  if (customer.points < threshold) {
    return res.status(400).json({ message: `Pas encore assez de points (${customer.points}/${threshold}).` });
  }

  const { data: updated, error: updateError } = await supabase
    .from('customers')
    .update({ points: customer.points - threshold })
    .eq('id', req.params.id)
    .select()
    .single();

  if (updateError) return res.status(400).json({ message: updateError.message });

  await supabase.from('transactions').insert({
    merchant_id: customer.merchant_id,
    customer_id: req.params.id,
    points: -threshold,
  });

  res.json({ message: 'Récompense utilisée avec succès.', customer: updated });
});

// --- Transactions ---

app.post('/transactions', auth, rateLimit(60_000, 30), async (req, res) => {
  const { merchant_id, customer_id, points } = req.body;
  if (!merchant_id || !customer_id || !points) {
    return res.status(400).json({ message: 'merchant_id, customer_id et points sont requis.' });
  }
  if (req.merchantId !== merchant_id) return res.status(403).json({ message: 'Accès refusé.' });

  try {
    const { error: transError } = await supabase
      .from('transactions').insert({ merchant_id, customer_id, points });
    if (transError) return res.status(400).json({ message: transError.message });

    const { data: customer, error: fetchError } = await supabase
      .from('customers').select('points').eq('id', customer_id).single();
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    const newPoints = (customer.points || 0) + Number(points);
    const { data: updated, error: updateError } = await supabase
      .from('customers')
      .update({ points: newPoints })
      .eq('id', customer_id)
      .select()
      .single();
    if (updateError) return res.status(400).json({ message: updateError.message });

    res.json({ message: 'Points ajoutés avec succès.', customer: updated });
  } catch (err) {
    console.error('Erreur transaction:', err);
    res.status(500).json({ message: 'Erreur serveur.' });
  }
});

app.get('/transactions/customer/:customerId', auth, async (req, res) => {
  const { customerId } = req.params;
  const { data: customer } = await supabase
    .from('customers').select('merchant_id').eq('id', customerId).single();

  if (!customer || req.merchantId !== customer.merchant_id) {
    return res.status(403).json({ message: 'Accès refusé.' });
  }

  const { data, error } = await supabase
    .from('transactions')
    .select('*')
    .eq('customer_id', customerId)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// All transactions for a merchant, enriched with customer name
app.get('/transactions/merchant/:merchantId', auth, async (req, res) => {
  const { merchantId } = req.params;
  if (req.merchantId !== merchantId) return res.status(403).json({ message: 'Accès refusé.' });

  const { data: txns, error } = await supabase
    .from('transactions')
    .select('*')
    .eq('merchant_id', merchantId)
    .order('created_at', { ascending: false })
    .limit(200);

  if (error) return res.status(400).json({ error: error.message });

  // Enrich with customer names in a single extra query
  const customerIds = [...new Set(txns.map(t => t.customer_id))];
  let customerMap = {};
  if (customerIds.length > 0) {
    const { data: customers } = await supabase
      .from('customers')
      .select('id, name, email')
      .in('id', customerIds);
    if (customers) customers.forEach(c => { customerMap[c.id] = c; });
  }

  res.json(txns.map(t => ({
    ...t,
    customer_name: customerMap[t.customer_id]?.name || 'Client inconnu',
    customer_email: customerMap[t.customer_id]?.email || '',
  })));
});

// --- Global error handler (malformed JSON etc.) ---
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ message: 'Corps de requête JSON invalide.' });
  }
  console.error(err);
  res.status(500).json({ message: 'Erreur serveur.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
