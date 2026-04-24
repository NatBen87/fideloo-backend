const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'fideloo-dev-secret';

const app = express();

app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} → ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

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

// --- Validation helpers ---
function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e));
}

function sanitizeStr(s, maxLen = 255) {
  return String(s || '').trim().slice(0, maxLen);
}

// ========================== ROUTES ==========================

app.get('/', (req, res) => res.json({ message: 'Serveur Fideloo opérationnel ✅' }));

// --- Health check ---
app.get('/health', async (req, res) => {
  let dbOk = false;
  try {
    const { error } = await supabase.from('merchants').select('id').limit(1);
    dbOk = !error;
  } catch {}
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    supabase: dbOk ? 'connected' : 'error',
  });
});

// --- Merchants ---

app.post('/merchants/register', async (req, res) => {
  const email = sanitizeStr(req.body.email, 254).toLowerCase();
  const password = sanitizeStr(req.body.password, 128);
  const business_name = sanitizeStr(req.body.business_name, 100);
  const business_type = sanitizeStr(req.body.business_type, 100);

  if (!email || !password || !business_name) {
    return res.status(400).json({ error: 'Email, mot de passe et nom du commerce sont requis.' });
  }
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Email invalide.' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 caractères minimum).' });

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
  const email = sanitizeStr(req.body.email, 254).toLowerCase();
  const password = sanitizeStr(req.body.password, 128);
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
    .select('id, business_name, business_type, primary_color, reward_threshold, reward_description, points_per_visit, reward_tiers')
    .eq('id', req.params.id)
    .single();
  if (error || !data) return res.status(404).json({ message: 'Commerce introuvable.' });
  res.json(data);
});

app.put('/merchants/:id', auth, async (req, res) => {
  const { id } = req.params;
  if (req.merchantId !== id) return res.status(403).json({ message: 'Accès refusé.' });

  const business_name = sanitizeStr(req.body.business_name, 100);
  const business_type = sanitizeStr(req.body.business_type, 100);
  const primary_color = sanitizeStr(req.body.primary_color, 20);
  const reward_description = sanitizeStr(req.body.reward_description, 200);
  const reward_threshold = Math.max(1, Math.min(9999, Number(req.body.reward_threshold) || 10));
  const points_per_visit = Math.max(1, Math.min(100, Number(req.body.points_per_visit) || 1));
  const reward_tiers = Array.isArray(req.body.reward_tiers) ? req.body.reward_tiers.slice(0, 10) : undefined;
  const onboarding_complete = req.body.onboarding_complete !== undefined ? Boolean(req.body.onboarding_complete) : undefined;

  const updates = { business_name, business_type, primary_color, reward_threshold, reward_description, points_per_visit };
  if (reward_tiers !== undefined) updates.reward_tiers = reward_tiers;
  if (onboarding_complete !== undefined) updates.onboarding_complete = onboarding_complete;

  const { data, error } = await supabase
    .from('merchants')
    .update(updates)
    .eq('id', id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json({ success: true, merchant: data });
});

// --- Customers ---

app.get('/customers/find/:query', auth, async (req, res) => {
  const q = sanitizeStr(req.params.query, 254);
  try {
    let data = null;
    ({ data } = await supabase.from('customers').select('*').eq('id', q).eq('merchant_id', req.merchantId).maybeSingle());
    if (!data) ({ data } = await supabase.from('customers').select('*').eq('email', q).eq('merchant_id', req.merchantId).maybeSingle());
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
    .select('id, name, points, merchant_id, referral_code')
    .eq('id', req.params.customerId)
    .single();

  if (error || !customer) return res.status(404).json({ message: 'Client introuvable.' });

  const { data: merchant } = await supabase
    .from('merchants')
    .select('business_name, primary_color, reward_threshold, reward_description, reward_tiers')
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
  const merchant_id = sanitizeStr(req.body.merchant_id, 36);
  const name = sanitizeStr(req.body.name, 100);
  const email = sanitizeStr(req.body.email, 254).toLowerCase();
  const birthday = req.body.birthday ? sanitizeStr(req.body.birthday, 10) : null;
  const ref_code = req.body.referral_code ? sanitizeStr(req.body.referral_code, 20) : null;

  if (!merchant_id || !name || !email) {
    return res.status(400).json({ message: 'merchant_id, nom et email sont requis.' });
  }
  if (!isValidEmail(email)) return res.status(400).json({ message: 'Email invalide.' });

  const { data: existing } = await supabase
    .from('customers')
    .select('*')
    .eq('email', email)
    .eq('merchant_id', merchant_id)
    .maybeSingle();

  if (existing) {
    return res.status(400).json({ message: 'Ce client existe déjà pour ce commerce.', customer: existing });
  }

  // Find referrer if referral code provided
  let referrer = null;
  if (ref_code) {
    const { data: ref } = await supabase
      .from('customers')
      .select('id, points')
      .eq('referral_code', ref_code)
      .eq('merchant_id', merchant_id)
      .maybeSingle();
    referrer = ref || null;
  }

  const newReferralCode = crypto.randomBytes(4).toString('hex');
  const insertData = {
    merchant_id,
    name,
    email,
    points: 0,
    referral_code: newReferralCode,
    referred_by: referrer?.id || null,
  };
  if (birthday) insertData.birthday = birthday;

  const { data, error } = await supabase
    .from('customers')
    .insert([insertData])
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });

  // Referral bonus: +3 points for both parties
  if (referrer && data) {
    const newRefPoints = (referrer.points || 0) + 3;
    await supabase.from('customers').update({ points: newRefPoints }).eq('id', referrer.id);
    await supabase.from('transactions').insert({ merchant_id, customer_id: referrer.id, points: 3 });
    const bonusPoints = (data.points || 0) + 3;
    await supabase.from('customers').update({ points: bonusPoints }).eq('id', data.id);
    await supabase.from('transactions').insert({ merchant_id, customer_id: data.id, points: 3 });
    const { data: updated } = await supabase.from('customers').select('*').eq('id', data.id).single();
    return res.json({ ...(updated || data), referred: true });
  }

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
          to: [email],
          subject: `Bienvenue chez ${mData?.business_name || 'notre commerce'} !`,
          html: `<p>Bonjour ${name},</p><p>Votre carte fidélité chez <strong>${mData?.business_name || 'notre commerce'}</strong> est activée. Vous avez actuellement <strong>0 point</strong>.</p>`,
        }),
      });
    } catch {} // fail silently
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
  const merchant_id = sanitizeStr(req.body.merchant_id, 36);
  const customer_id = sanitizeStr(req.body.customer_id, 36);
  const points = Math.max(1, Math.min(9999, Number(req.body.points) || 1));

  if (!merchant_id || !customer_id) {
    return res.status(400).json({ message: 'merchant_id et customer_id sont requis.' });
  }
  if (req.merchantId !== merchant_id) return res.status(403).json({ message: 'Accès refusé.' });

  try {
    const { error: transError } = await supabase
      .from('transactions').insert({ merchant_id, customer_id, points });
    if (transError) return res.status(400).json({ message: transError.message });

    const { data: customer, error: fetchError } = await supabase
      .from('customers').select('points').eq('id', customer_id).single();
    if (fetchError) return res.status(400).json({ message: fetchError.message });

    const newPoints = (customer.points || 0) + points;
    const updatePayload = { points: newPoints, last_visit: new Date().toISOString() };
    const { data: updated, error: updateError } = await supabase
      .from('customers')
      .update(updatePayload)
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

// --- Notifications ---
//
// Run in Supabase SQL editor before using these routes:
//
// CREATE TABLE IF NOT EXISTS notifications (
//   id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
//   merchant_id UUID REFERENCES merchants(id) ON DELETE CASCADE,
//   title TEXT NOT NULL,
//   message TEXT NOT NULL,
//   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
// );
//
// CREATE TABLE IF NOT EXISTS notification_reads (
//   id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
//   notification_id UUID REFERENCES notifications(id) ON DELETE CASCADE,
//   customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
//   read_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
//   UNIQUE(notification_id, customer_id)
// );
//
// ALTER TABLE merchants ADD COLUMN IF NOT EXISTS reward_tiers JSONB DEFAULT '[]'::jsonb;
// ALTER TABLE merchants ADD COLUMN IF NOT EXISTS onboarding_complete BOOLEAN DEFAULT false;
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS birthday DATE;
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS referral_code TEXT;
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS referred_by UUID REFERENCES customers(id);
// ALTER TABLE customers ADD COLUMN IF NOT EXISTS last_visit TIMESTAMP WITH TIME ZONE;

app.post('/merchants/:id/notify', auth, async (req, res) => {
  const { id } = req.params;
  if (req.merchantId !== id) return res.status(403).json({ message: 'Accès refusé.' });

  const title = sanitizeStr(req.body.title, 100);
  const message = sanitizeStr(req.body.message, 500);

  if (!title || !message) {
    return res.status(400).json({ message: 'Titre et message sont requis.' });
  }

  const { data, error } = await supabase
    .from('notifications')
    .insert([{ merchant_id: id, title, message }])
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });

  // Count how many customers will receive it
  const { count } = await supabase
    .from('customers')
    .select('id', { count: 'exact', head: true })
    .eq('merchant_id', id);

  res.json({ success: true, notification: data, recipients: count || 0 });
});

// Public — fetches unread notifications for a customer
app.get('/notifications/customer/:customerId', async (req, res) => {
  const { customerId } = req.params;

  const { data: customer } = await supabase
    .from('customers')
    .select('merchant_id')
    .eq('id', customerId)
    .single();

  if (!customer) return res.status(404).json({ message: 'Client introuvable.' });

  // Get all notifications for this merchant
  const { data: notifications, error } = await supabase
    .from('notifications')
    .select('*')
    .eq('merchant_id', customer.merchant_id)
    .order('created_at', { ascending: false })
    .limit(20);

  if (error) return res.status(400).json({ error: error.message });
  if (!notifications?.length) return res.json([]);

  // Get already-read notification IDs for this customer
  const { data: reads } = await supabase
    .from('notification_reads')
    .select('notification_id')
    .eq('customer_id', customerId);

  const readIds = new Set((reads || []).map(r => r.notification_id));
  const unread = notifications.filter(n => !readIds.has(n.id));

  res.json(unread);
});

// Public — mark all unread notifications as read for a customer
app.post('/notifications/customer/:customerId/mark-read', async (req, res) => {
  const { customerId } = req.params;

  const { data: customer } = await supabase
    .from('customers')
    .select('merchant_id')
    .eq('id', customerId)
    .single();

  if (!customer) return res.status(404).json({ message: 'Client introuvable.' });

  const { data: notifications } = await supabase
    .from('notifications')
    .select('id')
    .eq('merchant_id', customer.merchant_id);

  if (!notifications?.length) return res.json({ success: true });

  const { data: reads } = await supabase
    .from('notification_reads')
    .select('notification_id')
    .eq('customer_id', customerId);

  const readIds = new Set((reads || []).map(r => r.notification_id));
  const toInsert = notifications
    .filter(n => !readIds.has(n.id))
    .map(n => ({ notification_id: n.id, customer_id: customerId }));

  if (toInsert.length > 0) {
    await supabase.from('notification_reads').insert(toInsert);
  }

  res.json({ success: true, marked: toInsert.length });
});

// --- Global error handler ---
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ message: 'Corps de requête JSON invalide.' });
  }
  console.error(err);
  res.status(500).json({ message: 'Erreur serveur.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});