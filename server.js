// ============================================
// TALLY — Credit Layer API
// server.js — Main Express Server
// ============================================

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import Stripe from 'stripe';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client (service role — bypasses RLS)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// CORS — allow dashboard and any developer frontend to call the API
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Idempotency-Key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// Raw body needed for Stripe webhook signature verification
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use('/webhooks/stripe-billing', express.raw({ type: 'application/json' }));
app.use(express.json());

// ============================================
// MIDDLEWARE: API Key Authentication
// ============================================
async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing API key' });
  }

  const key = authHeader.replace('Bearer ', '').trim();

  const { data, error } = await supabase
    .from('api_keys')
    .select('id, app_id, is_active')
    .eq('key', key)
    .single();

  if (error || !data || !data.is_active) {
    return res.status(401).json({ error: 'Invalid or inactive API key' });
  }

  req.appId = data.app_id;
  req.apiKeyId = data.id;
  next();
}


// ============================================
// MIDDLEWARE: Plan limit enforcement
// Checks developer's plan limits before API calls
// ============================================
async function enforcePlanLimits(req, res, next) {
  try {
    const appId = req.appId;

    // Get app owner email
    const { data: app } = await supabase
      .from('apps')
      .select('owner_email')
      .eq('id', appId)
      .single();

    if (!app) return res.status(404).json({ error: 'App not found' });

    // Get owner's subscription
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('plan, status')
      .eq('owner_email', app.owner_email)
      .single();

    const plan = sub?.plan || 'free';

    // Get plan limits
    const { data: limits } = await supabase
      .from('plan_limits')
      .select('max_users')
      .eq('plan', plan)
      .single();

    const maxUsers = limits?.max_users ?? 100;

    // -1 means unlimited (scale plan)
    if (maxUsers === -1) return next();

    // Count current active users for this app
    const { count } = await supabase
      .from('app_users')
      .select('id', { count: 'exact' })
      .eq('app_id', appId);

    const currentUsers = count || 0;

    // Check if this request would create a new user
    const { user_id } = req.body;
    if (user_id) {
      const { data: existingUser } = await supabase
        .from('app_users')
        .select('id')
        .eq('app_id', appId)
        .eq('external_id', user_id)
        .single();

      // If user doesn't exist yet and we're at the limit — block
      if (!existingUser && currentUsers >= maxUsers) {
        return res.status(402).json({
          error: 'Plan limit reached',
          message: `Your ${plan} plan allows up to ${maxUsers} users. Upgrade to add more.`,
          current_users: currentUsers,
          max_users: maxUsers,
          plan,
          upgrade_url: `${process.env.DASHBOARD_URL}/billing`,
        });
      }
    }

    next();
  } catch (err) {
    console.error('Plan enforcement error:', err);
    next(); // Fail open — don't block on middleware errors
  }
}

// ============================================
// HELPER: Get or create app_user
// ============================================
async function getOrCreateUser(appId, externalId) {
  // Try to find existing user
  const { data: existing } = await supabase
    .from('app_users')
    .select('id')
    .eq('app_id', appId)
    .eq('external_id', externalId)
    .single();

  if (existing) return existing.id;

  // Create user
  const { data: newUser, error } = await supabase
    .from('app_users')
    .insert({ app_id: appId, external_id: externalId })
    .select('id')
    .single();

  if (error) throw new Error('Failed to create user');

  // Initialise balance row
  await supabase
    .from('balances')
    .insert({ app_user_id: newUser.id, balance: 0 });

  return newUser.id;
}

// ============================================
// HELPER: Idempotency check
// ============================================
async function checkIdempotency(key, appId) {
  if (!key) return null;

  const { data } = await supabase
    .from('idempotency_keys')
    .select('result')
    .eq('key', key)
    .eq('app_id', appId)
    .single();

  return data?.result || null;
}

async function saveIdempotency(key, appId, result) {
  if (!key) return;
  await supabase
    .from('idempotency_keys')
    .insert({ key, app_id: appId, result });
}

// ============================================
// POST /credits/add
// Add credits to a user's balance
// ============================================
app.post('/credits/add', authenticate, enforcePlanLimits, async (req, res) => {
  const { user_id, amount, description, reference_id, metadata } = req.body;
  const idempotencyKey = req.headers['idempotency-key'];

  if (!user_id || !amount || amount <= 0) {
    return res.status(400).json({ error: 'user_id and a positive amount are required' });
  }

  // Idempotency check
  const cached = await checkIdempotency(idempotencyKey, req.appId);
  if (cached) return res.status(200).json({ ...cached, idempotent: true });

  try {
    const appUserId = await getOrCreateUser(req.appId, user_id);

    // Atomic balance update + ledger write
    const { data: balance, error: balanceError } = await supabase
      .from('balances')
      .select('balance')
      .eq('app_user_id', appUserId)
      .single();

    if (balanceError) throw balanceError;

    const balanceAfter = Number(balance.balance) + Number(amount);

    // Update balance
    await supabase
      .from('balances')
      .update({ balance: balanceAfter, updated_at: new Date().toISOString() })
      .eq('app_user_id', appUserId);

    // Write ledger entry
    const { data: ledgerEntry } = await supabase
      .from('ledger')
      .insert({
        app_user_id: appUserId,
        event_type: 'add',
        amount: Number(amount),
        balance_after: balanceAfter,
        idempotency_key: idempotencyKey || null,
        reference_id: reference_id || null,
        description: description || 'Credit top-up',
        metadata: metadata || null,
      })
      .select('id')
      .single();

    const result = {
      success: true,
      ledger_id: ledgerEntry.id,
      user_id,
      amount: Number(amount),
      balance_after: balanceAfter,
    };

    await saveIdempotency(idempotencyKey, req.appId, result);
    return res.status(200).json(result);

  } catch (err) {
    console.error('Add credits error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// POST /credits/deduct
// Deduct credits atomically (uses DB function)
// ============================================
app.post('/credits/deduct', authenticate, enforcePlanLimits, async (req, res) => {
  const { user_id, amount, description, reference_id, metadata } = req.body;
  const idempotencyKey = req.headers['idempotency-key'];

  if (!user_id || !amount || amount <= 0) {
    return res.status(400).json({ error: 'user_id and a positive amount are required' });
  }

  // Idempotency check
  const cached = await checkIdempotency(idempotencyKey, req.appId);
  if (cached) return res.status(200).json({ ...cached, idempotent: true });

  try {
    const appUserId = await getOrCreateUser(req.appId, user_id);

    // Call the atomic DB function (handles race conditions)
    const { data, error } = await supabase.rpc('deduct_credits', {
      p_app_user_id: appUserId,
      p_amount: Number(amount),
      p_idempotency_key: idempotencyKey || null,
      p_reference_id: reference_id || null,
      p_description: description || 'Credit deduction',
      p_metadata: metadata || null,
    });

    if (error) throw error;

    if (!data.success) {
      return res.status(402).json({
        error: data.error,
        balance: data.balance,
      });
    }

    const result = {
      success: true,
      ledger_id: data.ledger_id,
      user_id,
      amount: Number(amount),
      balance_before: data.balance_before,
      balance_after: data.balance_after,
    };

    await saveIdempotency(idempotencyKey, req.appId, result);
    return res.status(200).json(result);

  } catch (err) {
    console.error('Deduct credits error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// POST /credits/refund
// Reverse a previous transaction by ledger_id
// ============================================
app.post('/credits/refund', authenticate, enforcePlanLimits, async (req, res) => {
  const { ledger_id, description } = req.body;
  const idempotencyKey = req.headers['idempotency-key'];

  if (!ledger_id) {
    return res.status(400).json({ error: 'ledger_id is required' });
  }

  const cached = await checkIdempotency(idempotencyKey, req.appId);
  if (cached) return res.status(200).json({ ...cached, idempotent: true });

  try {
    // Find original ledger entry
    const { data: original, error: fetchError } = await supabase
      .from('ledger')
      .select('id, app_user_id, event_type, amount, app_users(app_id, external_id)')
      .eq('id', ledger_id)
      .single();

    if (fetchError || !original) {
      return res.status(404).json({ error: 'Ledger entry not found' });
    }

    // Ensure this ledger entry belongs to this app
    if (original.app_users.app_id !== req.appId) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (original.event_type === 'refund') {
      return res.status(400).json({ error: 'Cannot refund a refund' });
    }

    const refundAmount = Number(original.amount);
    const appUserId = original.app_user_id;

    // Get current balance
    const { data: balance } = await supabase
      .from('balances')
      .select('balance')
      .eq('app_user_id', appUserId)
      .single();

    const balanceAfter = Number(balance.balance) + refundAmount;

    // Update balance
    await supabase
      .from('balances')
      .update({ balance: balanceAfter, updated_at: new Date().toISOString() })
      .eq('app_user_id', appUserId);

    // Write refund ledger entry
    const { data: refundEntry } = await supabase
      .from('ledger')
      .insert({
        app_user_id: appUserId,
        event_type: 'refund',
        amount: refundAmount,
        balance_after: balanceAfter,
        idempotency_key: idempotencyKey || null,
        reference_id: ledger_id,
        description: description || `Refund for ledger ${ledger_id}`,
      })
      .select('id')
      .single();

    const result = {
      success: true,
      ledger_id: refundEntry.id,
      original_ledger_id: ledger_id,
      user_id: original.app_users.external_id,
      amount_refunded: refundAmount,
      balance_after: balanceAfter,
    };

    await saveIdempotency(idempotencyKey, req.appId, result);
    return res.status(200).json(result);

  } catch (err) {
    console.error('Refund error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// GET /credits/balance
// Get current balance for a user
// ============================================
app.get('/credits/balance', authenticate, async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).json({ error: 'user_id query param is required' });
  }

  try {
    const { data: user } = await supabase
      .from('app_users')
      .select('id')
      .eq('app_id', req.appId)
      .eq('external_id', user_id)
      .single();

    if (!user) {
      return res.status(200).json({ user_id, balance: 0 });
    }

    const { data: balance } = await supabase
      .from('balances')
      .select('balance, updated_at')
      .eq('app_user_id', user.id)
      .single();

    return res.status(200).json({
      user_id,
      balance: Number(balance?.balance || 0),
      updated_at: balance?.updated_at,
    });

  } catch (err) {
    console.error('Balance error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// GET /credits/history
// Audit log for a user
// ============================================
app.get('/credits/history', authenticate, async (req, res) => {
  const { user_id, limit = 50, offset = 0 } = req.query;

  if (!user_id) {
    return res.status(400).json({ error: 'user_id query param is required' });
  }

  try {
    const { data: user } = await supabase
      .from('app_users')
      .select('id')
      .eq('app_id', req.appId)
      .eq('external_id', user_id)
      .single();

    if (!user) {
      return res.status(200).json({ user_id, entries: [], total: 0 });
    }

    const { data: entries, count } = await supabase
      .from('ledger')
      .select('id, event_type, amount, balance_after, reference_id, description, metadata, created_at', { count: 'exact' })
      .eq('app_user_id', user.id)
      .order('created_at', { ascending: false })
      .range(Number(offset), Number(offset) + Number(limit) - 1);

    return res.status(200).json({
      user_id,
      entries,
      total: count,
      limit: Number(limit),
      offset: Number(offset),
    });

  } catch (err) {
    console.error('History error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// POST /webhooks/stripe/:app_id
// Auto top-up credits on successful Stripe payment
// URL includes app_id so Stripe doesn't need custom headers
// Expects metadata: { tally_user_id, tally_credits (optional) }
// ============================================
app.post('/webhooks/stripe/:appId', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const { appId } = req.params;

  // Verify the app exists
  const { data: appData, error: appError } = await supabase
    .from('apps')
    .select('id, credit_rate, rate_currency')
    .eq('id', appId)
    .single();

  if (appError || !appData) {
    return res.status(404).json({ error: 'App not found' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).json({ error: `Webhook signature verification failed` });
  }

  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    const { tally_user_id, tally_credits } = intent.metadata;

    if (!tally_user_id) {
      return res.status(200).json({ received: true, skipped: 'No tally_user_id in metadata' });
    }

    const idempotencyKey = `stripe_${intent.id}`;

    // Check for duplicate
    const cached = await checkIdempotency(idempotencyKey, appId);
    if (cached) return res.status(200).json({ received: true, idempotent: true });

    try {
      let creditsToAdd;

      if (tally_credits) {
        // Developer explicitly passed credits — use that directly
        creditsToAdd = Number(tally_credits);
      } else if (appData?.credit_rate) {
        // Use the app's credit rate
        // Stripe amounts are in pence/cents — divide by 100 to get major unit
        const amountInMajorUnit = intent.amount / 100;
        creditsToAdd = Math.floor(amountInMajorUnit * Number(appData.credit_rate));
      } else {
        return res.status(200).json({ received: true, skipped: 'No tally_credits and no credit_rate configured' });
      }

      const appUserId = await getOrCreateUser(appId, tally_user_id);

      const { data: balance } = await supabase
        .from('balances')
        .select('balance')
        .eq('app_user_id', appUserId)
        .single();

      const balanceAfter = Number(balance.balance) + creditsToAdd;

      await supabase
        .from('balances')
        .update({ balance: balanceAfter, updated_at: new Date().toISOString() })
        .eq('app_user_id', appUserId);

      const { data: ledgerEntry } = await supabase
        .from('ledger')
        .insert({
          app_user_id: appUserId,
          event_type: 'add',
          amount: creditsToAdd,
          balance_after: balanceAfter,
          idempotency_key: idempotencyKey,
          reference_id: intent.id,
          description: `Stripe payment ${intent.id}`,
          metadata: { stripe_amount: intent.amount, currency: intent.currency },
        })
        .select('id')
        .single();

      const result = { success: true, ledger_id: ledgerEntry.id, credits_added: creditsToAdd };
      await saveIdempotency(idempotencyKey, appId, result);

    } catch (err) {
      console.error('Stripe webhook processing error:', err);
      return res.status(500).json({ error: 'Processing failed' });
    }
  }

  return res.status(200).json({ received: true });
});



// ============================================
// POST /webhooks/polar/:appId
// Auto top-up credits on Polar order.paid
// Expects metadata: { tally_user_id, tally_credits (optional) }
// ============================================
app.post('/webhooks/polar/:appId', express.json(), async (req, res) => {
  const { appId } = req.params;
  const signature = req.headers['webhook-signature'];
  const webhookId = req.headers['webhook-id'];
  const webhookTimestamp = req.headers['webhook-timestamp'];

  // Verify the app exists and get credit rate
  const { data: appData, error: appError } = await supabase
    .from('apps')
    .select('id, credit_rate')
    .eq('id', appId)
    .single();

  if (appError || !appData) {
    return res.status(404).json({ error: 'App not found' });
  }

  // Verify Polar webhook signature (Standard Webhooks spec)
  const polarWebhookSecret = process.env.POLAR_WEBHOOK_SECRET;
  if (polarWebhookSecret && signature) {
    try {
      const { createHmac } = await import('crypto');
      const toSign = `${webhookId}.${webhookTimestamp}.${JSON.stringify(req.body)}`;
      const expected = createHmac('sha256', polarWebhookSecret)
        .update(toSign)
        .digest('base64');
      const sigParts = signature.split(' ');
      const valid = sigParts.some(s => s.split(',')[1] === expected);
      if (!valid) return res.status(401).json({ error: 'Invalid signature' });
    } catch (err) {
      console.error('Polar signature error:', err);
    }
  }

  const event = req.body;

  // Only process order.paid — most reliable fulfillment event
  if (event.type !== 'order.paid') {
    return res.status(200).json({ received: true, skipped: `Event ${event.type} not handled` });
  }

  const order = event.data;
  const metadata = order.metadata || {};
  const tallyUserId = metadata.tally_user_id;
  const tallyCredits = metadata.tally_credits;

  if (!tallyUserId) {
    return res.status(200).json({ received: true, skipped: 'No tally_user_id in metadata' });
  }

  const idempotencyKey = `polar_${order.id}`;
  const cached = await checkIdempotency(idempotencyKey, appId);
  if (cached) return res.status(200).json({ received: true, idempotent: true });

  try {
    let creditsToAdd;

    if (tallyCredits) {
      creditsToAdd = Number(tallyCredits);
    } else if (appData?.credit_rate) {
      // Polar amounts are in cents
      const amountInMajorUnit = (order.amount || 0) / 100;
      creditsToAdd = Math.floor(amountInMajorUnit * Number(appData.credit_rate));
    } else {
      return res.status(200).json({ received: true, skipped: 'No tally_credits and no credit_rate configured' });
    }

    const appUserId = await getOrCreateUser(appId, tallyUserId);

    const { data: balance } = await supabase
      .from('balances')
      .select('balance')
      .eq('app_user_id', appUserId)
      .single();

    const balanceAfter = Number(balance.balance) + creditsToAdd;

    await supabase
      .from('balances')
      .update({ balance: balanceAfter, updated_at: new Date().toISOString() })
      .eq('app_user_id', appUserId);

    const { data: ledgerEntry } = await supabase
      .from('ledger')
      .insert({
        app_user_id: appUserId,
        event_type: 'add',
        amount: creditsToAdd,
        balance_after: balanceAfter,
        idempotency_key: idempotencyKey,
        reference_id: order.id,
        description: `Polar order ${order.id}`,
        metadata: { polar_amount: order.amount, currency: order.currency },
      })
      .select('id')
      .single();

    const result = { success: true, ledger_id: ledgerEntry.id, credits_added: creditsToAdd };
    await saveIdempotency(idempotencyKey, appId, result);

    return res.status(200).json({ received: true, ...result });
  } catch (err) {
    console.error('Polar webhook error:', err);
    return res.status(500).json({ error: 'Processing failed' });
  }
});

// ============================================
// POST /webhooks/lemonsqueezy/:appId
// Auto top-up credits on Lemon Squeezy order_created
// Expects custom_data: { tally_user_id, tally_credits (optional) }
// ============================================
app.post('/webhooks/lemonsqueezy/:appId', express.raw({ type: 'application/json' }), async (req, res) => {
  const { appId } = req.params;
  const signature = req.headers['x-signature'];

  // Verify the app exists
  const { data: appData, error: appError } = await supabase
    .from('apps')
    .select('id, credit_rate')
    .eq('id', appId)
    .single();

  if (appError || !appData) {
    return res.status(404).json({ error: 'App not found' });
  }

  // Verify Lemon Squeezy HMAC signature
  const lsSecret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (lsSecret && signature) {
    try {
      const { createHmac, timingSafeEqual } = await import('crypto');
      const expected = createHmac('sha256', lsSecret)
        .update(req.body)
        .digest('hex');
      if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
        return res.status(401).json({ error: 'Invalid signature' });
      }
    } catch (err) {
      console.error('LS signature error:', err);
    }
  }

  const payload = JSON.parse(req.body.toString());
  const eventName = payload?.meta?.event_name;

  // Only process order_created with status paid
  if (eventName !== 'order_created') {
    return res.status(200).json({ received: true, skipped: `Event ${eventName} not handled` });
  }

  const order = payload.data?.attributes;
  if (order?.status !== 'paid') {
    return res.status(200).json({ received: true, skipped: 'Order not paid' });
  }

  const customData = payload?.meta?.custom_data || {};
  const tallyUserId = customData.tally_user_id;
  const tallyCredits = customData.tally_credits;

  if (!tallyUserId) {
    return res.status(200).json({ received: true, skipped: 'No tally_user_id in custom_data' });
  }

  const orderId = payload.data?.id;
  const idempotencyKey = `ls_${orderId}`;
  const cached = await checkIdempotency(idempotencyKey, appId);
  if (cached) return res.status(200).json({ received: true, idempotent: true });

  try {
    let creditsToAdd;

    if (tallyCredits) {
      creditsToAdd = Number(tallyCredits);
    } else if (appData?.credit_rate) {
      // LS total is in cents
      const amountInMajorUnit = (order.total || 0) / 100;
      creditsToAdd = Math.floor(amountInMajorUnit * Number(appData.credit_rate));
    } else {
      return res.status(200).json({ received: true, skipped: 'No tally_credits and no credit_rate configured' });
    }

    const appUserId = await getOrCreateUser(appId, tallyUserId);

    const { data: balance } = await supabase
      .from('balances')
      .select('balance')
      .eq('app_user_id', appUserId)
      .single();

    const balanceAfter = Number(balance.balance) + creditsToAdd;

    await supabase
      .from('balances')
      .update({ balance: balanceAfter, updated_at: new Date().toISOString() })
      .eq('app_user_id', appUserId);

    const { data: ledgerEntry } = await supabase
      .from('ledger')
      .insert({
        app_user_id: appUserId,
        event_type: 'add',
        amount: creditsToAdd,
        balance_after: balanceAfter,
        idempotency_key: idempotencyKey,
        reference_id: orderId,
        description: `Lemon Squeezy order ${orderId}`,
        metadata: { ls_total: order.total, currency: order.currency },
      })
      .select('id')
      .single();

    const result = { success: true, ledger_id: ledgerEntry.id, credits_added: creditsToAdd };
    await saveIdempotency(idempotencyKey, appId, result);

    return res.status(200).json({ received: true, ...result });
  } catch (err) {
    console.error('Lemon Squeezy webhook error:', err);
    return res.status(500).json({ error: 'Processing failed' });
  }
});

// ============================================
// BILLING ROUTES
// ============================================

// POST /billing/create-checkout
// Creates a Stripe Checkout session for plan upgrade
app.post('/billing/create-checkout', async (req, res) => {
  const { email, priceId, plan } = req.body;

  if (!email || !priceId || !plan) {
    return res.status(400).json({ error: 'email, priceId, and plan are required' });
  }

  try {
    // Get or create Stripe customer
    let { data: sub } = await supabase
      .from('subscriptions')
      .select('stripe_customer_id')
      .eq('owner_email', email)
      .single();

    let customerId = sub?.stripe_customer_id;

    if (!customerId) {
      const customer = await stripe.customers.create({ email });
      customerId = customer.id;
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.DASHBOARD_URL}/billing?success=true`,
      cancel_url: `${process.env.DASHBOARD_URL}/billing?cancelled=true`,
      metadata: { email, plan },
    });

    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error('Checkout error:', err);
    return res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// POST /billing/portal
// Creates a Stripe Customer Portal session for managing subscription
app.post('/billing/portal', async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: 'email is required' });

  try {
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('stripe_customer_id')
      .eq('owner_email', email)
      .single();

    if (!sub?.stripe_customer_id) {
      return res.status(404).json({ error: 'No billing account found' });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: sub.stripe_customer_id,
      return_url: `${process.env.DASHBOARD_URL}/billing`,
    });

    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error('Portal error:', err);
    return res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// POST /webhooks/stripe-billing
// Handles Tally's own subscription events
app.post('/webhooks/stripe-billing', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_BILLING_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).json({ error: 'Webhook signature failed' });
  }

  const handlers = {
    'checkout.session.completed': async (data) => {
      const { email, plan } = data.metadata;
      const customerId = data.customer;
      const subscriptionId = data.subscription;

      // Get subscription details for period end
      const stripeSub = await stripe.subscriptions.retrieve(subscriptionId);

      await supabase.from('subscriptions').upsert({
        owner_email: email,
        plan,
        stripe_customer_id: customerId,
        stripe_subscription_id: subscriptionId,
        status: 'active',
        current_period_end: new Date(stripeSub.current_period_end * 1000).toISOString(),
        updated_at: new Date().toISOString(),
      }, { onConflict: 'owner_email' });
    },

    'customer.subscription.updated': async (data) => {
      const { data: sub } = await supabase
        .from('subscriptions')
        .select('owner_email')
        .eq('stripe_subscription_id', data.id)
        .single();

      if (!sub) return;

      await supabase.from('subscriptions').update({
        status: data.status,
        current_period_end: new Date(data.current_period_end * 1000).toISOString(),
        updated_at: new Date().toISOString(),
      }).eq('stripe_subscription_id', data.id);
    },

    'customer.subscription.deleted': async (data) => {
      await supabase.from('subscriptions').update({
        plan: 'free',
        status: 'cancelled',
        stripe_subscription_id: null,
        updated_at: new Date().toISOString(),
      }).eq('stripe_subscription_id', data.id);
    },
  };

  const handler = handlers[event.type];
  if (handler) {
    try {
      await handler(event.data.object);
    } catch (err) {
      console.error(`Billing webhook handler error for ${event.type}:`, err);
      return res.status(500).json({ error: 'Handler failed' });
    }
  }

  return res.status(200).json({ received: true });
});

// ============================================
// Health check
// ============================================
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'Tally API', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(`Tally API running on port ${PORT}`);
});
