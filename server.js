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
    .select('id, app_id, is_active, is_sandbox')
    .eq('key', key)
    .single();

  if (error || !data || !data.is_active) {
    return res.status(401).json({ error: 'Invalid or inactive API key' });
  }

  req.appId = data.app_id;
  req.apiKeyId = data.id;
  req.isSandbox = data.is_sandbox || key.startsWith('tally_test_');
  next();
}



// ============================================
// HELPER: Fire low balance webhook
// Called after every deduction
// ============================================
async function checkAndFireLowBalanceAlert(appId, appUserId, externalUserId, balanceAfter, isSandbox) {
  try {
    // Skip alerts for sandbox mode
    if (isSandbox) return;

    // Get app alert config
    const { data: app } = await supabase
      .from('apps')
      .select('alert_enabled, alert_threshold, alert_webhook_url, name')
      .eq('id', appId)
      .single();

    if (!app?.alert_enabled || !app?.alert_webhook_url || !app?.alert_threshold) return;
    if (balanceAfter > Number(app.alert_threshold)) return;

    // Check last alert — don't spam (max 1 alert per hour per user)
    const { data: user } = await supabase
      .from('app_users')
      .select('last_alert_sent_at')
      .eq('id', appUserId)
      .single();

    if (user?.last_alert_sent_at) {
      const lastAlert = new Date(user.last_alert_sent_at);
      const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
      if (lastAlert > hourAgo) return; // Already alerted within the last hour
    }

    // Update last alert time
    await supabase
      .from('app_users')
      .update({ last_alert_sent_at: new Date().toISOString() })
      .eq('id', appUserId);

    // Fire the webhook
    const payload = {
      event: 'credits.low_balance',
      app_id: appId,
      app_name: app.name,
      user_id: externalUserId,
      balance: balanceAfter,
      threshold: Number(app.alert_threshold),
      timestamp: new Date().toISOString(),
    };

    await fetch(app.alert_webhook_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tally-Event': 'credits.low_balance',
        'X-Tally-App-Id': appId,
      },
      body: JSON.stringify(payload),
    });

    console.log(`Low balance alert fired for user ${externalUserId} in app ${appId}`);
  } catch (err) {
    // Never throw — alerts are best-effort
    console.error('Low balance alert error:', err.message);
  }
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
async function getOrCreateUser(appId, externalId, isSandbox = false) {
  // Try to find existing user
  const { data: existing } = await supabase
    .from('app_users')
    .select('id')
    .eq('app_id', appId)
    .eq('external_id', externalId)
    .eq('is_sandbox', isSandbox)
    .single();

  if (existing) return existing.id;

  // Create user
  const { data: newUser, error } = await supabase
    .from('app_users')
    .insert({ app_id: appId, external_id: externalId, is_sandbox: isSandbox })
    .select('id')
    .single();

  if (error) throw new Error('Failed to create user');

  // Initialise balance row
  await supabase
    .from('balances')
    .insert({ app_user_id: newUser.id, balance: 0, is_sandbox: isSandbox });

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
  const { user_id, amount, description, reference_id, metadata, expires_in_days } = req.body;
  const idempotencyKey = req.headers['idempotency-key'];

  if (!user_id || !amount || amount <= 0) {
    return res.status(400).json({ error: 'user_id and a positive amount are required' });
  }

  // Idempotency check
  const cached = await checkIdempotency(idempotencyKey, req.appId);
  if (cached) return res.status(200).json({ ...cached, idempotent: true });

  try {
    const appUserId = await getOrCreateUser(req.appId, user_id, req.isSandbox);

    // Atomic balance update + ledger write
    const { data: balance, error: balanceError } = await supabase
      .from('balances')
      .select('balance')
      .eq('app_user_id', appUserId)
      .eq('is_sandbox', req.isSandbox)
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
        is_sandbox: req.isSandbox,
      })
      .select('id')
      .single();

    const result = {
      success: true,
      ledger_id: ledgerEntry.id,
      user_id,
      amount: Number(amount),
      balance_after: balanceAfter,
      expires_at: expiresAt,
      sandbox: req.isSandbox,
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
      p_is_sandbox: req.isSandbox,
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
      sandbox: req.isSandbox,
    };

    await saveIdempotency(idempotencyKey, req.appId, result);

    // Fire low balance alert if needed (async, non-blocking)
    checkAndFireLowBalanceAlert(req.appId, appUserId, user_id, data.balance_after, req.isSandbox);

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
      .eq('is_sandbox', req.isSandbox)
      .single();

    if (!user) {
      return res.status(200).json({ user_id, balance: 0, sandbox: req.isSandbox });
    }

    const { data: balance } = await supabase
      .from('balances')
      .select('balance, updated_at')
      .eq('app_user_id', user.id)
      .eq('is_sandbox', req.isSandbox)
      .single();

    // Process any expired credits before returning balance
    await supabase.rpc('process_expired_credits', { p_app_user_id: user.id });

    // Re-fetch balance after expiry processing
    const { data: freshBalance } = await supabase
      .from('balances')
      .select('balance, updated_at')
      .eq('app_user_id', user.id)
      .single();

    return res.status(200).json({
      user_id,
      balance: Number(freshBalance?.balance || 0),
      updated_at: freshBalance?.updated_at,
      sandbox: req.isSandbox,
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
      .eq('is_sandbox', req.isSandbox)
      .single();

    if (!user) {
      return res.status(200).json({ user_id, entries: [], total: 0, sandbox: req.isSandbox });
    }

    const { data: entries, count } = await supabase
      .from('ledger')
      .select('id, event_type, amount, balance_after, reference_id, description, metadata, created_at, expires_at', { count: 'exact' })
      .eq('app_user_id', user.id)
      .eq('is_sandbox', req.isSandbox)
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

// ============================================
// HOSTED TOP-UP PAGE
// GET /topup/:appId?user_id=xxx
// Shows a branded page for end users to buy credits
// ============================================
app.get('/topup/:appId', async (req, res) => {
  const { appId } = req.params;
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).send('<h2>Missing user_id parameter</h2>');
  }

  // Get app details
  const { data: app, error: appError } = await supabase
    .from('apps')
    .select('id, name, brand_name, brand_color, topup_success_url, topup_cancel_url')
    .eq('id', appId)
    .single();

  if (appError || !app) {
    return res.status(404).send('<h2>App not found</h2>');
  }

  // Get active credit packages
  const { data: packages } = await supabase
    .from('credit_packages')
    .select('*')
    .eq('app_id', appId)
    .eq('is_active', true)
    .order('sort_order', { ascending: true });

  if (!packages || packages.length === 0) {
    return res.status(404).send('<h2>No credit packages configured for this app</h2>');
  }

  const brandName = app.brand_name || app.name;
  const brandColor = app.brand_color || '#00ff88';
  const currencySymbol = { gbp: '£', usd: '$', eur: '€', ngn: '₦' };

  const packagesHTML = packages.map(pkg => {
    const symbol = currencySymbol[pkg.currency] || pkg.currency.toUpperCase();
    const price = (pkg.price_amount / 100).toFixed(2);
    return `
      <div class="package ${pkg.is_popular ? 'popular' : ''}" onclick="buy('${pkg.id}')">
        ${pkg.is_popular ? '<div class="popular-badge">Most Popular</div>' : ''}
        <div class="pkg-name">${pkg.name}</div>
        <div class="pkg-credits">${pkg.credits.toLocaleString()} <span>credits</span></div>
        ${pkg.description ? `<div class="pkg-desc">${pkg.description}</div>` : ''}
        <div class="pkg-price">${symbol}${price}</div>
        <button class="pkg-btn" style="background: ${brandColor}; color: #000;">
          Buy now
        </button>
      </div>
    `;
  }).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Buy Credits — ${brandName}</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root { --accent: ${brandColor}; }
    html, body { min-height: 100vh; background: #0a0a0a; color: #f0f0f0; font-family: 'Syne', sans-serif; -webkit-font-smoothing: antialiased; }
    .container { max-width: 700px; margin: 0 auto; padding: 60px 24px; }
    .header { text-align: center; margin-bottom: 48px; }
    .brand { font-size: 14px; color: #555; font-family: 'DM Mono', monospace; margin-bottom: 12px; }
    h1 { font-size: 36px; font-weight: 800; letter-spacing: -1px; margin-bottom: 10px; }
    h1 span { color: var(--accent); }
    .subtitle { font-size: 14px; color: #666; font-family: 'DM Mono', monospace; }
    .packages { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }
    .package { background: #111; border: 1px solid #1a1a1a; border-radius: 12px; padding: 24px; text-align: center; cursor: pointer; position: relative; transition: border-color 0.2s, transform 0.2s; }
    .package:hover { border-color: var(--accent); transform: translateY(-2px); }
    .package.popular { border-color: var(--accent); }
    .popular-badge { position: absolute; top: -10px; left: 50%; transform: translateX(-50%); background: var(--accent); color: #000; font-size: 10px; font-weight: 700; padding: 3px 12px; border-radius: 20px; white-space: nowrap; font-family: 'DM Mono', monospace; }
    .pkg-name { font-size: 14px; font-weight: 700; margin-bottom: 12px; }
    .pkg-credits { font-size: 32px; font-weight: 800; letter-spacing: -1px; color: var(--accent); margin-bottom: 4px; }
    .pkg-credits span { font-size: 14px; color: #555; font-weight: 400; }
    .pkg-desc { font-size: 11px; color: #555; font-family: 'DM Mono', monospace; margin-bottom: 12px; line-height: 1.5; }
    .pkg-price { font-size: 20px; font-weight: 800; margin-bottom: 16px; }
    .pkg-btn { width: 100%; padding: 11px; border: none; border-radius: 6px; font-size: 13px; font-weight: 700; cursor: pointer; font-family: 'Syne', sans-serif; transition: opacity 0.15s; }
    .pkg-btn:hover { opacity: 0.85; }
    .footer { text-align: center; margin-top: 40px; font-size: 11px; color: #333; font-family: 'DM Mono', monospace; }
    .footer a { color: #444; text-decoration: none; }
    .loading { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 100; }
    .loading.show { display: flex; }
    .spinner { width: 32px; height: 32px; border: 3px solid #222; border-top-color: var(--accent); border-radius: 50%; animation: spin 0.6s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="loading" id="loading"><div class="spinner"></div></div>
  <div class="container">
    <div class="header">
      <div class="brand">${brandName}</div>
      <h1>Buy <span>credits</span></h1>
      <div class="subtitle">Choose a package to top up your balance instantly</div>
    </div>
    <div class="packages">${packagesHTML}</div>
    <div class="footer">
      Payments powered by Stripe &nbsp;·&nbsp;
      <a href="https://tally-landing-ochre.vercel.app" target="_blank">Powered by Tally</a>
    </div>
  </div>
  <script>
    async function buy(packageId) {
      document.getElementById('loading').classList.add('show');
      try {
        const res = await fetch('/topup/${appId}/checkout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package_id: packageId, user_id: '${user_id}' })
        });
        const { url, error } = await res.json();
        if (error) { alert(error); document.getElementById('loading').classList.remove('show'); return; }
        window.location.href = url;
      } catch (err) {
        alert('Something went wrong. Please try again.');
        document.getElementById('loading').classList.remove('show');
      }
    }
  </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  return res.send(html);
});

// ============================================
// POST /topup/:appId/checkout
// Creates Stripe checkout for a credit package
// ============================================
app.post('/topup/:appId/checkout', async (req, res) => {
  const { appId } = req.params;
  const { package_id, user_id } = req.body;

  if (!package_id || !user_id) {
    return res.status(400).json({ error: 'package_id and user_id are required' });
  }

  // Get package
  const { data: pkg, error: pkgError } = await supabase
    .from('credit_packages')
    .select('*, apps(name, brand_name, topup_success_url, topup_cancel_url)')
    .eq('id', package_id)
    .eq('app_id', appId)
    .eq('is_active', true)
    .single();

  if (pkgError || !pkg) {
    return res.status(404).json({ error: 'Package not found' });
  }

  const app = pkg.apps;
  const successUrl = app.topup_success_url || `${process.env.DASHBOARD_URL}?topup=success`;
  const cancelUrl = app.topup_cancel_url || `${process.env.API_URL}/topup/${appId}?user_id=${user_id}`;

  try {
    // Use existing Stripe price if set, otherwise create dynamic session
    const sessionParams = {
      mode: 'payment',
      payment_method_types: ['card'],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        tally_user_id: user_id,
        tally_credits: String(pkg.credits),
        tally_app_id: appId,
      },
    };

    if (pkg.stripe_price_id) {
      sessionParams.line_items = [{ price: pkg.stripe_price_id, quantity: 1 }];
    } else {
      sessionParams.line_items = [{
        price_data: {
          currency: pkg.currency,
          product_data: {
            name: `${pkg.credits.toLocaleString()} Credits — ${app.brand_name || app.name}`,
            description: pkg.description || `${pkg.credits.toLocaleString()} credits for ${app.brand_name || app.name}`,
          },
          unit_amount: pkg.price_amount,
        },
        quantity: 1,
      }];
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error('Top-up checkout error:', err);
    return res.status(500).json({ error: 'Failed to create checkout' });
  }
});

// ============================================
// PACKAGES API — for dashboard management
// ============================================

// GET /apps/:appId/packages
app.get('/apps/:appId/packages', authenticate, async (req, res) => {
  if (req.appId !== req.params.appId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { data } = await supabase
    .from('credit_packages')
    .select('*')
    .eq('app_id', req.params.appId)
    .order('sort_order', { ascending: true });
  return res.status(200).json({ packages: data || [] });
});

// POST /apps/:appId/packages
app.post('/apps/:appId/packages', authenticate, async (req, res) => {
  if (req.appId !== req.params.appId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { name, description, credits, price_amount, currency, is_popular, sort_order } = req.body;
  if (!name || !credits || !price_amount) {
    return res.status(400).json({ error: 'name, credits, and price_amount are required' });
  }
  const { data, error } = await supabase
    .from('credit_packages')
    .insert({ app_id: req.params.appId, name, description, credits, price_amount, currency: currency || 'gbp', is_popular: is_popular || false, sort_order: sort_order || 0 })
    .select()
    .single();
  if (error) return res.status(500).json({ error: 'Failed to create package' });
  return res.status(200).json({ package: data });
});

// PUT /apps/:appId/packages/:packageId
app.put('/apps/:appId/packages/:packageId', authenticate, async (req, res) => {
  if (req.appId !== req.params.appId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { name, description, credits, price_amount, currency, is_popular, is_active, sort_order } = req.body;
  const { data, error } = await supabase
    .from('credit_packages')
    .update({ name, description, credits, price_amount, currency, is_popular, is_active, sort_order })
    .eq('id', req.params.packageId)
    .eq('app_id', req.params.appId)
    .select()
    .single();
  if (error) return res.status(500).json({ error: 'Failed to update package' });
  return res.status(200).json({ package: data });
});

// DELETE /apps/:appId/packages/:packageId
app.delete('/apps/:appId/packages/:packageId', authenticate, async (req, res) => {
  if (req.appId !== req.params.appId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  await supabase
    .from('credit_packages')
    .update({ is_active: false })
    .eq('id', req.params.packageId)
    .eq('app_id', req.params.appId);
  return res.status(200).json({ success: true });
});
