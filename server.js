// ============================================
// TALLY — Credit Layer API
// server.js — Main Express Server
// ============================================

console.log('ENV CHECK:', {
  hasUrl: !!process.env.SUPABASE_URL,
  hasKey: !!process.env.SUPABASE_SERVICE_KEY,
  url: process.env.SUPABASE_URL?.slice(0, 30)
})

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import Stripe from 'stripe';
import { randomUUID } from 'crypto';
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

// Raw body needed for Stripe webhook signature verification
app.use('/webhooks/stripe', express.raw({ type: 'application/json' }));
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
app.post('/credits/add', authenticate, async (req, res) => {
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
app.post('/credits/deduct', authenticate, async (req, res) => {
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
app.post('/credits/refund', authenticate, async (req, res) => {
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
// POST /webhooks/stripe
// Auto top-up credits on successful Stripe payment
// Expects metadata: { tally_user_id, tally_credits }
// ============================================
app.post('/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = req.headers['x-tally-webhook-secret'];

  // Find the app by webhook secret
  const { data: apiKey } = await supabase
    .from('api_keys')
    .select('app_id')
    .eq('key', webhookSecret)
    .eq('is_active', true)
    .single();

  if (!apiKey) {
    return res.status(401).json({ error: 'Invalid webhook secret' });
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

    if (!tally_user_id || !tally_credits) {
      return res.status(200).json({ received: true, skipped: 'No tally metadata' });
    }

    const idempotencyKey = `stripe_${intent.id}`;

    // Check for duplicate
    const cached = await checkIdempotency(idempotencyKey, apiKey.app_id);
    if (cached) return res.status(200).json({ received: true, idempotent: true });

    try {
      const appUserId = await getOrCreateUser(apiKey.app_id, tally_user_id);

      const { data: balance } = await supabase
        .from('balances')
        .select('balance')
        .eq('app_user_id', appUserId)
        .single();

      const creditsToAdd = Number(tally_credits);
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
      await saveIdempotency(idempotencyKey, apiKey.app_id, result);

    } catch (err) {
      console.error('Stripe webhook processing error:', err);
      return res.status(500).json({ error: 'Processing failed' });
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
