import { createClient } from '@supabase/supabase-js';

// Do not construct a client until real-backend mode is actually configured.
// Mock mode intentionally works without a .env file or Supabase project.
const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

const client = url && anonKey ? createClient(url, anonKey) : null;

export function getSupabase() {
  if (!client) {
    throw new Error(
      'Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY before using VITE_USE_MOCK=false.'
    );
  }
  return client;
}
