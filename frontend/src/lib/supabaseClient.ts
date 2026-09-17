import { createClient } from '@supabase/supabase-js';

// Do not construct a client until Supabase credentials are configured.
const url = import.meta.env.VITE_SUPABASE_URL;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

const client = url && anonKey ? createClient(url, anonKey) : null;

export function getSupabase() {
  if (!client) {
    throw new Error(
      'Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.'
    );
  }
  return client;
}
