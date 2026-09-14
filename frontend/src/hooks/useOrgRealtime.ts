import { useEffect, useRef } from 'react';
import { getSupabase } from '../lib/supabaseClient';

/**
 * Subscribe to Supabase Realtime ``postgres_changes`` for one org-scoped
 * table (migration 0009 publishes cyberguard.org_log_events + cyberguard.alerts).
 *
 * Calls ``onChange`` whenever an INSERT/UPDATE/DELETE for the organization
 * arrives. When Supabase is not configured (mock mode / local demo without
 * keys) this is a silent no-op and the caller should fall back to re-fetching
 * on an interval.
 */
export function useOrgRealtime(
  table: 'alerts' | 'org_log_events',
  orgId: string | undefined,
  onChange: () => void,
): void {
  const cbRef = useRef(onChange);
  cbRef.current = onChange;

  useEffect(() => {
    if (!orgId) return;
    let supabase: ReturnType<typeof getSupabase> | null = null;
    try {
      supabase = getSupabase();
    } catch {
      return; // realtime unavailable — caller's polling fallback covers this
    }

    const channelName = `org-${orgId}-${table}`;
    const channel = supabase
      .channel(channelName)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'cyberguard',
          table,
          filter: `organization_id=eq.${orgId}`,
        },
        () => cbRef.current(),
      )
      .subscribe();

    return () => {
      supabase?.removeChannel(channel);
    };
  }, [table, orgId]);
}
