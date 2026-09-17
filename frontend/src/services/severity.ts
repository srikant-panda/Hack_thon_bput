import type { Severity } from '../types';

// ---------------------------------------------------------------------------
// Score bands
// 0-20 safe | 21-40 low | 41-60 medium | 61-80 high | 81-100 critical
// ---------------------------------------------------------------------------
export function getSeverityFromScore(score: number): Severity {
  if (score <= 20) return 'safe';
  if (score <= 40) return 'low';
  if (score <= 60) return 'medium';
  if (score <= 80) return 'high';
  return 'critical';
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  safe: '#10b981',
  low: '#eab308',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};
