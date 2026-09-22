import { useState, useEffect, useCallback } from 'react';
import { getGmailStatus, GmailStatus } from '../services/api';

export interface UseGmailStatusResult {
  connected: boolean;
  email?: string;
  status: string;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useGmailStatus(): UseGmailStatusResult {
  const [data, setData] = useState<GmailStatus>({
    connected: false,
    status: 'DISCONNECTED',
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await getGmailStatus();
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch Gmail status');
      setData({ connected: false, status: 'DISCONNECTED' });
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  return {
    connected: data.connected,
    email: data.email,
    status: data.status,
    isLoading,
    error,
    refetch: fetchStatus,
  };
}
