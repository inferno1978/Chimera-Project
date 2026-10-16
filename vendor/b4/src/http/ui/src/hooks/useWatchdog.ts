import { useCallback, useEffect, useRef, useState } from "react";
import { watchdogApi } from "@api/watchdog";
import { WatchdogState } from "@models/watchdog";

export function useWatchdog() {
  const [state, setState] = useState<WatchdogState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const initRef = useRef(false);

  const loadStatus = useCallback(async () => {
    try {
      const data = await watchdogApi.status();
      setState(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load watchdog status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initRef.current) return;
    initRef.current = true;
    loadStatus().catch(() => {});
  }, [loadStatus]);

  useEffect(() => {
    const interval = setInterval(() => {
      loadStatus().catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, [loadStatus]);

  const forceCheck = useCallback(async (domain: string) => {
    try {
      await watchdogApi.forceCheck(domain);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Force check failed");
    }
  }, [loadStatus]);

  const addDomain = useCallback(async (domain: string) => {
    try {
      await watchdogApi.addDomain(domain);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add domain");
      throw err;
    }
  }, [loadStatus]);

  const removeDomain = useCallback(async (domain: string) => {
    try {
      await watchdogApi.removeDomain(domain);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove domain");
    }
  }, [loadStatus]);

  const toggleEnabled = useCallback(async (enabled: boolean) => {
    try {
      if (enabled) {
        await watchdogApi.enable();
      } else {
        await watchdogApi.disable();
      }
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle watchdog");
    }
  }, [loadStatus]);

  return {
    state,
    loading,
    error,
    forceCheck,
    addDomain,
    removeDomain,
    toggleEnabled,
    refresh: loadStatus,
  };
}
