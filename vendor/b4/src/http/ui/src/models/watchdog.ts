export interface WatchdogDomainStatus {
  domain: string;
  status: "healthy" | "degraded" | "escalating" | "queued";
  last_check: string;
  last_failure?: string;
  last_heal?: string;
  consecutive_failures: number;
  interval_sec: number;
  cooldown_until?: string;
  last_error?: string;
  last_speed?: number;
  matched_set?: string;
  matched_set_id?: string;
  display_domain?: string;
}

export interface WatchdogState {
  enabled: boolean;
  domains: WatchdogDomainStatus[];
}
