import { apiGet, apiPost, apiDelete } from "./apiClient";
import { WatchdogState } from "@models/watchdog";

export const watchdogApi = {
  status: () => apiGet<WatchdogState>("/api/watchdog/status"),
  forceCheck: (domain: string) =>
    apiPost("/api/watchdog/check", { domain }),
  addDomain: (domain: string) =>
    apiPost("/api/watchdog/domains", { domain }),
  removeDomain: (domain: string) =>
    apiDelete(`/api/watchdog/domains/${encodeURIComponent(domain)}`),
  enable: () => apiPost("/api/watchdog/enable", {}),
  disable: () => apiPost("/api/watchdog/disable", {}),
};
