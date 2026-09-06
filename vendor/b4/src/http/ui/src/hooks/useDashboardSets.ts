import { useEffect, useState, useCallback } from "react";
import { B4SetConfig } from "@models/config";
import { setsApi } from "@b4.sets";

export function useDashboardSets() {
  const [sets, setSets] = useState<B4SetConfig[]>([]);
  const [targetedDomains, setTargetedDomains] = useState<Set<string>>(
    new Set()
  );

  const refresh = useCallback(() => {
    setsApi.getSets().then(setSets).catch(console.error);
    setsApi
      .getTargetedDomains()
      .then((domains) => setTargetedDomains(new Set(domains)))
      .catch(console.error);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { sets, targetedDomains, refresh };
}
