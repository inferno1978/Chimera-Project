import { apiGet } from "./apiClient";
import { DevicesResponse } from "@b4.devices";

export const devicesApi = {
  list: () => apiGet<DevicesResponse>("/api/devices"),
};
