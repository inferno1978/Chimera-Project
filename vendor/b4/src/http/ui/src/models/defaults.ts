import { v4 as uuidv4 } from "uuid";
import { B4SetConfig } from "./config";
import generated from "./defaults.json";

export function createDefaultSet(setCount: number): B4SetConfig {
  const set = structuredClone(generated) as unknown as B4SetConfig;
  set.id = uuidv4();
  set.name = `Set ${setCount + 1}`;
  return set;
}
