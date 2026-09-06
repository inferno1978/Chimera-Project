export interface ParsedLog {
  timestamp: string;
  protocol: "TCP" | "UDP";
  hostSet: string;
  ipSet: string;
  domain: string;
  source: string;
  sourceAlias: string;
  deviceName: string;
  destination: string;
  tls: string;
  flags: string;
  raw: string;
}

export type SortColumn =
  | "timestamp"
  | "set"
  | "protocol"
  | "domain"
  | "source"
  | "destination";

export interface DomainModalState {
  open: boolean;
  domain: string;
  variants: string[];
  selected: string;
}
