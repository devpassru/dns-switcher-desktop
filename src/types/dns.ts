export type FallbackDNSOption =
  | "disabled"
  | "system"
  | "yandex"
  | "cloudflare"
  | "google"
  | "custom";

export type ResolutionSource =
  | "doh"
  | "cache"
  | "stale_cache"
  | "excluded"
  | "fallback"
  | "error";

export interface DNSResolutionRecord {
  id: string;
  timestampMs: number;
  domain: string;
  qtype: string;
  source: ResolutionSource;
  serverName: string;
  latencyMs: number;
  resolvedIps: string[];
  isSuccess: boolean;
}

export interface DNSProvider {
  id: string;
  name: string;
  subtitle: string;
  dohUrl: string;
  dotHost: string;
  bootstrapIps: string[];
  plainDnsSupported: boolean;
  websiteUrl: string;
  isBuiltIn: boolean;
  isEnabledInMenuBar: boolean;
}

export type ProviderHealth =
  | { status: "unknown" }
  | { status: "checking" }
  | { status: "healthy"; latencyMs: number; resolvedIP: string }
  | { status: "degraded"; latencyMs: number; reason: string }
  | { status: "unreachable"; reason: string };

export type UpdateStatus =
  | { status: "idle" }
  | { status: "checking" }
  | { status: "up_to_date" }
  | {
      status: "available";
      version: string;
      tagName: string;
      releaseUrl: string;
      downloadUrl: string;
    }
  | { status: "failed"; message: string };

export interface AppStateSnapshot {
  appVersion: string;
  platform: string;
  dnsStack: string;
  serviceKind: string;
  requiredBridgeVersion: number;
  providers: DNSProvider[];
  selectedProviderId: string | null;
  healthMap: Record<string, ProviderHealth>;
  isBridgeInstalled: boolean;
  isBridgeUpToDate: boolean;
  port53Conflict: string | null;
  autoFailoverEnabled: boolean;
  autostartEnabled: boolean;
  resetDnsOnQuit: boolean;
  keepDohOverVpn: boolean;
  isDnsOverriddenByVpn: boolean;
  isVpnActive: boolean;
  fallbackOption: FallbackDNSOption;
  customFallbackIp: string;
  resolvedFallbackIp: string;
  excludedDomains: string[];
  statusMessage: string;
  activeModeText: string;
  shortStatusText: string;
  isCheckingAll: boolean;
  consecutiveFailures: number;
  totalResolvedCount: number;
  historyCount: number;
  updateStatus: UpdateStatus;
}

export const FALLBACK_OPTIONS: { value: FallbackDNSOption; label: string }[] = [
  { value: "disabled", label: "Отключить (без фоллбэка)" },
  { value: "system", label: "Системный (DHCP роутера)" },
  { value: "yandex", label: "Яндекс.DNS (77.88.8.8)" },
  { value: "cloudflare", label: "Cloudflare (1.1.1.1)" },
  { value: "google", label: "Google (8.8.8.8)" },
  { value: "custom", label: "Указать свой IPv4…" },
];
