import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import type {
  AppStateSnapshot,
  DNSResolutionRecord,
  FallbackDNSOption,
} from "../types/dns";

export const api = {
  getAppState: () => invoke<AppStateSnapshot>("get_app_state"),
  selectProvider: (id: string) => invoke<void>("select_provider", { id }),
  toggleDnsEnabled: (enabled: boolean) =>
    invoke<void>("toggle_dns_enabled", { enabled }),
  checkAllProvidersHealth: () => invoke<void>("check_all_providers_health"),
  selectBestSmartProvider: () => invoke<void>("select_best_smart_provider"),
  installBridgeManually: () => invoke<void>("install_bridge_manually"),
  uninstallBridgeManually: () => invoke<void>("uninstall_bridge_manually"),
  addCustomProvider: (name: string, dohUrl: string, bootstrapIp: string) =>
    invoke<void>("add_custom_provider", { name, dohUrl, bootstrapIp }),
  removeProvider: (id: string) => invoke<void>("remove_provider", { id }),
  toggleProviderInMenuBar: (id: string) =>
    invoke<void>("toggle_provider_in_menu_bar", { id }),
  restoreDefaultProviders: () => invoke<void>("restore_default_providers"),
  addExcludedDomains: (rawInput: string) =>
    invoke<void>("add_excluded_domains", { rawInput }),
  removeExcludedDomain: (domain: string) =>
    invoke<void>("remove_excluded_domain", { domain }),
  clearExcludedDomains: () => invoke<void>("clear_excluded_domains"),
  setFallbackOption: (option: FallbackDNSOption) =>
    invoke<void>("set_fallback_option", { option }),
  setCustomFallbackIp: (ip: string) =>
    invoke<void>("set_custom_fallback_ip", { ip }),
  setKeepDohOverVpn: (enabled: boolean) =>
    invoke<void>("set_keep_doh_over_vpn", { enabled }),
  setAutoFailover: (enabled: boolean) =>
    invoke<void>("set_auto_failover", { enabled }),
  setResetDnsOnQuit: (enabled: boolean) =>
    invoke<void>("set_reset_dns_on_quit", { enabled }),
  setAutostartEnabled: (enabled: boolean) =>
    invoke<void>("set_autostart_enabled", { enabled }),
  flushDnsCache: () => invoke<void>("flush_dns_cache"),
  getHistory: () => invoke<DNSResolutionRecord[]>("get_history"),
  clearHistory: () => invoke<void>("clear_history"),
  checkForUpdates: () => invoke<void>("check_for_updates"),
  openWindow: (label: "main" | "settings" | "history") =>
    invoke<void>("open_window", { label }),
  quitApp: () => invoke<void>("quit_app"),
  openExternalUrl: (url: string) => openUrl(url),
  onStateChanged: (cb: (snap: AppStateSnapshot) => void) =>
    listen<AppStateSnapshot>("state-changed", (e) => cb(e.payload)),
  onHistoryUpdated: (cb: () => void) =>
    listen<void>("history-updated", () => cb()),
};
