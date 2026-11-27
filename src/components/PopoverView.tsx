import { Check, Loader2, RefreshCw, Shield, ShieldOff, Zap } from "lucide-react";
import { api } from "../api/tauri";
import type { AppStateSnapshot } from "../types/dns";
import { HealthBadge } from "./HealthBadge";
import { StatusBanners } from "./StatusBanners";
import { ToggleSwitch } from "./ToggleSwitch";

export function PopoverView({ state }: { state: AppStateSnapshot }) {
  const isActive = state.selectedProviderId !== null;
  const visibleProviders = state.providers.filter((p) => p.isEnabledInMenuBar);

  return (
    <div className="flex h-screen flex-col justify-between bg-white/95 p-3 text-gray-900 dark:bg-[#1b1d24]/95 dark:text-gray-100">
      <div className="flex flex-col gap-2.5 overflow-y-auto pr-0.5">
        {/* Header */}
        <div className="flex items-center gap-2.5 px-1 py-0.5">
          <div
            className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full transition-colors ${
              isActive
                ? "bg-blue-500 text-white"
                : "bg-gray-200 text-gray-500 dark:bg-white/10 dark:text-gray-400"
            }`}
          >
            {isActive ? (
              <Shield className="h-4 w-4" />
            ) : (
              <ShieldOff className="h-4 w-4" />
            )}
          </div>

          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-1.5">
              <span className="text-[13px] font-semibold">AI DNS</span>
              <span className="font-mono text-[10px] text-gray-400">
                v{state.appVersion}
              </span>
            </div>
            <div className="truncate text-[11px] text-gray-500 dark:text-gray-400">
              {state.shortStatusText}
            </div>
          </div>

          <ToggleSwitch
            checked={isActive}
            onChange={(next) => api.toggleDnsEnabled(next)}
          />
        </div>

        <StatusBanners
          state={state}
          onSelectFastest={() => api.selectBestSmartProvider()}
          onInstallBridge={() => api.installBridgeManually()}
          onEnableKeepVpn={() => api.setKeepDohOverVpn(true)}
          onOpenRelease={(url) => api.openExternalUrl(url)}
        />

        <div className="h-px bg-gray-200/80 dark:bg-white/10" />

        {/* Servers Section */}
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between px-1.5 pb-0.5">
            <span className="text-[11px] font-semibold text-gray-500 dark:text-gray-400">
              Серверы
            </span>
            <div className="flex items-center gap-1">
              <button
                type="button"
                disabled={state.isCheckingAll}
                title="Выбрать самый быстрый сервер"
                onClick={() => api.selectBestSmartProvider()}
                className="flex h-5 w-5 items-center justify-center rounded text-gray-500 hover:bg-gray-200/70 disabled:opacity-40 dark:text-gray-400 dark:hover:bg-white/10"
              >
                <Zap className="h-3 w-3" />
              </button>
              <button
                type="button"
                disabled={state.isCheckingAll}
                title="Обновить пинг"
                onClick={() => api.checkAllProvidersHealth()}
                className="flex h-5 w-5 items-center justify-center rounded text-gray-500 hover:bg-gray-200/70 disabled:opacity-40 dark:text-gray-400 dark:hover:bg-white/10"
              >
                {state.isCheckingAll ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <RefreshCw className="h-3 w-3" />
                )}
              </button>
            </div>
          </div>

          {visibleProviders.length === 0 ? (
            <div className="px-2 py-2 text-[11px] text-gray-500 dark:text-gray-400">
              Серверы скрыты из меню трея. Включите их в Настройках.
            </div>
          ) : (
            <div className="flex flex-col gap-0.5">
              {visibleProviders.map((provider) => {
                const selected = state.selectedProviderId === provider.id;
                const health = state.healthMap[provider.id];
                return (
                  <button
                    key={provider.id}
                    type="button"
                    onClick={() => api.selectProvider(provider.id)}
                    className={`flex items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors ${
                      selected
                        ? "bg-blue-500/10 text-gray-900 dark:bg-white/10 dark:text-white"
                        : "hover:bg-gray-100 dark:hover:bg-white/5"
                    }`}
                  >
                    <span className="flex w-3.5 shrink-0 items-center justify-center">
                      {selected && (
                        <Check className="h-3.5 w-3.5 stroke-[2.5] text-blue-500" />
                      )}
                    </span>
                    <span
                      className={`min-w-0 flex-1 truncate text-[13px] ${
                        selected ? "font-medium" : "font-normal"
                      }`}
                    >
                      {provider.name}
                    </span>
                    <HealthBadge health={health} compact />
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="px-1.5 text-[10px] text-gray-400 dark:text-gray-500">
          {state.statusMessage}
        </div>
      </div>

      {/* Footer */}
      <div className="mt-2 flex flex-col gap-0.5 border-t border-gray-200/80 pt-2 dark:border-white/10">
        <button
          type="button"
          onClick={() => api.openWindow("settings")}
          className="flex items-center justify-between rounded-md px-2 py-1.5 text-[13px] hover:bg-gray-100 dark:hover:bg-white/8"
        >
          <span>Настройки AI DNS…</span>
          <span className="text-[11px] text-gray-400">Ctrl+,</span>
        </button>
        <button
          type="button"
          onClick={() => api.openWindow("history")}
          className="flex items-center justify-between rounded-md px-2 py-1.5 text-[13px] hover:bg-gray-100 dark:hover:bg-white/8"
        >
          <span>История запросов…</span>
          <span className="text-[11px] text-gray-400">
            {state.historyCount > 0 ? state.historyCount : ""}
          </span>
        </button>
        <button
          type="button"
          onClick={() => api.quitApp()}
          className="flex items-center justify-between rounded-md px-2 py-1.5 text-[13px] text-red-600 hover:bg-red-500/10 dark:text-red-400"
        >
          <span>Выход</span>
          <span className="text-[11px] opacity-70">Ctrl+Q</span>
        </button>
      </div>
    </div>
  );
}
