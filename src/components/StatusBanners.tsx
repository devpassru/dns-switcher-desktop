import {
  AlertCircle,
  AlertTriangle,
  ArrowDownCircle,
  RefreshCw,
  WifiOff,
} from "lucide-react";
import type { AppStateSnapshot } from "../types/dns";

interface StatusBannersProps {
  state: AppStateSnapshot;
  onSelectFastest: () => void;
  onInstallBridge: () => void;
  onEnableKeepVpn: () => void;
  onOpenRelease: (url: string) => void;
}

export function StatusBanners({
  state,
  onSelectFastest,
  onInstallBridge,
  onEnableKeepVpn,
  onOpenRelease,
}: StatusBannersProps) {
  const activeHealth = state.selectedProviderId
    ? state.healthMap[state.selectedProviderId]
    : undefined;

  return (
    <div className="flex flex-col gap-1.5">
      {state.port53Conflict && (
        <div className="flex items-center gap-2 rounded-lg bg-amber-500/12 px-2.5 py-1.5 text-[11px] text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500" />
          <span className="line-clamp-2">{state.port53Conflict}</span>
        </div>
      )}

      {state.selectedProviderId && activeHealth?.status === "unreachable" && (
        <div className="flex items-center gap-2 rounded-lg bg-red-500/12 px-2.5 py-1.5">
          <AlertCircle className="h-3.5 w-3.5 shrink-0 text-red-500" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold">
              Текущий сервер не отвечает
            </div>
            <div className="truncate text-[10px] text-gray-500 dark:text-gray-400">
              {activeHealth.reason}
            </div>
          </div>
          <button
            type="button"
            onClick={onSelectFastest}
            className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-blue-600"
          >
            Сменить
          </button>
        </div>
      )}

      {state.isBridgeInstalled && !state.isBridgeUpToDate && (
        <div className="flex items-center gap-2 rounded-lg bg-amber-500/12 px-2.5 py-1.5">
          <RefreshCw className="h-3.5 w-3.5 shrink-0 text-amber-500" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold">Обновление DoH-моста</div>
            <div className="text-[10px] text-gray-500 dark:text-gray-400">
              Требуется обновить службу
            </div>
          </div>
          <button
            type="button"
            onClick={onInstallBridge}
            className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-blue-600"
          >
            Обновить
          </button>
        </div>
      )}

      {state.selectedProviderId &&
        state.isDnsOverriddenByVpn &&
        state.isBridgeUpToDate && (
          <div className="flex items-center gap-2 rounded-lg bg-amber-500/12 px-2.5 py-1.5">
            <WifiOff className="h-3.5 w-3.5 shrink-0 text-amber-500" />
            <div className="min-w-0 flex-1">
              <div className="text-[11px] font-semibold">
                VPN использует свой DNS
              </div>
              <div className="text-[10px] text-gray-500 dark:text-gray-400">
                {!state.keepDohOverVpn
                  ? "Удержание DoH поверх VPN выключено"
                  : "Туннель перехватил системный DNS"}
              </div>
            </div>
            {!state.keepDohOverVpn && (
              <button
                type="button"
                onClick={onEnableKeepVpn}
                className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-blue-600"
              >
                Включить
              </button>
            )}
          </div>
        )}

      {state.updateStatus.status === "available" && (
        <div className="flex items-center gap-2 rounded-lg bg-blue-500/12 px-2.5 py-1.5">
          <ArrowDownCircle className="h-3.5 w-3.5 shrink-0 text-blue-500" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold">
              Доступна версия v{state.updateStatus.version}
            </div>
            <div className="text-[10px] text-gray-500 dark:text-gray-400">
              Обновление на GitHub Releases
            </div>
          </div>
          <button
            type="button"
            onClick={() =>
              state.updateStatus.status === "available" &&
              onOpenRelease(state.updateStatus.releaseUrl)
            }
            className="shrink-0 rounded bg-blue-500 px-2 py-0.5 text-[11px] font-medium text-white hover:bg-blue-600"
          >
            Скачать
          </button>
        </div>
      )}
    </div>
  );
}
