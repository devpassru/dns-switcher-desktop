import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronUp,
  ExternalLink,
  GitBranch,
  Loader2,
  Network,
  Plus,
  Server,
  Settings,
  ShieldCheck,
  ShieldOff,
  Trash2,
} from "lucide-react";
import { api } from "../api/tauri";
import {
  FALLBACK_OPTIONS,
  type AppStateSnapshot,
  type FallbackDNSOption,
} from "../types/dns";
import { HealthBadge } from "./HealthBadge";
import { ToggleSwitch } from "./ToggleSwitch";

type TabId = "servers" | "bridge" | "exceptions" | "general";

function isValidIpv4(ip: string): boolean {
  const s = ip.trim();
  if (!s || s.startsWith("127.") || s === "0.0.0.0") return false;
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

export function SettingsView({ state }: { state: AppStateSnapshot }) {
  const [tab, setTab] = useState<TabId>("servers");
  const [showAddForm, setShowAddForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDohUrl, setNewDohUrl] = useState("");
  const [newBootstrapIp, setNewBootstrapIp] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [newExcluded, setNewExcluded] = useState("");

  const enabledCount = state.providers.filter((p) => p.isEnabledInMenuBar).length;

  const tabs: { id: TabId; label: string; icon: typeof Server }[] = [
    { id: "servers", label: "Серверы", icon: Server },
    { id: "bridge", label: "DoH-мост", icon: Network },
    { id: "exceptions", label: "Исключения", icon: GitBranch },
    { id: "general", label: "Основные", icon: Settings },
  ];

  const handleAddProvider = async () => {
    setFormError(null);
    try {
      await api.addCustomProvider(newName, newDohUrl, newBootstrapIp);
      setNewName("");
      setNewDohUrl("");
      setNewBootstrapIp("");
      setShowAddForm(false);
    } catch (err) {
      setFormError(String(err));
    }
  };

  const handleAddExcluded = async () => {
    const trimmed = newExcluded.trim();
    if (!trimmed) return;
    await api.addExcludedDomains(trimmed);
    setNewExcluded("");
  };

  return (
    <div className="flex h-screen flex-col bg-[#f4f5f7] text-gray-900 dark:bg-[#16181d] dark:text-gray-100">
      {/* Segmented Tab Bar */}
      <div className="border-b border-gray-200 bg-white/80 px-5 py-3 dark:border-white/10 dark:bg-[#1c1f26]">
        <div className="grid grid-cols-4 gap-1 rounded-lg bg-gray-200/70 p-1 dark:bg-black/30">
          {tabs.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={`flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-all ${
                  active
                    ? "bg-white text-gray-900 shadow-sm dark:bg-[#2a2e39] dark:text-white"
                    : "text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5">
        {tab === "servers" && (
          <div className="mx-auto flex max-w-xl flex-col gap-4">
            <div className="flex items-center justify-between rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <div>
                <h2 className="text-sm font-semibold">Серверы DNS-over-HTTPS</h2>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Всего: {state.providers.length} • В меню трея: {enabledCount}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddForm((v) => !v)}
                  className="inline-flex items-center gap-1 rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600"
                >
                  {showAddForm ? (
                    <>
                      <ChevronUp className="h-3.5 w-3.5" /> Скрыть
                    </>
                  ) : (
                    <>
                      <Plus className="h-3.5 w-3.5" /> Добавить…
                    </>
                  )}
                </button>
              </div>
            </div>

            {showAddForm && (
              <div className="flex flex-col gap-2.5 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
                <div className="text-xs font-semibold text-gray-600 dark:text-gray-300">
                  Новый DoH-сервер
                </div>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Название (например, Quad9 DNS)"
                  className="rounded-lg border border-gray-300 bg-transparent px-3 py-1.5 text-xs focus:border-blue-500 focus:outline-none dark:border-white/15"
                />
                <input
                  type="url"
                  value={newDohUrl}
                  onChange={(e) => setNewDohUrl(e.target.value)}
                  placeholder="DoH URL (https://.../dns-query)"
                  className="rounded-lg border border-gray-300 bg-transparent px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none dark:border-white/15"
                />
                <input
                  type="text"
                  value={newBootstrapIp}
                  onChange={(e) => setNewBootstrapIp(e.target.value)}
                  placeholder="Bootstrap IPv4 (необязательно, например 9.9.9.9)"
                  className="rounded-lg border border-gray-300 bg-transparent px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none dark:border-white/15"
                />
                {formError && (
                  <div className="text-xs text-red-500">{formError}</div>
                )}
                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setShowAddForm(false)}
                    className="rounded-lg border border-gray-300 px-3 py-1 text-xs hover:bg-gray-100 dark:border-white/15 dark:hover:bg-white/5"
                  >
                    Отмена
                  </button>
                  <button
                    type="button"
                    disabled={!newName.trim() || !newDohUrl.startsWith("https://")}
                    onClick={handleAddProvider}
                    className="rounded-lg bg-blue-500 px-3 py-1 text-xs font-medium text-white hover:bg-blue-600 disabled:opacity-40"
                  >
                    Добавить сервер
                  </button>
                </div>
              </div>
            )}

            <div className="flex flex-col divide-y divide-gray-200 rounded-xl border border-gray-200 bg-white dark:divide-white/10 dark:border-white/10 dark:bg-[#1e2128]">
              {state.providers.length === 0 ? (
                <div className="flex items-center justify-between gap-3 px-4 py-4">
                  <div>
                    <div className="text-xs font-semibold">
                      В системе нет DNS-серверов
                    </div>
                    <div className="text-[11px] text-gray-500 dark:text-gray-400">
                      URL можно получить на rungate
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowAddForm(true)}
                    className="shrink-0 rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600"
                  >
                    Добавить…
                  </button>
                </div>
              ) : (
                state.providers.map((p) => (
                <div key={p.id} className="flex items-center gap-3 px-4 py-3">
                  <ToggleSwitch
                    checked={p.isEnabledInMenuBar}
                    onChange={() => api.toggleProviderInMenuBar(p.id)}
                    title={
                      p.isEnabledInMenuBar
                        ? "Отображается в трее"
                        : "Скрыт из меню трея"
                    }
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-[13px] font-medium">
                        {p.name}
                      </span>
                      {p.isBuiltIn ? (
                        <span className="rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] font-medium text-blue-600 dark:text-blue-400">
                          Встроенный
                        </span>
                      ) : (
                        <span className="rounded bg-purple-500/15 px-1.5 py-0.5 text-[10px] font-medium text-purple-600 dark:text-purple-400">
                          Пользовательский
                        </span>
                      )}
                      {!p.isEnabledInMenuBar && (
                        <span className="text-[10px] text-gray-400">Скрыт</span>
                      )}
                    </div>
                    <div className="truncate font-mono text-[11px] text-gray-500 dark:text-gray-400">
                      {p.dohUrl}
                    </div>
                  </div>

                  <HealthBadge health={state.healthMap[p.id]} compact={false} />

                  <button
                    type="button"
                    title="Удалить DNS-сервер"
                    onClick={() => api.removeProvider(p.id)}
                    className="rounded p-1.5 text-red-500 hover:bg-red-500/10"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
                ))
              )}
            </div>
            <p className="px-1 text-[11px] text-gray-500 dark:text-gray-400">
              Тумблер слева включает или выключает сервер в списке быстрого
              переключения в трее. Значок корзины удаляет сервер.
            </p>
          </div>
        )}

        {tab === "bridge" && (
          <div className="mx-auto flex max-w-xl flex-col gap-4">
            {/* Bridge Service Card */}
            <div className="flex items-start gap-3 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <span
                className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${
                  !state.isBridgeInstalled || !state.isBridgeUpToDate
                    ? "bg-amber-500"
                    : "bg-emerald-500"
                }`}
              />
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-semibold">
                  {!state.isBridgeInstalled
                    ? `Служба моста (${state.serviceKind}) не установлена`
                    : !state.isBridgeUpToDate
                    ? "Служба установлена (требуется обновление)"
                    : `Служба моста (${state.serviceKind}) активна`}
                </div>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  Локальный системный сервис перехватывает DNS-запросы на{" "}
                  <code className="font-mono">127.0.0.1:53</code> и отправляет их
                  в локальный DoH-прокси без необходимости запрашивать права
                  администратора при каждом переключении.
                </p>
              </div>
              {!state.isBridgeInstalled ? (
                <button
                  type="button"
                  onClick={() => api.installBridgeManually()}
                  className="shrink-0 rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600"
                >
                  Установить…
                </button>
              ) : !state.isBridgeUpToDate ? (
                <button
                  type="button"
                  onClick={() => api.installBridgeManually()}
                  className="shrink-0 rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600"
                >
                  Обновить…
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => api.uninstallBridgeManually()}
                  className="shrink-0 rounded-lg border border-gray-300 px-3 py-1.5 text-xs font-medium hover:bg-gray-100 dark:border-white/15 dark:hover:bg-white/5"
                >
                  Удалить
                </button>
              )}
            </div>

            {/* VPN Compatibility */}
            <div className="flex flex-col gap-2 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[13px] font-medium">
                    Удерживать DoH поверх VPN (WireGuard, OpenVPN, GlobalProtect)
                  </div>
                  <p className="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
                    Сохраняет 127.0.0.1 основным DNS при подключении корпоративных
                    VPN, оставляя внутренние домены в Split-DNS. Прокси-клиенты
                    с FakeIP (v2Ray, Clash, Sing-box, Outline и др.) не
                    затрагиваются.
                  </p>
                </div>
                <ToggleSwitch
                  checked={state.keepDohOverVpn}
                  onChange={(v) => api.setKeepDohOverVpn(v)}
                />
              </div>

              {state.isDnsOverriddenByVpn && (
                <div className="flex items-center gap-2 rounded-lg bg-amber-500/12 px-2.5 py-1.5 text-xs text-amber-700 dark:text-amber-300">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500" />
                  <span>
                    Сейчас активный VPN перехватил системный DNS и направляет
                    запросы в обход DoH.
                  </span>
                </div>
              )}
            </div>

            {/* Fallback DNS */}
            <div className="flex flex-col gap-2.5 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-center justify-between gap-3">
                <label className="text-[13px] font-medium">
                  Резервный DNS (Фоллбэк) при сбое DoH:
                </label>
                <select
                  value={state.fallbackOption}
                  onChange={(e) =>
                    api.setFallbackOption(e.target.value as FallbackDNSOption)
                  }
                  className="rounded-lg border border-gray-300 bg-white px-2.5 py-1 text-xs dark:border-white/15 dark:bg-[#262a34]"
                >
                  {FALLBACK_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>

              {state.fallbackOption === "custom" && (
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={state.customFallbackIp}
                    onChange={(e) => api.setCustomFallbackIp(e.target.value)}
                    placeholder="IPv4-адрес (например, 9.9.9.9)"
                    className="flex-1 rounded-lg border border-gray-300 bg-transparent px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none dark:border-white/15"
                  />
                  {isValidIpv4(state.customFallbackIp) ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  ) : (
                    state.customFallbackIp.trim() && (
                      <AlertTriangle className="h-4 w-4 text-amber-500" />
                    )
                  )}
                </div>
              )}

              {state.fallbackOption === "disabled" ? (
                <div className="flex items-center gap-2 text-xs text-amber-600 dark:text-amber-400">
                  <ShieldOff className="h-3.5 w-3.5 shrink-0" />
                  <span>
                    Фоллбэк отключён: при недоступности DoH запросы не утекают
                    на открытые DNS (возвращается SERVFAIL).
                  </span>
                </div>
              ) : (
                <div className="text-xs text-gray-500 dark:text-gray-400">
                  Используется при временном сбое DoH или когда приложение
                  выключено • Активен:{" "}
                  <span className="font-mono">{state.resolvedFallbackIp}:53</span>
                </div>
              )}
            </div>

            {/* Diagnostics */}
            <div className="flex flex-col divide-y divide-gray-200 rounded-xl border border-gray-200 bg-white dark:divide-white/10 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">Системный кэш DNS</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    {state.totalResolvedCount > 0
                      ? `Обработано запросов прокси: ${state.totalResolvedCount}`
                      : `Сбросить кэш резолвера (${state.dnsStack})`}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => api.flushDnsCache()}
                  className="rounded-lg border border-gray-300 px-3 py-1 text-xs hover:bg-gray-100 dark:border-white/15 dark:hover:bg-white/5"
                >
                  Очистить кэш
                </button>
              </div>
              <div className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">Журнал DNS-запросов</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    Записей в сессии: {state.historyCount} (кэш, DoH, задержки)
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => api.openWindow("history")}
                  className="rounded-lg border border-gray-300 px-3 py-1 text-xs hover:bg-gray-100 dark:border-white/15 dark:hover:bg-white/5"
                >
                  Показать историю…
                </button>
              </div>
            </div>
          </div>
        )}

        {tab === "exceptions" && (
          <div className="mx-auto flex max-w-xl flex-col gap-4">
            <div className="flex flex-col gap-3 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-start gap-2.5">
                <GitBranch className="mt-0.5 h-5 w-5 shrink-0 text-blue-500" />
                <div>
                  <h2 className="text-sm font-semibold">
                    Обход DoH для локальных сетей и VPN
                  </h2>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Запросы к этим доменам направляются напрямую через
                    системный/VPN DNS. Это позволяет внутренним ресурсам
                    компании работать стабильно.
                  </p>
                </div>
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={newExcluded}
                  onChange={(e) => setNewExcluded(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddExcluded()}
                  placeholder="Домен или список через запятую (напр. corp.local, company.ru)"
                  className="flex-1 rounded-lg border border-gray-300 bg-transparent px-3 py-1.5 text-xs focus:border-blue-500 focus:outline-none dark:border-white/15"
                />
                <button
                  type="button"
                  disabled={!newExcluded.trim()}
                  onClick={handleAddExcluded}
                  className="rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600 disabled:opacity-40"
                >
                  Добавить
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-gray-200 bg-white dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-center justify-between border-b border-gray-200 px-4 py-2.5 text-xs font-semibold text-gray-500 dark:border-white/10 dark:text-gray-400">
                <span>Активные исключения ({state.excludedDomains.length})</span>
                {state.excludedDomains.length > 1 && (
                  <button
                    type="button"
                    onClick={() => api.clearExcludedDomains()}
                    className="font-medium text-blue-500 hover:underline"
                  >
                    Очистить все
                  </button>
                )}
              </div>

              {state.excludedDomains.length === 0 ? (
                <div className="flex flex-col items-center gap-2 px-6 py-8 text-center">
                  <ShieldCheck className="h-8 w-8 text-gray-400" />
                  <div className="text-xs font-medium">Список исключений пуст</div>
                  <p className="max-w-sm text-[11px] text-gray-500 dark:text-gray-400">
                    Все запросы шифруются через выбранный DoH-сервер. Добавьте
                    локальные домены, если используете корпоративный VPN.
                  </p>
                </div>
              ) : (
                <div className="divide-y divide-gray-200 dark:divide-white/10">
                  {state.excludedDomains.map((dom) => (
                    <div
                      key={dom}
                      className="flex items-center justify-between px-4 py-2.5"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-medium">
                          {dom}
                        </span>
                        <span className="rounded bg-gray-200/80 px-1.5 py-0.5 font-mono text-[10px] text-gray-600 dark:bg-white/10 dark:text-gray-400">
                          + *.{dom}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => api.removeExcludedDomain(dom)}
                        className="rounded p-1 text-red-500 hover:bg-red-500/10"
                        title="Удалить домен из исключений"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === "general" && (
          <div className="mx-auto flex max-w-xl flex-col gap-4">
            <div className="flex flex-col divide-y divide-gray-200 rounded-xl border border-gray-200 bg-white dark:divide-white/10 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-center justify-between gap-4 px-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">
                    Умный фоллбэк (авто-смена сервера)
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    Автоматически переключаться на самый быстрый рабочий сервер
                    при недоступности или сбое текущего.
                  </div>
                </div>
                <ToggleSwitch
                  checked={state.autoFailoverEnabled}
                  onChange={(v) => api.setAutoFailover(v)}
                />
              </div>

              <div className="flex items-center justify-between gap-4 px-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">
                    Запускать при входе в систему
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    Автоматический запуск AI DNS Switcher свёрнутым в системный
                    трей.
                  </div>
                </div>
                <ToggleSwitch
                  checked={state.autostartEnabled}
                  onChange={(v) => api.setAutostartEnabled(v)}
                />
              </div>

              <div className="flex items-center justify-between gap-4 px-4 py-3">
                <div>
                  <div className="text-[13px] font-medium">
                    Возвращать системный DNS при выходе
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    При закрытии приложения сбрасывать настройки DNS к
                    стандартным (DHCP роутера).
                  </div>
                </div>
                <ToggleSwitch
                  checked={state.resetDnsOnQuit}
                  onChange={(v) => api.setResetDnsOnQuit(v)}
                />
              </div>
            </div>

            <div className="flex flex-col gap-3 rounded-xl border border-gray-200 bg-white p-4 dark:border-white/10 dark:bg-[#1e2128]">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-semibold">AI DNS Switcher</div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    Версия {state.appVersion} • {state.platform} ({state.dnsStack})
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-[11px] text-gray-500 dark:text-gray-400">
                    Прокси 127.0.0.1:53
                  </div>
                  <div className="text-[11px] text-blue-500">
                    {state.activeModeText}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between border-t border-gray-200 pt-3 text-xs dark:border-white/10">
                <span className="text-gray-500 dark:text-gray-400">
                  Репозиторий проекта
                </span>
                <button
                  type="button"
                  onClick={() =>
                    api.openExternalUrl(
                      "https://github.com/devpassru/dns-switcher-desktop"
                    )
                  }
                  className="inline-flex items-center gap-1 text-blue-500 hover:underline"
                >
                  github.com/devpassru/dns-switcher-desktop
                  <ExternalLink className="h-3 w-3" />
                </button>
              </div>

              <div className="flex items-center justify-between border-t border-gray-200 pt-3 text-xs dark:border-white/10">
                <span className="text-gray-500 dark:text-gray-400">
                  Обновления
                </span>
                <div className="flex items-center gap-2">
                  {state.updateStatus.status === "checking" && (
                    <span className="inline-flex items-center gap-1 text-gray-500">
                      <Loader2 className="h-3 w-3 animate-spin" /> Проверка…
                    </span>
                  )}
                  {state.updateStatus.status === "up_to_date" && (
                    <span className="text-emerald-500">Актуальная версия</span>
                  )}
                  {state.updateStatus.status === "available" && (
                    <button
                      type="button"
                      onClick={() =>
                        state.updateStatus.status === "available" &&
                        api.openExternalUrl(state.updateStatus.releaseUrl)
                      }
                      className="rounded bg-blue-500 px-2.5 py-1 text-xs font-medium text-white hover:bg-blue-600"
                    >
                      Скачать v{state.updateStatus.version}
                    </button>
                  )}
                  {state.updateStatus.status === "failed" && (
                    <span className="text-red-500">
                      {state.updateStatus.message}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => api.checkForUpdates()}
                    className="rounded-lg border border-gray-300 px-2.5 py-1 text-xs hover:bg-gray-100 dark:border-white/15 dark:hover:bg-white/5"
                  >
                    Проверить
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
