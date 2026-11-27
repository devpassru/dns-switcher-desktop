import { useEffect, useMemo, useState } from "react";
import { Clock, Copy, Search, Trash2, X } from "lucide-react";
import { api } from "../api/tauri";
import type { DNSResolutionRecord, ResolutionSource } from "../types/dns";

type FilterId =
  | "all"
  | "doh"
  | "cache"
  | "stale_cache"
  | "excluded"
  | "fallback"
  | "error";

const FILTERS: { id: FilterId; label: string }[] = [
  { id: "all", label: "Все" },
  { id: "doh", label: "DoH" },
  { id: "cache", label: "Кэш" },
  { id: "stale_cache", label: "Stale-кэш" },
  { id: "excluded", label: "Исключения" },
  { id: "fallback", label: "Фоллбэк" },
  { id: "error", label: "Ошибки" },
];

function formatTime(tsMs: number): string {
  const d = new Date(tsMs);
  return d.toLocaleTimeString("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function SourceBadge({ source }: { source: ResolutionSource }) {
  const map: Record<ResolutionSource, { label: string; cls: string }> = {
    doh: {
      label: "DoH",
      cls: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
    },
    cache: {
      label: "Кэш",
      cls: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
    },
    stale_cache: {
      label: "Stale-кэш",
      cls: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
    },
    excluded: {
      label: "Исключение",
      cls: "bg-purple-500/15 text-purple-600 dark:text-purple-400",
    },
    fallback: {
      label: "Фоллбэк",
      cls: "bg-yellow-500/20 text-amber-700 dark:text-amber-300",
    },
    error: {
      label: "Ошибка",
      cls: "bg-red-500/15 text-red-600 dark:text-red-400",
    },
  };
  const item = map[source];
  return (
    <span
      className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold ${item.cls}`}
    >
      {item.label}
    </span>
  );
}

export function HistoryView() {
  const [records, setRecords] = useState<DNSResolutionRecord[]>([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<FilterId>("all");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const list = await api.getHistory();
        if (active) setRecords(list);
      } catch {
        // ignore
      }
    };
    load();
    const unlistenPromise = api.onHistoryUpdated(() => {
      load();
    });
    const timer = window.setInterval(load, 2000);
    return () => {
      active = false;
      window.clearInterval(timer);
      unlistenPromise.then((fn) => fn());
    };
  }, []);

  const stats = useMemo(() => {
    let doh = 0;
    let cache = 0;
    let stale = 0;
    let failed = 0;
    for (const r of records) {
      if (r.source === "doh") doh++;
      else if (r.source === "cache") cache++;
      else if (r.source === "stale_cache") stale++;
      else if (r.source === "error" || !r.isSuccess) failed++;
    }
    return { doh, cache, stale, failed };
  }, [records]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return records.filter((r) => {
      if (filter !== "all") {
        if (filter === "error") {
          if (r.source !== "error" && r.isSuccess) return false;
        } else if (r.source !== filter) {
          return false;
        }
      }
      if (q) {
        return (
          r.domain.toLowerCase().includes(q) ||
          r.serverName.toLowerCase().includes(q) ||
          r.resolvedIps.some((ip) => ip.includes(q))
        );
      }
      return true;
    });
  }, [records, filter, search]);

  const copyToClipboard = async () => {
    const lines = records.map((r) => {
      const ips = r.resolvedIps.length
        ? r.resolvedIps.join(", ")
        : r.serverName;
      return `${formatTime(r.timestampMs)}\t${r.source}\t${r.qtype}\t${r.domain}\t${ips}\t${r.latencyMs}ms`;
    });
    await navigator.clipboard.writeText(lines.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex h-screen flex-col bg-[#f4f5f7] text-gray-900 dark:bg-[#16181d] dark:text-gray-100">
      {/* Top Toolbar */}
      <div className="flex flex-col gap-2.5 border-b border-gray-200 bg-white px-4 py-3 dark:border-white/10 dark:bg-[#1c1f26]">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h1 className="text-sm font-semibold">История DNS-запросов</h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Мониторинг всех резолвов в реальном времени с поддержкой
              Serve-Stale кэша
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={records.length === 0}
              onClick={copyToClipboard}
              className="inline-flex items-center gap-1 rounded-lg border border-gray-300 px-2.5 py-1 text-xs hover:bg-gray-100 disabled:opacity-40 dark:border-white/15 dark:hover:bg-white/5"
            >
              <Copy className="h-3.5 w-3.5" />
              {copied ? "Скопировано" : "Копировать"}
            </button>
            <button
              type="button"
              disabled={records.length === 0}
              onClick={async () => {
                await api.clearHistory();
                setRecords([]);
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-red-300 px-2.5 py-1 text-xs text-red-600 hover:bg-red-500/10 disabled:opacity-40 dark:border-red-500/30 dark:text-red-400"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Очистить
            </button>
          </div>
        </div>

        {/* Stat Pills */}
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
            <span className="h-1.5 w-1.5 rounded-full bg-gray-500" />
            Всего <b>{records.length}</b>
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            DoH <b>{stats.doh}</b>
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
            Кэш <b>{stats.cache}</b>
          </span>
          {stats.stale > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
              Stale-кэш <b>{stats.stale}</b>
            </span>
          )}
          {stats.failed > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 bg-gray-50 px-2 py-0.5 dark:border-white/10 dark:bg-white/5">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              Ошибки <b>{stats.failed}</b>
            </span>
          )}
        </div>

        {/* Search & Filters */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2 rounded-lg bg-gray-100 px-2.5 py-1.5 dark:bg-black/30">
            <Search className="h-3.5 w-3.5 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Фильтр по домену, IP или серверу…"
              className="flex-1 bg-transparent text-xs focus:outline-none"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map((f) => {
              const active = filter === f.id;
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFilter(f.id)}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    active
                      ? "bg-blue-500 text-white"
                      : "bg-gray-200/70 text-gray-700 hover:bg-gray-200 dark:bg-white/8 dark:text-gray-300 dark:hover:bg-white/15"
                  }`}
                >
                  {f.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
            <Clock className="h-9 w-9 text-gray-400" />
            <div className="text-sm font-medium">
              {records.length === 0
                ? "История запросов пока пуста"
                : "По заданному фильтру ничего не найдено"}
            </div>
            {records.length === 0 && (
              <div className="text-xs text-gray-500 dark:text-gray-400">
                Запросы, отправленные через 127.0.0.1:53, будут отображаться
                здесь
              </div>
            )}
          </div>
        ) : (
          <div className="divide-y divide-gray-200/70 dark:divide-white/5">
            {filtered.map((r, idx) => (
              <div
                key={r.id}
                className={`flex items-center gap-2 px-4 py-1.5 text-xs ${
                  idx % 2 === 1 ? "bg-black/[0.02] dark:bg-white/[0.02]" : ""
                }`}
              >
                <span className="w-16 shrink-0 font-mono text-[11px] text-gray-500 dark:text-gray-400">
                  {formatTime(r.timestampMs)}
                </span>
                <span className="w-22 shrink-0">
                  <SourceBadge source={r.source} />
                </span>
                <span className="w-12 shrink-0 rounded bg-gray-200/70 px-1 py-0.5 text-center font-mono text-[10px] font-bold dark:bg-white/10">
                  {r.qtype}
                </span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs font-medium">
                  {r.domain}
                </span>
                <span className="max-w-[200px] truncate font-mono text-[11px] text-gray-500 dark:text-gray-400">
                  {r.resolvedIps.length > 0
                    ? r.resolvedIps.join(", ")
                    : r.serverName}
                </span>
                <span
                  className={`w-14 shrink-0 text-right font-mono text-[11px] font-medium ${
                    r.isSuccess
                      ? "text-gray-500 dark:text-gray-400"
                      : "text-red-500"
                  }`}
                >
                  {r.source === "cache" ? "<1 мс" : `${r.latencyMs} мс`}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
