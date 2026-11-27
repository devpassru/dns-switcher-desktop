import { Loader2 } from "lucide-react";
import type { ProviderHealth } from "../types/dns";

export function HealthBadge({
  health,
  compact = true,
}: {
  health?: ProviderHealth;
  compact?: boolean;
}) {
  if (!health || health.status === "unknown") {
    return null;
  }

  if (health.status === "checking") {
    return <Loader2 className="h-3.5 w-3.5 animate-spin text-gray-400" />;
  }

  if (health.status === "healthy") {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span className="font-mono text-[11px] text-gray-500 dark:text-gray-400">
          {health.latencyMs} мс
        </span>
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
      </span>
    );
  }

  if (health.status === "degraded") {
    return (
      <span className="inline-flex items-center gap-1.5" title={health.reason}>
        <span className="font-mono text-[11px] text-gray-500 dark:text-gray-400">
          {health.latencyMs} мс
        </span>
        <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5" title={health.reason}>
      <span className="text-[10px] text-red-500 dark:text-red-400">
        {compact ? "недоступен" : "сбой"}
      </span>
      <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
    </span>
  );
}
