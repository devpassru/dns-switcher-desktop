import { useEffect, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { api } from "./api/tauri";
import { HistoryView } from "./components/HistoryView";
import { PopoverView } from "./components/PopoverView";
import { SettingsView } from "./components/SettingsView";
import type { AppStateSnapshot } from "./types/dns";

function detectView(): "main" | "settings" | "history" {
  const params = new URLSearchParams(window.location.search);
  const q = params.get("view");
  if (q === "settings" || q === "history" || q === "main") {
    return q;
  }
  try {
    const label = getCurrentWebviewWindow().label;
    if (label === "settings" || label === "history") {
      return label;
    }
  } catch {
    // fallback for browser preview
  }
  return "main";
}

export function App() {
  const [view] = useState<"main" | "settings" | "history">(detectView);
  const [state, setState] = useState<AppStateSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api
      .getAppState()
      .then((snap) => {
        if (active) setState(snap);
      })
      .catch((err) => {
        if (active) setError(String(err));
      });

    const unlistenPromise = api.onStateChanged((snap) => {
      if (active) setState(snap);
    });

    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "q") {
        e.preventDefault();
        api.quitApp();
      } else if ((e.ctrlKey || e.metaKey) && e.key === ",") {
        e.preventDefault();
        api.openWindow("settings");
      }
    };
    window.addEventListener("keydown", onKeyDown);

    return () => {
      active = false;
      window.removeEventListener("keydown", onKeyDown);
      unlistenPromise.then((fn) => fn());
    };
  }, []);

  if (view === "history") {
    return <HistoryView />;
  }

  if (error) {
    return (
      <div className="flex h-screen items-center justify-center p-4 text-xs text-red-500">
        Ошибка инициализации: {error}
      </div>
    );
  }

  if (!state) {
    return (
      <div className="flex h-screen items-center justify-center text-xs text-gray-500">
        Загрузка AI DNS Switcher…
      </div>
    );
  }

  if (view === "settings") {
    return <SettingsView state={state} />;
  }

  return <PopoverView state={state} />;
}

export default App;
