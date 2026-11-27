# AI DNS Switcher (Windows & Linux)

Кроссплатформенное десктопное приложение на **Tauri 2 (Rust + React + TypeScript + Tailwind CSS)** для избирательного переключения DNS (Split-DNS через локальный DoH-прокси + системный DNS) для AI-сервисов и выбранных доменов — порт [DNSSwitcher (macOS)](../DNSSwitcher).

## Архитектура

Проект представляет собой единый Cargo workspace:

- **`crates/dns-core`** — общее Rust-ядро без GUI-зависимостей:
  - DNS wire-format парсер/сборщик (`dns_packet.rs`)
  - Локальный DoH-прокси (`127.0.0.1:53535`) с RFC 8484 GET/POST, собственным bootstrap-резолвером (исключает DNS-петли при системном `127.0.0.1`), singleflight-дедупликацией, TTL + Serve-Stale кэшем (RFC 8767), исключениями доменов и глубокой проверкой здоровья (`chatgpt.com` + TCP:443)
  - Типизированный локальный IPC (`127.0.0.1:53536`) и перехватчик порта 53 (`127.0.0.1:53`, UDP + TCP)
  - Платформенные бэкенды (`platform/windows.rs`, `platform/linux.rs`, `platform/mock.rs`)
- **`crates/dns-bridge`** — лёгкий фоновый сервис (`dns-switcher-bridge`), работающий с правами системы:
  - **Windows**: регистрируется один раз как Windows Service (`DNSSwitcherBridge`) через UAC. Использует PowerShell/CIM (`Get-NetAdapter`, `Set-DnsClientServerAddress`, `Clear-DnsClientCache`) со скрытым окном и автоопределением DHCP/VPN-адаптеров.
  - **Linux**: регистрируется один раз как systemd-сервис (`dnsswitcher-bridge.service`) через `pkexec`. Автоматически определяет стек сети (`systemd-resolved` / `resolvectl` → `NetworkManager` / `nmcli` → `/etc/resolv.conf`).
- **`src-tauri` + `src/`** — приложение в системном трее с тремя окнами: быстрый Control Center, Настройки (4 вкладки) и История DNS-запросов.

## Разработка и тестирование

```bash
# Установка JS-зависимостей
pnpm install

# Прогон всех Rust юнит-тестов (ядро, парсеры Windows/Linux, bridge UDP/TCP, IPC)
cargo test --workspace

# Сборка sidecar-моста и проверка фронтенда
pnpm run build:bridge
pnpm run build

# Запуск в режиме разработки (на macOS использует MockDnsBackend для превью UI)
pnpm tauri dev
```

## Сборка установщиков

Релизные пакеты для Windows (`.msi`, `.exe`) и Linux (`.deb`, `.AppImage`, `.rpm`) автоматически собираются в [`.github/workflows/build.yml`](.github/workflows/build.yml) при пуше в `main`/`master` или создании тега `v*`.
