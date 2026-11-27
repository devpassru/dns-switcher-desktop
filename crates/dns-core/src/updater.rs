use crate::models::UpdateStatus;

pub const REPO_OWNER: &str = "devpassru";
pub const REPO_NAME: &str = "dns-switcher-desktop";

/// Compares two semantic version strings (e.g. "v1.7.8" vs "1.7.7").
pub fn is_version_newer(candidate: &str, current: &str) -> bool {
    let parse = |raw: &str| -> Vec<u64> {
        let mut s = raw.trim();
        if let Some(rest) = s.strip_prefix('v').or_else(|| s.strip_prefix('V')) {
            s = rest;
        }
        if let Some(idx) = s.find('-') {
            s = &s[..idx];
        }
        s.split('.')
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };

    let a = parse(candidate);
    let b = parse(current);
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return false;
    }

    for i in 0..max_len {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        if av != bv {
            return av > bv;
        }
    }
    false
}

#[derive(Debug, serde::Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, serde::Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

pub fn select_platform_asset_url<'a>(assets: &'a [(String, String)], target_os: &str) -> Option<&'a str> {
    let priorities: &[&str] = match target_os {
        "windows" => &[".msi", "-setup.exe", ".exe", ".zip"],
        "linux" => &[".appimage", ".deb", ".rpm", ".tar.gz"],
        _ => &[".dmg", ".zip"],
    };

    for ext in priorities {
        if let Some((_, url)) = assets
            .iter()
            .find(|(name, _)| name.to_lowercase().ends_with(ext))
        {
            return Some(url.as_str());
        }
    }
    None
}

pub async fn check_for_updates(current_version: &str) -> UpdateStatus {
    let url = format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return UpdateStatus::Failed {
                message: format!("Ошибка HTTP-клиента: {e}"),
            }
        }
    };

    let resp = match client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("DNSSwitcherDesktop/{current_version}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return UpdateStatus::Failed {
                message: "Не удалось проверить обновления".to_string(),
            }
        }
    };

    if !resp.status().is_success() {
        return UpdateStatus::Failed {
            message: format!("GitHub API вернул статус {}", resp.status().as_u16()),
        };
    }

    let Ok(release) = resp.json::<GitHubRelease>().await else {
        return UpdateStatus::Failed {
            message: "Некорректный ответ GitHub API".to_string(),
        };
    };

    if !is_version_newer(&release.tag_name, current_version) {
        return UpdateStatus::UpToDate;
    }

    let pairs: Vec<(String, String)> = release
        .assets
        .iter()
        .map(|a| (a.name.clone(), a.browser_download_url.clone()))
        .collect();
    let download_url = select_platform_asset_url(&pairs, std::env::consts::OS)
        .unwrap_or(release.html_url.as_str())
        .to_string();

    let clean_version = release
        .tag_name
        .trim_start_matches(['v', 'V'])
        .to_string();

    UpdateStatus::Available {
        version: clean_version,
        tag_name: release.tag_name,
        release_url: release.html_url,
        download_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_compare() {
        assert!(is_version_newer("v1.7.8", "1.7.7"));
        assert!(is_version_newer("1.10.0", "1.9.0"));
        assert!(is_version_newer("2.0.0", "1.9.9"));
        assert!(!is_version_newer("v1.7.7", "1.7.7"));
        assert!(!is_version_newer("1.7.6", "1.7.7"));
    }

    #[test]
    fn test_platform_asset_selection() {
        let assets = vec![
            ("AI-DNS-Switcher_1.0.0_x64_en-US.msi".to_string(), "https://example.com/win.msi".to_string()),
            ("AI-DNS-Switcher_1.0.0_amd64.AppImage".to_string(), "https://example.com/linux.AppImage".to_string()),
            ("AI-DNS-Switcher_1.0.0_amd64.deb".to_string(), "https://example.com/linux.deb".to_string()),
        ];
        assert_eq!(select_platform_asset_url(&assets, "windows"), Some("https://example.com/win.msi"));
        assert_eq!(select_platform_asset_url(&assets, "linux"), Some("https://example.com/linux.AppImage"));
    }
}
