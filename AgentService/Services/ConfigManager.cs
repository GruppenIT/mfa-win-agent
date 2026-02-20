using System.Text.Json;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Manages local config storage (JSON file) and syncs config values to the
/// Windows Registry so the Credential Provider DLL can read them.
/// </summary>
public sealed class ConfigManager
{
    private readonly ILogger<ConfigManager> _logger;

    // Paths
    private const string DataFolder = @"C:\ProgramData\Gruppen IT\GruppenMFA";
    private const string ConfigFilePath = DataFolder + @"\agent-config.json";
    private const string AgentConfPath = DataFolder + @"\agent.conf";
    private const string LogoFilePath = DataFolder + @"\logo.png";

    // Registry keys — must match what the C++ CP reads from
    private const string CpRegistryPath = @"SOFTWARE\Gruppen IT\GruppenMFA-CP";
    private const string AgentRegistryPath = @"SOFTWARE\Gruppen IT\GruppenMFA-Agent";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private string _currentConfigHash = string.Empty;

    public string CurrentConfigHash => _currentConfigHash;

    public ConfigManager(ILogger<ConfigManager> logger)
    {
        _logger = logger;
        Directory.CreateDirectory(DataFolder);
        Directory.CreateDirectory(Path.Combine(DataFolder, "Logs"));
        LoadConfigHash();
    }

    /// <summary>
    /// Read the server URL from registry.
    /// Checks the Agent registry first, then falls back to CP registry.
    /// </summary>
    public string ReadServerUrl()
    {
        // Try agent registry first
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AgentRegistryPath);
            var val = key?.GetValue("server_url") as string;
            if (!string.IsNullOrWhiteSpace(val))
                return val;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read server URL from agent registry");
        }

        // Fallback to CP registry
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CpRegistryPath);
            var val = key?.GetValue("server_url") as string;
            if (!string.IsNullOrWhiteSpace(val))
                return val;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read server URL from CP registry");
        }

        return string.Empty;
    }

    /// <summary>
    /// Read the API key from the local agent.conf file or registry.
    /// </summary>
    public string ReadApiKey()
    {
        // Try registry first
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AgentRegistryPath);
            var val = key?.GetValue("api_key") as string;
            if (!string.IsNullOrWhiteSpace(val))
                return val;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read API key from registry");
        }

        // Fallback to file
        try
        {
            if (File.Exists(AgentConfPath))
            {
                var lines = File.ReadAllLines(AgentConfPath);
                foreach (var line in lines)
                {
                    if (line.StartsWith("api_key=", StringComparison.OrdinalIgnoreCase))
                        return line["api_key=".Length..].Trim();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read API key from agent.conf");
        }

        return string.Empty;
    }

    /// <summary>
    /// Save the API key to both registry and file.
    /// </summary>
    public void SaveApiKey(string apiKey)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(AgentRegistryPath);
            key.SetValue("api_key", apiKey, RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save API key to registry");
        }

        try
        {
            Directory.CreateDirectory(DataFolder);
            File.WriteAllText(AgentConfPath, $"api_key={apiKey}{Environment.NewLine}");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save API key to agent.conf");
        }
    }

    /// <summary>
    /// Check if offline MFA is enabled, checking config first, then registry.
    /// </summary>
    public bool IsOfflineMfaEnabled()
    {
        // Check local config first
        var config = LoadLocalConfig();
        if (config?.OfflineMfaEnabled == true)
            return true;

        // Fallback: check registry directly (may have been set by MSI installer or manually)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CpRegistryPath);
            var val = key?.GetValue("offline_mfa_enabled");
            if (val is int intVal) return intVal != 0;
            if (val is string strVal) return strVal == "1";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read offline_mfa_enabled from registry");
        }

        return false;
    }

    /// <summary>
    /// Load the current config hash from the persisted state.
    /// </summary>
    private void LoadConfigHash()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AgentRegistryPath);
            _currentConfigHash = key?.GetValue("config_hash") as string ?? string.Empty;
        }
        catch
        {
            _currentConfigHash = string.Empty;
        }
    }

    /// <summary>
    /// Load the current config from the local JSON file. Returns null if no config exists.
    /// </summary>
    public AgentConfig? LoadLocalConfig()
    {
        try
        {
            if (!File.Exists(ConfigFilePath)) return null;
            var json = File.ReadAllText(ConfigFilePath);
            return JsonSerializer.Deserialize<AgentConfig>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load local config from {Path}", ConfigFilePath);
            return null;
        }
    }

    /// <summary>
    /// Apply a new config: persist to JSON, sync to registry, save hash.
    /// </summary>
    public bool ApplyConfig(AgentConfig config, string configHash)
    {
        try
        {
            // 1. Write JSON to disk
            var json = JsonSerializer.Serialize(config, JsonOptions);
            File.WriteAllText(ConfigFilePath, json);
            _logger.LogInformation("Config saved to {Path}", ConfigFilePath);

            // 2. Sync to CP registry
            SyncToRegistry(config);

            // 3. Handle logo
            if (!string.IsNullOrWhiteSpace(config.TotpPromptLogoBase64))
            {
                SaveLogoFile(config.TotpPromptLogoBase64);
            }

            // 4. Persist config hash
            _currentConfigHash = configHash;
            using (var key = Registry.LocalMachine.CreateSubKey(AgentRegistryPath))
            {
                key.SetValue("config_hash", configHash, RegistryValueKind.String);
            }

            _logger.LogInformation("Config applied successfully (hash: {Hash})", configHash);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply config");
            return false;
        }
    }

    /// <summary>
    /// Write the config fields to the CP registry so the DLL can read them.
    /// Only writes fields that have values (absent JSON keys = don't alter current registry).
    /// </summary>
    private void SyncToRegistry(AgentConfig config)
    {
        using var key = Registry.LocalMachine.CreateSubKey(CpRegistryPath);

        // CP connection settings (from server config — spec fields)
        if (config.Hostname != null)
            key.SetValue("hostname", config.Hostname, RegistryValueKind.String);
        if (config.CustomPort.HasValue)
            key.SetValue("custom_port", config.CustomPort.Value, RegistryValueKind.DWord);
        if (config.Path != null)
            key.SetValue("path", config.Path, RegistryValueKind.String);
        if (config.SslIgnoreInvalidCn.HasValue)
            key.SetValue("ssl_ignore_invalid_cn", config.SslIgnoreInvalidCn.Value ? 1 : 0, RegistryValueKind.DWord);
        if (config.DefaultRealm != null)
            key.SetValue("default_realm", config.DefaultRealm, RegistryValueKind.String);
        if (config.OtpText != null)
            key.SetValue("otp_text", config.OtpText, RegistryValueKind.String);
        if (config.HideFullname.HasValue)
            key.SetValue("hide_fullname", config.HideFullname.Value ? 1 : 0, RegistryValueKind.DWord);
        if (config.HideDomainname.HasValue)
            key.SetValue("hide_domainname", config.HideDomainname.Value ? 1 : 0, RegistryValueKind.DWord);
        if (config.TwoStepHideOtp.HasValue)
            key.SetValue("two_step_hide_otp", config.TwoStepHideOtp.Value ? 1 : 0, RegistryValueKind.DWord);
        if (config.ExcludedAccount != null)
            key.SetValue("excluded_account", config.ExcludedAccount, RegistryValueKind.String);
        if (config.ExcludedGroup != null)
            key.SetValue("excluded_group", config.ExcludedGroup, RegistryValueKind.String);

        // Offline settings
        key.SetValue("offline_grace_period", config.OfflineGracePeriod, RegistryValueKind.DWord);
        key.SetValue("offline_threshold", config.OfflineMaxAttempts, RegistryValueKind.DWord);
        key.SetValue("offline_cache_enabled", config.OfflineCacheEnabled ? 1 : 0, RegistryValueKind.DWord);

        // TOTP prompt UI
        key.SetValue("login_text", config.TotpPromptTitle, RegistryValueKind.String);
        key.SetValue("otp_hint_text", config.TotpPromptMessage, RegistryValueKind.String);
        if (File.Exists(LogoFilePath))
            key.SetValue("v1_bitmap_path", LogoFilePath, RegistryValueKind.String);

        // Exceptions (legacy array format)
        if (config.ExceptUsers.Length > 0)
            key.SetValue("excluded_account", string.Join(";", config.ExceptUsers), RegistryValueKind.String);
        if (config.ExceptGroups.Length > 0)
            key.SetValue("excluded_group", string.Join(";", config.ExceptGroups), RegistryValueKind.String);

        // Protection
        key.SetValue("prevent_uninstall", config.PreventUninstall ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("prevent_disable", config.PreventDisable ? 1 : 0, RegistryValueKind.DWord);

        // Scenario enforcement
        key.SetValue("force_on_rdp", config.ForceOnRDP ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("force_on_console", config.ForceOnConsole ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("force_on_unlock", config.ForceOnUnlock ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("force_on_new_session", config.ForceOnNewSession ? 1 : 0, RegistryValueKind.DWord);

        // Debug
        key.SetValue("debug_log", config.DebugLogging ? 1 : 0, RegistryValueKind.DWord);

        // Offline MFA settings (only write when server explicitly provides them)
        if (config.OfflineMfaEnabled.HasValue)
            key.SetValue("offline_mfa_enabled", config.OfflineMfaEnabled.Value ? 1 : 0, RegistryValueKind.DWord);
        if (config.OfflineCacheTtlDays.HasValue)
            key.SetValue("offline_cache_ttl_days", config.OfflineCacheTtlDays.Value, RegistryValueKind.DWord);
        if (config.OfflineMaxCachedUsers.HasValue)
            key.SetValue("offline_max_cached_users", config.OfflineMaxCachedUsers.Value, RegistryValueKind.DWord);
        if (config.OfflineBruteForceLimit.HasValue)
            key.SetValue("offline_brute_force_limit", config.OfflineBruteForceLimit.Value, RegistryValueKind.DWord);
        if (config.OfflineLockoutMinutes.HasValue)
            key.SetValue("offline_lockout_minutes", config.OfflineLockoutMinutes.Value, RegistryValueKind.DWord);
        if (config.OfflineRequireOnlineDays.HasValue)
            key.SetValue("offline_require_online_days", config.OfflineRequireOnlineDays.Value, RegistryValueKind.DWord);
        if (config.OfflineOnTheFlyGraceSeconds.HasValue)
            key.SetValue("offline_on_the_fly_grace_seconds", config.OfflineOnTheFlyGraceSeconds.Value, RegistryValueKind.DWord);

        _logger.LogDebug("Registry synced to {Path}", CpRegistryPath);
    }

    /// <summary>
    /// Decode base64 logo and save as PNG file.
    /// </summary>
    private void SaveLogoFile(string base64)
    {
        try
        {
            // Strip data URI prefix if present
            var data = base64;
            var commaIdx = data.IndexOf(',');
            if (commaIdx >= 0) data = data[(commaIdx + 1)..];

            var bytes = Convert.FromBase64String(data);
            File.WriteAllBytes(LogoFilePath, bytes);
            _logger.LogDebug("Logo saved to {Path} ({Bytes} bytes)", LogoFilePath, bytes.Length);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to save logo file");
        }
    }
}
