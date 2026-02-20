using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

/// <summary>
/// Represents the resolved CP configuration received from the server.
/// All fields are optional — missing fields keep their default values.
/// </summary>
public class AgentConfig
{
    // CP connection settings (written to CP registry)
    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    [JsonPropertyName("custom_port")]
    public int? CustomPort { get; set; }

    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("ssl_ignore_invalid_cn")]
    public bool? SslIgnoreInvalidCn { get; set; }

    [JsonPropertyName("default_realm")]
    public string? DefaultRealm { get; set; }

    [JsonPropertyName("otp_text")]
    public string? OtpText { get; set; }

    [JsonPropertyName("hide_fullname")]
    public bool? HideFullname { get; set; }

    [JsonPropertyName("hide_domainname")]
    public bool? HideDomainname { get; set; }

    [JsonPropertyName("two_step_hide_otp")]
    public bool? TwoStepHideOtp { get; set; }

    [JsonPropertyName("excluded_account")]
    public string? ExcludedAccount { get; set; }

    [JsonPropertyName("excluded_group")]
    public string? ExcludedGroup { get; set; }

    // Offline behavior
    [JsonPropertyName("offlineGracePeriod")]
    public int OfflineGracePeriod { get; set; } = 3600;

    [JsonPropertyName("offlineMaxAttempts")]
    public int OfflineMaxAttempts { get; set; } = 3;

    [JsonPropertyName("offlineCacheEnabled")]
    public bool OfflineCacheEnabled { get; set; } = true;

    // TOTP prompt UI
    [JsonPropertyName("totpPromptTitle")]
    public string TotpPromptTitle { get; set; } = "GruppenMFA Login";

    [JsonPropertyName("totpPromptMessage")]
    public string TotpPromptMessage { get; set; } = "Enter your One-Time Password";

    [JsonPropertyName("totpPromptLogoBase64")]
    public string? TotpPromptLogoBase64 { get; set; }

    // Exceptions (legacy array format)
    [JsonPropertyName("exceptUsers")]
    public string[] ExceptUsers { get; set; } = Array.Empty<string>();

    [JsonPropertyName("exceptGroups")]
    public string[] ExceptGroups { get; set; } = Array.Empty<string>();

    // Protection & enforcement
    [JsonPropertyName("preventUninstall")]
    public bool PreventUninstall { get; set; } = false;

    [JsonPropertyName("preventDisable")]
    public bool PreventDisable { get; set; } = false;

    // Scenario enforcement
    [JsonPropertyName("forceOnRDP")]
    public bool ForceOnRDP { get; set; } = true;

    [JsonPropertyName("forceOnConsole")]
    public bool ForceOnConsole { get; set; } = true;

    [JsonPropertyName("forceOnUnlock")]
    public bool ForceOnUnlock { get; set; } = true;

    [JsonPropertyName("forceOnNewSession")]
    public bool ForceOnNewSession { get; set; } = true;

    // Debug
    [JsonPropertyName("debugLogging")]
    public bool DebugLogging { get; set; } = false;

    [JsonPropertyName("logRetentionDays")]
    public int LogRetentionDays { get; set; } = 7;

    // Offline MFA (from server config — nullable so absent fields don't overwrite local registry)
    [JsonPropertyName("offline_mfa_enabled")]
    public bool? OfflineMfaEnabled { get; set; }

    [JsonPropertyName("offline_cache_ttl_days")]
    public int? OfflineCacheTtlDays { get; set; }

    [JsonPropertyName("offline_max_cached_users")]
    public int? OfflineMaxCachedUsers { get; set; }

    [JsonPropertyName("offline_brute_force_limit")]
    public int? OfflineBruteForceLimit { get; set; }

    [JsonPropertyName("offline_lockout_minutes")]
    public int? OfflineLockoutMinutes { get; set; }

    [JsonPropertyName("offline_require_online_days")]
    public int? OfflineRequireOnlineDays { get; set; }

    [JsonPropertyName("offline_on_the_fly_grace_seconds")]
    public int? OfflineOnTheFlyGraceSeconds { get; set; }
}
