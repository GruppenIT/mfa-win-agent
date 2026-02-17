using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

/// <summary>
/// Represents the resolved CP configuration received from the server.
/// All fields are optional — missing fields keep their default values.
/// </summary>
public class AgentConfig
{
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

    // Exceptions
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
}
