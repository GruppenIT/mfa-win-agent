using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

/// <summary>
/// Response from GET /api/agents/offline-cache?hostname=HOSTNAME
/// </summary>
public class OfflineCacheResponse
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("settings")]
    public OfflineCacheSettings? Settings { get; set; }

    [JsonPropertyName("users")]
    public OfflineCachedUser[] Users { get; set; } = Array.Empty<OfflineCachedUser>();

    [JsonPropertyName("mobilityPolicies")]
    public MobilityPolicy[] MobilityPolicies { get; set; } = Array.Empty<MobilityPolicy>();

    [JsonPropertyName("generatedAt")]
    public DateTime GeneratedAt { get; set; }
}

public class OfflineCacheSettings
{
    [JsonPropertyName("cacheTtlDays")]
    public int CacheTtlDays { get; set; } = 7;

    [JsonPropertyName("maxCachedUsers")]
    public int MaxCachedUsers { get; set; } = 200;

    [JsonPropertyName("bruteForceLimitOffline")]
    public int BruteForceLimitOffline { get; set; } = 3;

    [JsonPropertyName("lockoutMinutesOffline")]
    public int LockoutMinutesOffline { get; set; } = 30;

    [JsonPropertyName("requireOnlineEveryDays")]
    public int RequireOnlineEveryDays { get; set; } = 30;

    [JsonPropertyName("onTheFlyGraceSeconds")]
    public int OnTheFlyGraceSeconds { get; set; } = 60;

    [JsonPropertyName("totpPeriod")]
    public int TotpPeriod { get; set; } = 30;

    [JsonPropertyName("totpDigits")]
    public int TotpDigits { get; set; } = 6;

    [JsonPropertyName("totpAlgorithm")]
    public string TotpAlgorithm { get; set; } = "SHA1";
}

public class OfflineCachedUser
{
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    [JsonPropertyName("accountName")]
    public string AccountName { get; set; } = string.Empty;

    [JsonPropertyName("aliases")]
    public string[] Aliases { get; set; } = Array.Empty<string>();

    [JsonPropertyName("totpSecret")]
    public string TotpSecret { get; set; } = string.Empty;

    [JsonPropertyName("tagIds")]
    public string[] TagIds { get; set; } = Array.Empty<string>();
}

public class MobilityPolicy
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("policyNumber")]
    public int PolicyNumber { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty; // "USER" or "ENDPOINT"

    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty; // "ALLOW" or "DENY"

    [JsonPropertyName("priority")]
    public int Priority { get; set; }

    [JsonPropertyName("enforceOnTheFly")]
    public bool EnforceOnTheFly { get; set; }

    [JsonPropertyName("startDate")]
    public string? StartDate { get; set; }

    [JsonPropertyName("endDate")]
    public string? EndDate { get; set; }

    [JsonPropertyName("daysOfWeek")]
    public int[] DaysOfWeek { get; set; } = Array.Empty<int>();

    [JsonPropertyName("timeStart")]
    public string? TimeStart { get; set; }

    [JsonPropertyName("timeEnd")]
    public string? TimeEnd { get; set; }

    [JsonPropertyName("cidrs")]
    public string[] Cidrs { get; set; } = Array.Empty<string>();

    [JsonPropertyName("userIds")]
    public string[] UserIds { get; set; } = Array.Empty<string>();

    [JsonPropertyName("userTagIds")]
    public string[] UserTagIds { get; set; } = Array.Empty<string>();

    [JsonPropertyName("endpointHostnames")]
    public string[] EndpointHostnames { get; set; } = Array.Empty<string>();

    [JsonPropertyName("endpointTagIds")]
    public string[] EndpointTagIds { get; set; } = Array.Empty<string>();
}
