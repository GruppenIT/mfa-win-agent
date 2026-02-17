using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

public class ConfigResponse
{
    [JsonPropertyName("config")]
    public AgentConfig Config { get; set; } = new();

    [JsonPropertyName("configHash")]
    public string ConfigHash { get; set; } = string.Empty;

    [JsonPropertyName("appliedPolicies")]
    public AppliedPolicy[] AppliedPolicies { get; set; } = Array.Empty<AppliedPolicy>();
}

public class AppliedPolicy
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("isDefault")]
    public bool IsDefault { get; set; }
}
