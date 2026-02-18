using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

/// <summary>
/// Request body for POST /api/agents/mobility-check
/// </summary>
public class MobilityCheckRequest
{
    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    [JsonPropertyName("endpointHostname")]
    public string EndpointHostname { get; set; } = string.Empty;

    [JsonPropertyName("clientIp")]
    public string ClientIp { get; set; } = string.Empty;
}

/// <summary>
/// Response from POST /api/agents/mobility-check
/// </summary>
public class MobilityCheckResponse
{
    [JsonPropertyName("allowed")]
    public bool Allowed { get; set; }

    [JsonPropertyName("policyName")]
    public string? PolicyName { get; set; }

    [JsonPropertyName("policyNumber")]
    public int? PolicyNumber { get; set; }

    [JsonPropertyName("action")]
    public string? Action { get; set; }

    [JsonPropertyName("graceSeconds")]
    public int? GraceSeconds { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}
