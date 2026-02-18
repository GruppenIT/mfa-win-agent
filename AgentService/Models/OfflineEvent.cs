using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

/// <summary>
/// A single offline authentication event.
/// </summary>
public class OfflineEvent
{
    [JsonPropertyName("alias")]
    public string Alias { get; set; } = string.Empty;

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; }

    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("ipAddress")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("agentType")]
    public string AgentType { get; set; } = "CP";

    [JsonPropertyName("failReason")]
    public string FailReason { get; set; } = string.Empty;
}

/// <summary>
/// Request body for POST /api/agents/offline-events
/// </summary>
public class OfflineEventsRequest
{
    [JsonPropertyName("events")]
    public OfflineEvent[] Events { get; set; } = Array.Empty<OfflineEvent>();
}

/// <summary>
/// Response from POST /api/agents/offline-events
/// </summary>
public class OfflineEventsResponse
{
    [JsonPropertyName("accepted")]
    public int Accepted { get; set; }

    [JsonPropertyName("rejected")]
    public int Rejected { get; set; }
}
