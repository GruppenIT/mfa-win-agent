using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

public class CheckinRequest
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("agentType")]
    public string AgentType { get; set; } = "CP";

    [JsonPropertyName("osVersion")]
    public string OsVersion { get; set; } = string.Empty;

    [JsonPropertyName("agentVersion")]
    public string AgentVersion { get; set; } = string.Empty;
}
