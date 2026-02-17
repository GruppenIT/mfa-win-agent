using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

public class ConfigAckRequest
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("agentType")]
    public string AgentType { get; set; } = "CP";

    [JsonPropertyName("configHash")]
    public string ConfigHash { get; set; } = string.Empty;
}
