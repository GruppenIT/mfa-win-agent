using System.Text.Json.Serialization;

namespace GruppenMFA.AgentService.Models;

public class CheckinResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("configHash")]
    public string ConfigHash { get; set; } = string.Empty;
}
