using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// HTTP client for communicating with the MFA Gruppen backend.
/// All endpoints authenticate via X-API-Key header.
/// </summary>
public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly ILogger<ApiClient> _logger;
    private readonly string _apiKey;
    private readonly string _baseUrl;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    // Retry configuration: 2s, 4s, 8s, 16s, then cap at 5min
    private static readonly int[] RetryDelaysMs = { 2000, 4000, 8000, 16000 };
    private const int MaxRetryDelayMs = 300_000; // 5 minutes

    public ApiClient(string baseUrl, string apiKey, ILogger<ApiClient> logger)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _logger = logger;

        var handler = new HttpClientHandler
        {
            // The server uses a valid Let's Encrypt cert
            ServerCertificateCustomValidationCallback = null
        };

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };
        _http.DefaultRequestHeaders.Add("X-API-Key", _apiKey);
        _http.DefaultRequestHeaders.Add("User-Agent", "gruppen-mfa-agent/1.0.0");
    }

    /// <summary>
    /// POST /api/agents/checkin — periodic agent heartbeat.
    /// </summary>
    public async Task<CheckinResponse?> CheckinAsync(CheckinRequest request, CancellationToken ct = default)
    {
        return await PostWithRetryAsync<CheckinRequest, CheckinResponse>(
            "/api/agents/checkin", request, ct);
    }

    /// <summary>
    /// GET /api/agents/config?hostname=X&agentType=CP — fetch resolved config.
    /// </summary>
    public async Task<ConfigResponse?> GetConfigAsync(string hostname, CancellationToken ct = default)
    {
        var url = $"/api/agents/config?hostname={Uri.EscapeDataString(hostname)}&agentType=CP";
        return await GetWithRetryAsync<ConfigResponse>(url, ct);
    }

    /// <summary>
    /// POST /api/agents/config/ack — confirm config was applied.
    /// </summary>
    public async Task<bool> AckConfigAsync(ConfigAckRequest request, CancellationToken ct = default)
    {
        var result = await PostWithRetryAsync<ConfigAckRequest, object>(
            "/api/agents/config/ack", request, ct);
        return result != null;
    }

    private async Task<TResponse?> PostWithRetryAsync<TRequest, TResponse>(
        string path, TRequest body, CancellationToken ct) where TResponse : class
    {
        var jsonBody = JsonSerializer.Serialize(body, JsonOptions);

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(path, content, ct);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync(ct);
                    _logger.LogWarning("POST {Path} returned {StatusCode}: {Body}",
                        path, (int)response.StatusCode, errorBody.Length > 500 ? errorBody[..500] : errorBody);
                    return null;
                }

                var responseText = await response.Content.ReadAsStringAsync(ct);
                if (typeof(TResponse) == typeof(object))
                    return (TResponse)(object)new object(); // For ack, we just need success

                return JsonSerializer.Deserialize<TResponse>(responseText, JsonOptions);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (ct.IsCancellationRequested) return null;

                var delay = attempt < RetryDelaysMs.Length
                    ? RetryDelaysMs[attempt]
                    : MaxRetryDelayMs;

                _logger.LogWarning(ex, "POST {Path} failed (attempt {Attempt}), retrying in {Delay}ms",
                    path, attempt + 1, delay);

                try { await Task.Delay(delay, ct); }
                catch (OperationCanceledException) { return null; }
            }
        }
    }

    private async Task<TResponse?> GetWithRetryAsync<TResponse>(string path, CancellationToken ct) where TResponse : class
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using var response = await _http.GetAsync(path, ct);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync(ct);
                    _logger.LogWarning("GET {Path} returned {StatusCode}: {Body}",
                        path, (int)response.StatusCode, errorBody.Length > 500 ? errorBody[..500] : errorBody);
                    return null;
                }

                var responseText = await response.Content.ReadAsStringAsync(ct);
                return JsonSerializer.Deserialize<TResponse>(responseText, JsonOptions);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (ct.IsCancellationRequested) return null;

                var delay = attempt < RetryDelaysMs.Length
                    ? RetryDelaysMs[attempt]
                    : MaxRetryDelayMs;

                _logger.LogWarning(ex, "GET {Path} failed (attempt {Attempt}), retrying in {Delay}ms",
                    path, attempt + 1, delay);

                try { await Task.Delay(delay, ct); }
                catch (OperationCanceledException) { return null; }
            }
        }
    }

    public void Dispose() => _http.Dispose();
}
