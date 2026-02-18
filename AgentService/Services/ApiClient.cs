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

    // Retry configuration: 2s, 4s, 8s, 16s, then give up
    private static readonly int[] RetryDelaysMs = { 2000, 4000, 8000, 16000 };
    private const int MaxRetries = 4;

    public ApiClient(string baseUrl, string apiKey, ILogger<ApiClient> logger)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _logger = logger;

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = null
        };

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };
        _http.DefaultRequestHeaders.Add("X-API-Key", _apiKey);
        var version = typeof(ApiClient).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        var hostname = Environment.MachineName.ToUpperInvariant();
        var userAgent = $"gruppen-mfa-cp/{version} Windows/{hostname}";
        _http.DefaultRequestHeaders.Add("User-Agent", userAgent);

        _logger.LogInformation("ApiClient initialized — baseUrl={BaseUrl}, userAgent={UA}, apiKeyLength={Len}",
            _baseUrl, userAgent, _apiKey.Length);
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

    /// <summary>
    /// GET /api/agents/offline-cache?hostname=X — fetch offline TOTP secrets + mobility policies.
    /// </summary>
    public async Task<OfflineCacheResponse?> GetOfflineCacheAsync(string hostname, CancellationToken ct = default)
    {
        var url = $"/api/agents/offline-cache?hostname={Uri.EscapeDataString(hostname)}";
        return await GetWithRetryAsync<OfflineCacheResponse>(url, ct);
    }

    /// <summary>
    /// POST /api/agents/offline-events — sync offline auth events to server.
    /// </summary>
    public async Task<OfflineEventsResponse?> PostOfflineEventsAsync(OfflineEventsRequest request, CancellationToken ct = default)
    {
        return await PostWithRetryAsync<OfflineEventsRequest, OfflineEventsResponse>(
            "/api/agents/offline-events", request, ct);
    }

    /// <summary>
    /// POST /api/agents/mobility-check — check if a session is allowed by mobility policies.
    /// </summary>
    public async Task<MobilityCheckResponse?> MobilityCheckAsync(MobilityCheckRequest request, CancellationToken ct = default)
    {
        return await PostWithRetryAsync<MobilityCheckRequest, MobilityCheckResponse>(
            "/api/agents/mobility-check", request, ct);
    }

    private async Task<TResponse?> PostWithRetryAsync<TRequest, TResponse>(
        string path, TRequest body, CancellationToken ct) where TResponse : class
    {
        var fullUrl = _baseUrl + path;
        var jsonBody = JsonSerializer.Serialize(body, JsonOptions);
        _logger.LogInformation("  >> POST {Url}", fullUrl);
        _logger.LogInformation("  >> Body: {Body}", Truncate(jsonBody, 500));

        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                using var response = await _http.PostAsync(path, content, ct);

                var responseText = await response.Content.ReadAsStringAsync(ct);
                _logger.LogInformation("  << {StatusCode} {Reason} ({Bytes} bytes)",
                    (int)response.StatusCode, response.ReasonPhrase, responseText.Length);

                if (responseText.Length > 0)
                    _logger.LogInformation("  << Body: {Body}", Truncate(responseText, 1000));

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("  << POST {Path} returned HTTP {StatusCode}", path, (int)response.StatusCode);
                    return null;
                }

                if (typeof(TResponse) == typeof(object))
                    return (TResponse)(object)new object(); // For ack, we just need success

                return JsonSerializer.Deserialize<TResponse>(responseText, JsonOptions);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (ct.IsCancellationRequested) return null;

                var delay = attempt < RetryDelaysMs.Length
                    ? RetryDelaysMs[attempt]
                    : RetryDelaysMs[^1];

                _logger.LogWarning("  << POST {Url} FAILED (attempt {Attempt}/{Max}): {Error}. Retrying in {Delay}ms...",
                    fullUrl, attempt + 1, MaxRetries, ex.Message, delay);

                try { await Task.Delay(delay, ct); }
                catch (OperationCanceledException) { return null; }
            }
        }

        _logger.LogError("  << POST {Url} FAILED after {Max} attempts — giving up", fullUrl, MaxRetries);
        return null;
    }

    private async Task<TResponse?> GetWithRetryAsync<TResponse>(string path, CancellationToken ct) where TResponse : class
    {
        var fullUrl = _baseUrl + path;
        _logger.LogInformation("  >> GET {Url}", fullUrl);

        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                using var response = await _http.GetAsync(path, ct);

                var responseText = await response.Content.ReadAsStringAsync(ct);
                _logger.LogInformation("  << {StatusCode} {Reason} ({Bytes} bytes)",
                    (int)response.StatusCode, response.ReasonPhrase, responseText.Length);

                if (responseText.Length > 0)
                    _logger.LogInformation("  << Body: {Body}", Truncate(responseText, 1000));

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("  << GET {Path} returned HTTP {StatusCode}", path, (int)response.StatusCode);
                    return null;
                }

                return JsonSerializer.Deserialize<TResponse>(responseText, JsonOptions);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                if (ct.IsCancellationRequested) return null;

                var delay = attempt < RetryDelaysMs.Length
                    ? RetryDelaysMs[attempt]
                    : RetryDelaysMs[^1];

                _logger.LogWarning("  << GET {Url} FAILED (attempt {Attempt}/{Max}): {Error}. Retrying in {Delay}ms...",
                    fullUrl, attempt + 1, MaxRetries, ex.Message, delay);

                try { await Task.Delay(delay, ct); }
                catch (OperationCanceledException) { return null; }
            }
        }

        _logger.LogError("  << GET {Url} FAILED after {Max} attempts — giving up", fullUrl, MaxRetries);
        return null;
    }

    private static string Truncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..maxLen] + "...(truncated)";

    public void Dispose() => _http.Dispose();
}
