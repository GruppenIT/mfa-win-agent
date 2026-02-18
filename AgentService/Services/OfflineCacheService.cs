using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Manages the offline TOTP cache: fetches from server, encrypts via DPAPI (LocalMachine),
/// and stores to disk so the C++ Credential Provider can read it for offline validation.
/// </summary>
public sealed class OfflineCacheService
{
    private readonly ILogger<OfflineCacheService> _logger;

    private const string CacheDir = @"C:\ProgramData\Gruppen IT\GruppenMFA\cache";
    private const string CacheFilePath = CacheDir + @"\offline_cache.dat";
    private const string LastOnlineAuthPath = CacheDir + @"\last_online_auth.txt";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    private OfflineCacheResponse? _currentCache;
    private readonly object _lock = new();

    public OfflineCacheResponse? CurrentCache
    {
        get { lock (_lock) return _currentCache; }
    }

    public OfflineCacheService(ILogger<OfflineCacheService> logger)
    {
        _logger = logger;
        Directory.CreateDirectory(CacheDir);
        LoadFromDisk();
    }

    /// <summary>
    /// Fetch offline cache from the server and persist to disk (DPAPI encrypted).
    /// </summary>
    public async Task FetchAndStoreAsync(ApiClient apiClient, string hostname, CancellationToken ct)
    {
        _logger.LogInformation("[OfflineCache] Fetching offline cache from server...");

        var response = await apiClient.GetOfflineCacheAsync(hostname, ct);
        if (response == null)
        {
            _logger.LogWarning("[OfflineCache] Failed to fetch offline cache from server");
            return;
        }

        if (!response.Enabled)
        {
            _logger.LogInformation("[OfflineCache] Offline MFA is disabled for this tenant");
            // Clear existing cache if disabled
            lock (_lock) _currentCache = null;
            TryDeleteFile(CacheFilePath);
            return;
        }

        _logger.LogInformation("[OfflineCache] Received cache: {UserCount} users, {PolicyCount} mobility policies, generatedAt={GeneratedAt}",
            response.Users.Length, response.MobilityPolicies.Length, response.GeneratedAt);

        SaveToDisk(response);

        lock (_lock)
        {
            _currentCache = response;
        }

        _logger.LogInformation("[OfflineCache] Cache saved and loaded successfully");
    }

    /// <summary>
    /// Record that an online authentication succeeded (for requireOnlineEveryDays tracking).
    /// </summary>
    public void RecordOnlineAuth()
    {
        try
        {
            File.WriteAllText(LastOnlineAuthPath, DateTime.UtcNow.ToString("o"));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OfflineCache] Failed to record last online auth time");
        }
    }

    /// <summary>
    /// Get the last online authentication timestamp.
    /// </summary>
    public DateTime? GetLastOnlineAuthTime()
    {
        try
        {
            if (!File.Exists(LastOnlineAuthPath)) return null;
            var text = File.ReadAllText(LastOnlineAuthPath).Trim();
            if (DateTime.TryParse(text, out var dt)) return dt;
        }
        catch { }
        return null;
    }

    private void SaveToDisk(OfflineCacheResponse cache)
    {
        try
        {
            var json = JsonSerializer.Serialize(cache, JsonOptions);
            var plainBytes = Encoding.UTF8.GetBytes(json);
            var encryptedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(CacheFilePath, encryptedBytes);
            _logger.LogDebug("[OfflineCache] Encrypted cache written to {Path} ({Bytes} bytes)",
                CacheFilePath, encryptedBytes.Length);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[OfflineCache] Failed to save cache to disk");
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            if (!File.Exists(CacheFilePath))
            {
                _logger.LogDebug("[OfflineCache] No cache file found at {Path}", CacheFilePath);
                return;
            }

            var encryptedBytes = File.ReadAllBytes(CacheFilePath);
            var plainBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine);
            var json = Encoding.UTF8.GetString(plainBytes);
            var cache = JsonSerializer.Deserialize<OfflineCacheResponse>(json, JsonOptions);

            if (cache != null)
            {
                lock (_lock) _currentCache = cache;
                _logger.LogInformation("[OfflineCache] Loaded existing cache from disk: {UserCount} users, generatedAt={GeneratedAt}",
                    cache.Users.Length, cache.GeneratedAt);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OfflineCache] Failed to load cache from disk (may be corrupted or from different machine)");
        }
    }

    private void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }
}
