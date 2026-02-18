using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Monitors offline sessions and enforces mobility policies.
/// When a session was started offline and network comes back,
/// checks with the server and locks the workstation if denied.
/// </summary>
public sealed class MobilityEnforcementService
{
    private readonly ILogger<MobilityEnforcementService> _logger;
    private readonly MobilityPolicyEvaluator _policyEvaluator;

    private const string SessionsDir = @"C:\ProgramData\Gruppen IT\GruppenMFA\cache\offline_sessions";
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    // Track active offline sessions
    private readonly List<OfflineSessionInfo> _offlineSessions = new();
    private readonly object _lock = new();

    public MobilityEnforcementService(
        ILogger<MobilityEnforcementService> logger,
        MobilityPolicyEvaluator policyEvaluator)
    {
        _logger = logger;
        _policyEvaluator = policyEvaluator;
        Directory.CreateDirectory(SessionsDir);
    }

    /// <summary>
    /// Scan for new offline session files written by the C++ CP DLL.
    /// </summary>
    public void ImportOfflineSessions()
    {
        try
        {
            if (!Directory.Exists(SessionsDir)) return;

            var files = Directory.GetFiles(SessionsDir, "*.json");
            foreach (var file in files)
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var session = JsonSerializer.Deserialize<OfflineSessionInfo>(json, JsonOptions);
                    if (session != null)
                    {
                        lock (_lock)
                        {
                            // Avoid duplicates
                            if (!_offlineSessions.Any(s => s.UserId == session.UserId && s.Timestamp == session.Timestamp))
                            {
                                _offlineSessions.Add(session);
                                _logger.LogInformation("[Mobility] Imported offline session: user={UserId}, ip={Ip}",
                                    session.UserId, session.ClientIp);
                            }
                        }
                    }
                    File.Delete(file);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[Mobility] Failed to import session file {File}", file);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Mobility] Error scanning offline sessions directory");
        }
    }

    /// <summary>
    /// Check all active offline sessions against mobility policies via the server.
    /// If the server denies any session, warn the user and lock the workstation after grace period.
    /// </summary>
    public async Task EnforceAsync(ApiClient apiClient, string hostname, CancellationToken ct)
    {
        OfflineSessionInfo[] sessions;
        lock (_lock)
        {
            if (_offlineSessions.Count == 0) return;
            sessions = _offlineSessions.ToArray();
        }

        var currentIp = GetLocalIpAddress();

        foreach (var session in sessions)
        {
            if (ct.IsCancellationRequested) break;

            var request = new MobilityCheckRequest
            {
                UserId = session.UserId,
                EndpointHostname = hostname,
                ClientIp = currentIp ?? session.ClientIp
            };

            _logger.LogInformation("[Mobility] Checking session: userId={UserId}, hostname={Hostname}, ip={Ip}",
                session.UserId, hostname, request.ClientIp);

            var response = await apiClient.MobilityCheckAsync(request, ct);

            if (response == null)
            {
                _logger.LogDebug("[Mobility] Server unreachable for mobility check, will retry later");
                continue;
            }

            if (response.Allowed)
            {
                _logger.LogInformation("[Mobility] Session allowed for user {UserId}", session.UserId);
                // Remove from tracking — session is verified
                lock (_lock) _offlineSessions.Remove(session);
            }
            else
            {
                _logger.LogWarning("[Mobility] Session DENIED for user {UserId}: policy #{Num} '{Name}'",
                    session.UserId, response.PolicyNumber, response.PolicyName);

                int graceSeconds = response.GraceSeconds ?? 60;
                _logger.LogWarning("[Mobility] Workstation will be locked in {Grace} seconds", graceSeconds);

                // Wait for grace period then lock
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(graceSeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                _logger.LogWarning("[Mobility] Locking workstation due to mobility policy violation");
                LockWorkStation();

                // Remove from tracking after lockout
                lock (_lock) _offlineSessions.Remove(session);
            }
        }
    }

    /// <summary>
    /// Evaluate offline sessions against cached mobility policies (fallback when server is unreachable).
    /// Called by the C++ CP during offline login — the result is written as a session file.
    /// </summary>
    public MobilityCheckResponse EvaluateOffline(
        OfflineCacheResponse cache,
        string userId,
        string endpointHostname,
        string clientIp)
    {
        if (cache.MobilityPolicies.Length == 0)
        {
            return new MobilityCheckResponse { Allowed = true, Message = "Nenhuma política configurada" };
        }

        // Find user tags from cache
        var userTags = cache.Users
            .FirstOrDefault(u => u.UserId.Equals(userId, StringComparison.OrdinalIgnoreCase))
            ?.TagIds ?? Array.Empty<string>();

        return _policyEvaluator.Evaluate(
            cache.MobilityPolicies,
            userId,
            userTags,
            endpointHostname,
            clientIp);
    }

    /// <summary>
    /// Check if there are active offline sessions that need mobility enforcement.
    /// </summary>
    public bool HasPendingSessions
    {
        get { lock (_lock) return _offlineSessions.Count > 0; }
    }

    private static string? GetLocalIpAddress()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var props = ni.GetIPProperties();
                foreach (var addr in props.UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        return addr.Address.ToString();
                }
            }
        }
        catch { }
        return null;
    }
}

/// <summary>
/// Represents an offline session that needs mobility enforcement.
/// Written by C++ CP DLL, read by this service.
/// </summary>
public class OfflineSessionInfo
{
    public string UserId { get; set; } = string.Empty;
    public string AccountName { get; set; } = string.Empty;
    public string ClientIp { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}
