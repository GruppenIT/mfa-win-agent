using GruppenMFA.AgentService.Helpers;
using GruppenMFA.AgentService.Models;
using GruppenMFA.AgentService.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService;

/// <summary>
/// Main background worker for the GruppenMFA Agent Service.
/// Performs periodic checkin, config sync, offline cache management,
/// offline event sync, and mobility enforcement.
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ConfigManager _configManager;
    private readonly OfflineCacheService _offlineCacheService;
    private readonly OfflineEventService _offlineEventService;
    private readonly MobilityEnforcementService _mobilityEnforcement;

    private const string DefaultServerUrl = "https://mfa.gruppen.com.br";
    private static readonly TimeSpan CheckinInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan TamperCheckInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MobilityCheckInterval = TimeSpan.FromSeconds(30);

    public Worker(
        ILogger<Worker> logger,
        ILoggerFactory loggerFactory,
        ConfigManager configManager,
        OfflineCacheService offlineCacheService,
        OfflineEventService offlineEventService,
        MobilityEnforcementService mobilityEnforcement)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _configManager = configManager;
        _offlineCacheService = offlineCacheService;
        _offlineEventService = offlineEventService;
        _mobilityEnforcement = mobilityEnforcement;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GruppenMFA Agent Service starting");

        // Read API key
        var apiKey = _configManager.ReadApiKey();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            _logger.LogError("No API key configured — checked registry keys: " +
                @"HKLM\SOFTWARE\Gruppen IT\GruppenMFA-Agent\api_key and " +
                @"HKLM\SOFTWARE\Gruppen IT\GruppenMFA-CP\api_key. " +
                "Waiting and retrying every 30s...");
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
                apiKey = _configManager.ReadApiKey();
                if (!string.IsNullOrWhiteSpace(apiKey))
                {
                    _logger.LogInformation("API key found, proceeding");
                    break;
                }
            }
            if (stoppingToken.IsCancellationRequested) return;
        }
        _logger.LogInformation("API key: {Prefix}...{Suffix} ({Length} chars)",
            apiKey!.Length > 8 ? apiKey[..8] : apiKey,
            apiKey.Length > 4 ? apiKey[^4..] : "",
            apiKey.Length);

        var serverUrl = _configManager.ReadServerUrl();
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            serverUrl = DefaultServerUrl;
            _logger.LogInformation("No server URL in registry, using default: {Url}", serverUrl);
        }
        else
        {
            _logger.LogInformation("Server URL from registry: {Url}", serverUrl);
        }

        using var apiClient = new ApiClient(
            serverUrl, apiKey!, _loggerFactory.CreateLogger<ApiClient>());

        var tamperProtection = new TamperProtection(
            _loggerFactory.CreateLogger<TamperProtection>());

        var hostname = Environment.MachineName.ToUpperInvariant();
        var agentVersion = typeof(Worker).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
        var osVersion = GetWindowsVersion();

        _logger.LogInformation("Agent: hostname={Hostname}, version={Version}, os={OS}",
            hostname, agentVersion, osVersion);
        _logger.LogInformation("Current config hash: {Hash}",
            string.IsNullOrEmpty(_configManager.CurrentConfigHash) ? "(none)" : _configManager.CurrentConfigHash);

        // Initial startup: checkin + config sync + tamper check
        _logger.LogInformation("--- Starting initial checkin + config sync ---");
        bool serverReachable = await DoCheckinAndSyncAsync(apiClient, hostname, agentVersion, osVersion, tamperProtection, stoppingToken);

        // Initial offline cache fetch (if enabled in config)
        if (serverReachable)
        {
            var config = _configManager.LoadLocalConfig();
            if (config?.OfflineMfaEnabled == true)
            {
                _logger.LogInformation("--- Fetching initial offline cache ---");
                await _offlineCacheService.FetchAndStoreAsync(apiClient, hostname, stoppingToken);
            }

            // Sync any pending offline events
            _offlineEventService.ImportCppEvents();
            if (_offlineEventService.PendingCount > 0)
            {
                _logger.LogInformation("--- Syncing {Count} pending offline events ---", _offlineEventService.PendingCount);
                await _offlineEventService.SyncAsync(apiClient, stoppingToken);
            }

            // Record successful online connectivity
            _offlineCacheService.RecordOnlineAuth();
        }

        // Clean old logs
        FileLogger.CleanOldLogs(
            @"C:\ProgramData\Gruppen IT\GruppenMFA\Logs",
            _configManager.LoadLocalConfig()?.LogRetentionDays ?? 7);

        // Main loop
        var lastCheckin = DateTime.UtcNow;
        var lastTamperCheck = DateTime.UtcNow;
        var lastMobilityCheck = DateTime.UtcNow;

        _logger.LogInformation("Entering main loop (checkin every {Interval}s)", CheckinInterval.TotalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var now = DateTime.UtcNow;

            // Periodic checkin (every 2 minutes)
            if (now - lastCheckin >= CheckinInterval)
            {
                serverReachable = await DoCheckinAndSyncAsync(apiClient, hostname, agentVersion, osVersion, tamperProtection, stoppingToken);

                if (serverReachable)
                {
                    // Update offline cache if enabled
                    var config = _configManager.LoadLocalConfig();
                    if (config?.OfflineMfaEnabled == true)
                    {
                        await _offlineCacheService.FetchAndStoreAsync(apiClient, hostname, stoppingToken);
                    }

                    // Sync pending offline events
                    _offlineEventService.ImportCppEvents();
                    if (_offlineEventService.PendingCount > 0)
                    {
                        await _offlineEventService.SyncAsync(apiClient, stoppingToken);
                    }

                    _offlineCacheService.RecordOnlineAuth();
                }

                lastCheckin = DateTime.UtcNow;
            }

            // Periodic mobility enforcement (every 30 seconds)
            if (now - lastMobilityCheck >= MobilityCheckInterval)
            {
                _mobilityEnforcement.ImportOfflineSessions();
                if (_mobilityEnforcement.HasPendingSessions && serverReachable)
                {
                    await _mobilityEnforcement.EnforceAsync(apiClient, hostname, stoppingToken);
                }
                lastMobilityCheck = DateTime.UtcNow;
            }

            // Periodic tamper check (every 5 minutes)
            if (now - lastTamperCheck >= TamperCheckInterval)
            {
                var config = _configManager.LoadLocalConfig();
                if (config?.PreventDisable == true)
                {
                    tamperProtection.EnsureCpRegistered();
                }
                lastTamperCheck = DateTime.UtcNow;
            }
        }

        _logger.LogInformation("GruppenMFA Agent Service stopping");
    }

    /// <summary>
    /// Perform checkin and config sync. Returns true if server was reachable.
    /// </summary>
    private async Task<bool> DoCheckinAndSyncAsync(
        ApiClient apiClient,
        string hostname,
        string agentVersion,
        string osVersion,
        TamperProtection tamperProtection,
        CancellationToken ct)
    {
        // 1. Checkin
        var checkinRequest = new CheckinRequest
        {
            Hostname = hostname,
            AgentType = "CP",
            OsVersion = osVersion,
            AgentVersion = agentVersion
        };

        _logger.LogInformation("[Checkin] POST /api/agents/checkin — hostname={Hostname}, agentType=CP", hostname);
        var checkinResponse = await apiClient.CheckinAsync(checkinRequest, ct);

        if (checkinResponse == null)
        {
            _logger.LogWarning("[Checkin] FAILED — server unreachable or returned error. Will retry next cycle.");
            return false;
        }

        _logger.LogInformation("[Checkin] OK — id={Id}, status={Status}, configHash={Hash}",
            checkinResponse.Id, checkinResponse.Status, checkinResponse.ConfigHash);

        // 2. Compare config hash
        if (!string.IsNullOrEmpty(checkinResponse.ConfigHash) &&
            checkinResponse.ConfigHash != _configManager.CurrentConfigHash)
        {
            _logger.LogInformation("[Config] Hash changed: local={Old} -> server={New}. Fetching new config...",
                string.IsNullOrEmpty(_configManager.CurrentConfigHash) ? "(none)" : _configManager.CurrentConfigHash,
                checkinResponse.ConfigHash);

            // 3. Fetch new config
            _logger.LogInformation("[Config] GET /api/agents/config?hostname={Hostname}&agentType=CP", hostname);
            var configResponse = await apiClient.GetConfigAsync(hostname, ct);
            if (configResponse?.Config != null)
            {
                _logger.LogInformation("[Config] Received config — configHash={Hash}, policies={PolicyCount}",
                    configResponse.ConfigHash, configResponse.AppliedPolicies.Length);

                foreach (var p in configResponse.AppliedPolicies)
                    _logger.LogInformation("[Config]   Policy: {Name} (default={IsDefault})", p.Name, p.IsDefault);

                // 4. Apply config
                if (_configManager.ApplyConfig(configResponse.Config, configResponse.ConfigHash))
                {
                    // 5. Ack
                    var ack = new ConfigAckRequest
                    {
                        Hostname = hostname,
                        AgentType = "CP",
                        ConfigHash = configResponse.ConfigHash
                    };
                    _logger.LogInformation("[Config] POST /api/agents/config/ack — configHash={Hash}", configResponse.ConfigHash);
                    var acked = await apiClient.AckConfigAsync(ack, ct);
                    _logger.LogInformation("[Config] ACK result: {Result}", acked ? "success" : "FAILED");

                    // 6. Apply tamper protection based on new config
                    if (configResponse.Config.PreventUninstall)
                        tamperProtection.EnableUninstallProtection();
                    else
                        tamperProtection.DisableUninstallProtection();

                    if (configResponse.Config.PreventDisable)
                        tamperProtection.EnsureCpRegistered();
                }
                else
                {
                    _logger.LogWarning("[Config] Failed to apply config to registry");
                }
            }
            else
            {
                _logger.LogWarning("[Config] FAILED — server returned null config. Check API key permissions and endpoint.");
            }
        }
        else if (string.IsNullOrEmpty(checkinResponse.ConfigHash))
        {
            _logger.LogWarning("[Config] Server returned empty configHash — no policy assigned to this agent?");
        }
        else
        {
            _logger.LogInformation("[Config] Up to date (hash={Hash})", _configManager.CurrentConfigHash);
        }

        return true;
    }

    private static string GetWindowsVersion()
    {
        try
        {
            var os = Environment.OSVersion;
            var release = Microsoft.Win32.Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                "DisplayVersion", null) as string;

            return $"Windows {os.Version.Major}.{os.Version.Minor}.{os.Version.Build}" +
                   (string.IsNullOrEmpty(release) ? "" : $" {release}");
        }
        catch
        {
            return Environment.OSVersion.ToString();
        }
    }
}
