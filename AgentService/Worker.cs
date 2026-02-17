using GruppenMFA.AgentService.Helpers;
using GruppenMFA.AgentService.Models;
using GruppenMFA.AgentService.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService;

/// <summary>
/// Main background worker for the GruppenMFA Agent Service.
/// Performs periodic checkin, config sync, and tamper protection monitoring.
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ConfigManager _configManager;

    private const string DefaultServerUrl = "https://mfa.gruppen.com.br";
    private static readonly TimeSpan CheckinInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan TamperCheckInterval = TimeSpan.FromMinutes(5);

    public Worker(ILogger<Worker> logger, ILoggerFactory loggerFactory, ConfigManager configManager)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _configManager = configManager;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("GruppenMFA Agent Service starting");

        // Read API key
        var apiKey = _configManager.ReadApiKey();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            _logger.LogError("No API key configured. The service will wait and retry every 30s.");
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

        var serverUrl = _configManager.ReadServerUrl();
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            serverUrl = DefaultServerUrl;
            _logger.LogInformation("No server URL in registry, using default: {Url}", serverUrl);
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

        // Initial startup: checkin + config sync + tamper check
        await DoCheckinAndSyncAsync(apiClient, hostname, agentVersion, osVersion, tamperProtection, stoppingToken);

        // Clean old logs
        FileLogger.CleanOldLogs(
            @"C:\ProgramData\Gruppen IT\GruppenMFA\Logs",
            _configManager.LoadLocalConfig()?.LogRetentionDays ?? 7);

        // Main loop
        var lastCheckin = DateTime.UtcNow;
        var lastTamperCheck = DateTime.UtcNow;

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
                await DoCheckinAndSyncAsync(apiClient, hostname, agentVersion, osVersion, tamperProtection, stoppingToken);
                lastCheckin = DateTime.UtcNow;
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

    private async Task DoCheckinAndSyncAsync(
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

        _logger.LogDebug("Sending checkin...");
        var checkinResponse = await apiClient.CheckinAsync(checkinRequest, ct);

        if (checkinResponse == null)
        {
            _logger.LogWarning("Checkin failed — server unreachable, will retry next cycle");
            return;
        }

        _logger.LogDebug("Checkin OK: id={Id}, status={Status}, configHash={Hash}",
            checkinResponse.Id, checkinResponse.Status, checkinResponse.ConfigHash);

        // 2. Compare config hash
        if (!string.IsNullOrEmpty(checkinResponse.ConfigHash) &&
            checkinResponse.ConfigHash != _configManager.CurrentConfigHash)
        {
            _logger.LogInformation("Config hash changed: {Old} -> {New}",
                _configManager.CurrentConfigHash, checkinResponse.ConfigHash);

            // 3. Fetch new config
            var configResponse = await apiClient.GetConfigAsync(hostname, ct);
            if (configResponse?.Config != null)
            {
                _logger.LogInformation("Received config with {PolicyCount} applied policies",
                    configResponse.AppliedPolicies.Length);

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
                    var acked = await apiClient.AckConfigAsync(ack, ct);
                    _logger.LogInformation("Config ack: {Result}", acked ? "success" : "failed");

                    // 6. Apply tamper protection based on new config
                    if (configResponse.Config.PreventUninstall)
                        tamperProtection.EnableUninstallProtection();
                    else
                        tamperProtection.DisableUninstallProtection();

                    if (configResponse.Config.PreventDisable)
                        tamperProtection.EnsureCpRegistered();
                }
            }
            else
            {
                _logger.LogWarning("Failed to fetch config from server");
            }
        }
        else
        {
            _logger.LogDebug("Config is up to date");
        }
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
