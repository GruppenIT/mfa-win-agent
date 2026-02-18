using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Manages the offline event queue: reads events written by the C++ CP DLL,
/// batches them, and syncs to the server when connectivity is available.
/// </summary>
public sealed class OfflineEventService
{
    private readonly ILogger<OfflineEventService> _logger;

    private const string CacheDir = @"C:\ProgramData\Gruppen IT\GruppenMFA\cache";
    private const string EventsFilePath = CacheDir + @"\offline_events.dat";
    private const int MaxEventsPerRequest = 1000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    private readonly List<OfflineEvent> _pendingEvents = new();
    private readonly object _lock = new();

    public int PendingCount
    {
        get { lock (_lock) return _pendingEvents.Count; }
    }

    public OfflineEventService(ILogger<OfflineEventService> logger)
    {
        _logger = logger;
        Directory.CreateDirectory(CacheDir);
        LoadFromDisk();
    }

    /// <summary>
    /// Add a new offline event to the pending queue.
    /// Called by the C++ CP via shared file, or directly from the service.
    /// </summary>
    public void Enqueue(OfflineEvent evt)
    {
        lock (_lock)
        {
            _pendingEvents.Add(evt);
        }
        PersistToDisk();
        _logger.LogDebug("[OfflineEvents] Enqueued event for {Alias} (success={Success})", evt.Alias, evt.Success);
    }

    /// <summary>
    /// Scan for event files written by the C++ CP DLL and import them into the queue.
    /// The CP writes individual JSON files in the events directory.
    /// </summary>
    public void ImportCppEvents()
    {
        var eventsDir = Path.Combine(CacheDir, "events");
        if (!Directory.Exists(eventsDir)) return;

        try
        {
            var files = Directory.GetFiles(eventsDir, "*.json");
            if (files.Length == 0) return;

            int imported = 0;
            foreach (var file in files)
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var evt = JsonSerializer.Deserialize<OfflineEvent>(json, JsonOptions);
                    if (evt != null)
                    {
                        lock (_lock) _pendingEvents.Add(evt);
                        imported++;
                    }
                    File.Delete(file);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[OfflineEvents] Failed to import event file {File}", file);
                }
            }

            if (imported > 0)
            {
                PersistToDisk();
                _logger.LogInformation("[OfflineEvents] Imported {Count} events from CP", imported);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OfflineEvents] Error scanning events directory");
        }
    }

    /// <summary>
    /// Sync pending events to the server. Sends batches of up to 1000 events.
    /// Returns true if all events were synced successfully.
    /// </summary>
    public async Task<bool> SyncAsync(ApiClient apiClient, CancellationToken ct)
    {
        OfflineEvent[] eventsToSend;
        lock (_lock)
        {
            if (_pendingEvents.Count == 0) return true;
            eventsToSend = _pendingEvents.ToArray();
        }

        _logger.LogInformation("[OfflineEvents] Syncing {Count} pending events to server", eventsToSend.Length);

        int totalSynced = 0;
        for (int offset = 0; offset < eventsToSend.Length; offset += MaxEventsPerRequest)
        {
            if (ct.IsCancellationRequested) break;

            var batch = eventsToSend.Skip(offset).Take(MaxEventsPerRequest).ToArray();
            var request = new OfflineEventsRequest { Events = batch };

            var response = await apiClient.PostOfflineEventsAsync(request, ct);
            if (response != null)
            {
                totalSynced += batch.Length;
                _logger.LogInformation("[OfflineEvents] Batch synced: accepted={Accepted}, rejected={Rejected}",
                    response.Accepted, response.Rejected);
            }
            else
            {
                _logger.LogWarning("[OfflineEvents] Failed to sync batch (offset={Offset}). Remaining events kept in queue.", offset);
                break;
            }
        }

        if (totalSynced > 0)
        {
            lock (_lock)
            {
                _pendingEvents.RemoveRange(0, Math.Min(totalSynced, _pendingEvents.Count));
            }
            PersistToDisk();
        }

        return totalSynced == eventsToSend.Length;
    }

    private void PersistToDisk()
    {
        try
        {
            OfflineEvent[] snapshot;
            lock (_lock) snapshot = _pendingEvents.ToArray();

            var json = JsonSerializer.Serialize(snapshot, JsonOptions);
            var plainBytes = Encoding.UTF8.GetBytes(json);
            var encryptedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(EventsFilePath, encryptedBytes);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OfflineEvents] Failed to persist events to disk");
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            if (!File.Exists(EventsFilePath)) return;

            var encryptedBytes = File.ReadAllBytes(EventsFilePath);
            var plainBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine);
            var json = Encoding.UTF8.GetString(plainBytes);
            var events = JsonSerializer.Deserialize<OfflineEvent[]>(json, JsonOptions);

            if (events != null && events.Length > 0)
            {
                lock (_lock) _pendingEvents.AddRange(events);
                _logger.LogInformation("[OfflineEvents] Loaded {Count} pending events from disk", events.Length);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OfflineEvents] Failed to load events from disk");
        }
    }
}
