using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Helpers;

/// <summary>
/// Simple file logger with daily rotation and configurable retention.
/// Logs to C:\ProgramData\Gruppen IT\GruppenMFA\Logs\agent-service-YYYY-MM-DD.log
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _logDirectory;
    private readonly int _retentionDays;
    private readonly object _lock = new();

    public FileLoggerProvider(string logDirectory, int retentionDays = 7)
    {
        _logDirectory = logDirectory;
        _retentionDays = retentionDays;
        Directory.CreateDirectory(_logDirectory);
    }

    public ILogger CreateLogger(string categoryName) =>
        new FileLogger(_logDirectory, categoryName, _retentionDays, _lock);

    public void Dispose() { }
}

public sealed class FileLogger : ILogger
{
    private readonly string _logDirectory;
    private readonly string _category;
    private readonly int _retentionDays;
    private readonly object _lock;

    public FileLogger(string logDirectory, string category, int retentionDays, object lockObj)
    {
        _logDirectory = logDirectory;
        _category = category;
        _retentionDays = retentionDays;
        _lock = lockObj;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;

        var message = formatter(state, exception);
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var level = logLevel switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Critical => "CRT",
            _ => "???"
        };

        // Short category name (last segment)
        var shortCategory = _category.Contains('.')
            ? _category[((_category.LastIndexOf('.') + 1))..]
            : _category;

        var logLine = $"[{timestamp}] [{level}] [{shortCategory}] {message}";
        if (exception != null)
            logLine += Environment.NewLine + exception;

        var fileName = $"agent-service-{DateTime.Now:yyyy-MM-dd}.log";
        var filePath = Path.Combine(_logDirectory, fileName);

        lock (_lock)
        {
            try
            {
                File.AppendAllText(filePath, logLine + Environment.NewLine);
            }
            catch
            {
                // Swallow — don't crash the service because of log failure
            }
        }
    }

    /// <summary>
    /// Delete log files older than retention period.
    /// </summary>
    public static void CleanOldLogs(string logDirectory, int retentionDays)
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-retentionDays);
            foreach (var file in Directory.GetFiles(logDirectory, "agent-service-*.log"))
            {
                if (File.GetCreationTime(file) < cutoff)
                    File.Delete(file);
            }
        }
        catch
        {
            // Best effort
        }
    }
}
