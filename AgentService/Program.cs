using GruppenMFA.AgentService;
using GruppenMFA.AgentService.Helpers;
using GruppenMFA.AgentService.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var logDirectory = @"C:\ProgramData\Gruppen IT\GruppenMFA\Logs";

var builder = Host.CreateApplicationBuilder(args);

// Remove default providers and add our file logger
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new FileLoggerProvider(logDirectory, retentionDays: 7));

// Also log to console when running interactively (for debugging)
if (!Environment.UserInteractive || args.Contains("--console"))
{
    builder.Logging.AddConsole();
}

// Set minimum log level
builder.Logging.SetMinimumLevel(LogLevel.Information);

// Register services
builder.Services.AddSingleton<ConfigManager>();
builder.Services.AddSingleton<OfflineCacheService>();
builder.Services.AddSingleton<OfflineEventService>();
builder.Services.AddSingleton<MobilityPolicyEvaluator>();
builder.Services.AddSingleton<MobilityEnforcementService>();
builder.Services.AddHostedService<Worker>();

// Enable running as a Windows Service
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "GruppenMFA Agent";
});

var host = builder.Build();
host.Run();
