using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Monitors and protects the Credential Provider registration.
/// If the CP is unregistered (removed from the authentication flow), this service
/// re-registers it automatically. Also blocks disabling via registry manipulation.
/// </summary>
public sealed class TamperProtection
{
    private readonly ILogger<TamperProtection> _logger;

    // The CP CLSID — must match guid.cpp in the CredentialProvider project
    private const string CpClsid = "{7BAF541E-F8E0-4EDF-B69A-BD2771139E8E}";
    private const string FilterClsid = "{34065473-D75F-4BC2-9782-E98E63ED0D41}";

    private const string CredProviderRegistryPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\" + CpClsid;
    private const string CredFilterRegistryPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\" + FilterClsid;
    private const string ClsidCpPath = @"CLSID\" + CpClsid;
    private const string ClsidFilterPath = @"CLSID\" + FilterClsid;

    public TamperProtection(ILogger<TamperProtection> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Check if the CP is still registered and re-register if needed.
    /// </summary>
    public void EnsureCpRegistered()
    {
        try
        {
            // Check Credential Provider registration
            using var cpKey = Registry.LocalMachine.OpenSubKey(CredProviderRegistryPath);
            if (cpKey == null)
            {
                _logger.LogWarning("Credential Provider not registered at {Path} — re-registering", CredProviderRegistryPath);
                RegisterCredentialProvider();
            }

            // Check Filter registration
            using var filterKey = Registry.LocalMachine.OpenSubKey(CredFilterRegistryPath);
            if (filterKey == null)
            {
                _logger.LogWarning("Credential Provider Filter not registered at {Path} — re-registering", CredFilterRegistryPath);
                RegisterCredentialProviderFilter();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking CP registration");
        }
    }

    /// <summary>
    /// Block uninstallation by setting the SystemComponent flag on the MSI product.
    /// This hides the product from Add/Remove Programs.
    /// </summary>
    public void EnableUninstallProtection()
    {
        try
        {
            // Find our MSI product in the Uninstall registry
            var uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using var uninstallKey = Registry.LocalMachine.OpenSubKey(uninstallPath);
            if (uninstallKey == null) return;

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                using var productKey = Registry.LocalMachine.OpenSubKey($@"{uninstallPath}\{subKeyName}", writable: true);
                var displayName = productKey?.GetValue("DisplayName") as string;
                if (displayName != null && displayName.Contains("GruppenMFA", StringComparison.OrdinalIgnoreCase))
                {
                    productKey!.SetValue("SystemComponent", 1, RegistryValueKind.DWord);
                    _logger.LogInformation("Uninstall protection enabled for {Product}", displayName);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enable uninstall protection");
        }
    }

    /// <summary>
    /// Remove uninstall protection.
    /// </summary>
    public void DisableUninstallProtection()
    {
        try
        {
            var uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using var uninstallKey = Registry.LocalMachine.OpenSubKey(uninstallPath);
            if (uninstallKey == null) return;

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                using var productKey = Registry.LocalMachine.OpenSubKey($@"{uninstallPath}\{subKeyName}", writable: true);
                var displayName = productKey?.GetValue("DisplayName") as string;
                if (displayName != null && displayName.Contains("GruppenMFA", StringComparison.OrdinalIgnoreCase))
                {
                    productKey!.DeleteValue("SystemComponent", throwOnMissingValue: false);
                    _logger.LogInformation("Uninstall protection disabled for {Product}", displayName);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to disable uninstall protection");
        }
    }

    private void RegisterCredentialProvider()
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(CredProviderRegistryPath);
            key.SetValue(null, "GruppenMFACredentialProvider"); // default value

            // CLSID registration
            using var clsidKey = Registry.ClassesRoot.CreateSubKey(ClsidCpPath);
            clsidKey.SetValue(null, "GruppenMFACredentialProvider");

            using var inproc = Registry.ClassesRoot.CreateSubKey(ClsidCpPath + @"\InprocServer32");
            inproc.SetValue(null, "GruppenMFACredentialProvider.dll");
            inproc.SetValue("ThreadingModel", "Apartment");

            _logger.LogInformation("Credential Provider re-registered successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to re-register Credential Provider");
        }
    }

    private void RegisterCredentialProviderFilter()
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(CredFilterRegistryPath);
            key.SetValue(null, "GruppenMFACredentialProviderFilter");

            using var clsidKey = Registry.ClassesRoot.CreateSubKey(ClsidFilterPath);
            clsidKey.SetValue(null, "GruppenMFACredentialProviderFilter");

            using var inproc = Registry.ClassesRoot.CreateSubKey(ClsidFilterPath + @"\InprocServer32");
            inproc.SetValue(null, "GruppenMFACredentialProviderFilter.dll");
            inproc.SetValue("ThreadingModel", "Apartment");

            _logger.LogInformation("Credential Provider Filter re-registered successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to re-register Credential Provider Filter");
        }
    }
}
