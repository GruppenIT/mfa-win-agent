using System.Net;
using GruppenMFA.AgentService.Models;
using Microsoft.Extensions.Logging;

namespace GruppenMFA.AgentService.Services;

/// <summary>
/// Evaluates mobility policies locally using the cached data.
/// Used as fallback when the server is unreachable.
/// </summary>
public sealed class MobilityPolicyEvaluator
{
    private readonly ILogger<MobilityPolicyEvaluator> _logger;

    public MobilityPolicyEvaluator(ILogger<MobilityPolicyEvaluator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Evaluate mobility policies locally against the provided context.
    /// Returns a synthetic MobilityCheckResponse.
    /// Logic: process policies by priority. If any DENY matches, deny.
    /// If any ALLOW matches, allow. If nothing matches, allow (default-allow).
    /// </summary>
    public MobilityCheckResponse Evaluate(
        MobilityPolicy[] policies,
        string userId,
        string[] userTagIds,
        string endpointHostname,
        string clientIp)
    {
        if (policies.Length == 0)
        {
            return new MobilityCheckResponse
            {
                Allowed = true,
                Message = "Nenhuma política de mobilidade configurada"
            };
        }

        // Filter active policies (date, day of week, time)
        var now = DateTime.Now;
        var activePolicies = policies
            .Where(p => IsPolicyActive(p, now))
            .OrderBy(p => p.Priority)
            .ToArray();

        if (activePolicies.Length == 0)
        {
            return new MobilityCheckResponse
            {
                Allowed = true,
                Message = "Nenhuma política de mobilidade ativa no momento"
            };
        }

        // Check DENY policies first
        foreach (var policy in activePolicies.Where(p => p.Action == "DENY"))
        {
            if (PolicyMatchesContext(policy, userId, userTagIds, endpointHostname, clientIp))
            {
                _logger.LogInformation("[Mobility] DENY matched: policy #{Num} '{Name}'",
                    policy.PolicyNumber, policy.Name);
                return new MobilityCheckResponse
                {
                    Allowed = false,
                    PolicyName = policy.Name,
                    PolicyNumber = policy.PolicyNumber,
                    Action = "DENY",
                    Message = $"Sessão não autorizada pela política de mobilidade #{policy.PolicyNumber}: {policy.Name}"
                };
            }
        }

        // Check ALLOW policies
        foreach (var policy in activePolicies.Where(p => p.Action == "ALLOW"))
        {
            if (PolicyMatchesContext(policy, userId, userTagIds, endpointHostname, clientIp))
            {
                _logger.LogDebug("[Mobility] ALLOW matched: policy #{Num} '{Name}'",
                    policy.PolicyNumber, policy.Name);
                return new MobilityCheckResponse
                {
                    Allowed = true,
                    PolicyName = policy.Name,
                    PolicyNumber = policy.PolicyNumber
                };
            }
        }

        // Default: allow if no policy matched
        return new MobilityCheckResponse
        {
            Allowed = true,
            Message = "Nenhuma política de mobilidade aplicável"
        };
    }

    private bool IsPolicyActive(MobilityPolicy policy, DateTime now)
    {
        // Check date range
        if (!string.IsNullOrEmpty(policy.StartDate))
        {
            if (DateOnly.TryParse(policy.StartDate, out var start) && DateOnly.FromDateTime(now) < start)
                return false;
        }
        if (!string.IsNullOrEmpty(policy.EndDate))
        {
            if (DateOnly.TryParse(policy.EndDate, out var end) && DateOnly.FromDateTime(now) > end)
                return false;
        }

        // Check day of week (1=Monday ... 7=Sunday in ISO, DayOfWeek: 0=Sunday ... 6=Saturday)
        if (policy.DaysOfWeek.Length > 0)
        {
            // Convert .NET DayOfWeek to ISO day number
            int isoDayOfWeek = now.DayOfWeek == DayOfWeek.Sunday ? 7 : (int)now.DayOfWeek;
            if (!policy.DaysOfWeek.Contains(isoDayOfWeek))
                return false;
        }

        // Check time range
        if (!string.IsNullOrEmpty(policy.TimeStart) && !string.IsNullOrEmpty(policy.TimeEnd))
        {
            if (TimeOnly.TryParse(policy.TimeStart, out var timeStart) &&
                TimeOnly.TryParse(policy.TimeEnd, out var timeEnd))
            {
                var timeNow = TimeOnly.FromDateTime(now);
                if (timeNow < timeStart || timeNow > timeEnd)
                    return false;
            }
        }

        return true;
    }

    private bool PolicyMatchesContext(
        MobilityPolicy policy,
        string userId,
        string[] userTagIds,
        string endpointHostname,
        string clientIp)
    {
        if (policy.Type == "USER")
        {
            // Match by userId or user tags
            bool userMatch = policy.UserIds.Contains(userId, StringComparer.OrdinalIgnoreCase);
            if (!userMatch && policy.UserTagIds.Length > 0 && userTagIds.Length > 0)
            {
                userMatch = policy.UserTagIds.Any(tagId =>
                    userTagIds.Contains(tagId, StringComparer.OrdinalIgnoreCase));
            }
            if (!userMatch) return false;

            // If CIDRs are specified, also check IP
            if (policy.Cidrs.Length > 0)
            {
                if (!IpMatchesCidrs(clientIp, policy.Cidrs))
                    return false;
            }

            return true;
        }

        if (policy.Type == "ENDPOINT")
        {
            // Match by hostname
            bool endpointMatch = policy.EndpointHostnames
                .Contains(endpointHostname, StringComparer.OrdinalIgnoreCase);

            // Or by endpoint tags (we don't have endpoint tags in the CP context, skip)

            // Or by CIDR
            if (!endpointMatch && policy.Cidrs.Length > 0)
            {
                endpointMatch = IpMatchesCidrs(clientIp, policy.Cidrs);
            }

            return endpointMatch;
        }

        return false;
    }

    /// <summary>
    /// Check if a given IP address falls within any of the specified CIDR ranges.
    /// </summary>
    private static bool IpMatchesCidrs(string ipStr, string[] cidrs)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return false;

        foreach (var cidr in cidrs)
        {
            if (IsInCidr(ip, cidr)) return true;
        }
        return false;
    }

    private static bool IsInCidr(IPAddress ip, string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return false;
            if (!IPAddress.TryParse(parts[0], out var network)) return false;
            if (!int.TryParse(parts[1], out var prefixLen)) return false;

            var ipBytes = ip.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            if (ipBytes.Length != networkBytes.Length) return false;

            int fullBytes = prefixLen / 8;
            int remainingBits = prefixLen % 8;

            for (int i = 0; i < fullBytes && i < ipBytes.Length; i++)
            {
                if (ipBytes[i] != networkBytes[i]) return false;
            }

            if (remainingBits > 0 && fullBytes < ipBytes.Length)
            {
                byte mask = (byte)(0xFF << (8 - remainingBits));
                if ((ipBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask))
                    return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}
