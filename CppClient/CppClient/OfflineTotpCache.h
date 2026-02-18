/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2026 Gruppen it Security
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */
#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <Windows.h>

// Error codes for offline TOTP validation
#define OFFLINE_TOTP_SUCCESS                    ((HRESULT)0x00000000) // S_OK
#define OFFLINE_TOTP_CACHE_NOT_FOUND            ((HRESULT)0x88809030)
#define OFFLINE_TOTP_CACHE_EXPIRED              ((HRESULT)0x88809031)
#define OFFLINE_TOTP_ONLINE_REQUIRED            ((HRESULT)0x88809032)
#define OFFLINE_TOTP_USER_NOT_FOUND             ((HRESULT)0x88809033)
#define OFFLINE_TOTP_INVALID_CODE               ((HRESULT)0x88809034)
#define OFFLINE_TOTP_BRUTE_FORCE_LOCKOUT        ((HRESULT)0x88809035)
#define OFFLINE_TOTP_DISABLED                   ((HRESULT)0x88809036)
#define OFFLINE_TOTP_DECRYPT_FAILED             ((HRESULT)0x88809037)
#define OFFLINE_TOTP_MOBILITY_DENIED            ((HRESULT)0x88809038)

/// <summary>
/// A cached user entry for offline TOTP validation.
/// </summary>
struct CachedUser
{
	std::string userId;
	std::string accountName;
	std::vector<std::string> aliases;
	std::string totpSecret; // Base32-encoded
	std::vector<std::string> tagIds;
};

/// <summary>
/// A mobility policy from the offline cache.
/// </summary>
struct CachedMobilityPolicy
{
	std::string id;
	int policyNumber = 0;
	std::string name;
	std::string type;       // "USER" or "ENDPOINT"
	std::string action;     // "ALLOW" or "DENY"
	int priority = 0;
	bool enforceOnTheFly = false;
	std::string startDate;
	std::string endDate;
	std::vector<int> daysOfWeek;
	std::string timeStart;
	std::string timeEnd;
	std::vector<std::string> cidrs;
	std::vector<std::string> userIds;
	std::vector<std::string> userTagIds;
	std::vector<std::string> endpointHostnames;
	std::vector<std::string> endpointTagIds;
};

/// <summary>
/// Settings for offline MFA.
/// </summary>
struct OfflineCacheSettings
{
	int cacheTtlDays = 7;
	int maxCachedUsers = 200;
	int bruteForceLimitOffline = 3;
	int lockoutMinutesOffline = 30;
	int requireOnlineEveryDays = 30;
	int onTheFlyGraceSeconds = 60;
	int totpPeriod = 30;
	int totpDigits = 6;
	std::string totpAlgorithm = "SHA1"; // SHA1, SHA256, SHA512
};

/// <summary>
/// Result of an offline TOTP validation.
/// </summary>
struct OfflineTotpResult
{
	bool success = false;
	std::string userId;
	std::string accountName;
	std::string failReason;
	std::string errorMessage;
	int lockoutRemainingMinutes = 0;
};

/// <summary>
/// Manages the DPAPI-encrypted offline TOTP cache written by the C# AgentService.
/// Reads the cache, validates TOTP codes locally, manages brute-force lockouts,
/// and writes offline events for later sync.
/// </summary>
class OfflineTotpCache
{
public:
	OfflineTotpCache();

	/// <summary>
	/// Load the offline cache from the DPAPI-encrypted file.
	/// </summary>
	/// <returns>true if cache was loaded successfully</returns>
	bool LoadCache();

	/// <summary>
	/// Check if the offline cache is available and not expired.
	/// </summary>
	bool IsCacheValid() const;

	/// <summary>
	/// Check if online authentication is required (requireOnlineEveryDays exceeded).
	/// </summary>
	bool IsOnlineRequired() const;

	/// <summary>
	/// Validate a TOTP code for the given username using the offline cache.
	/// Handles brute-force protection and lockout.
	/// </summary>
	/// <param name="username">The username or alias to look up</param>
	/// <param name="totpCode">The TOTP code to validate</param>
	/// <param name="result">Output: detailed result</param>
	/// <returns>HRESULT error code</returns>
	HRESULT ValidateTotp(const std::wstring& username, const std::wstring& totpCode, OfflineTotpResult& result);

	/// <summary>
	/// Write an offline authentication event to the events directory for later sync.
	/// </summary>
	void WriteOfflineEvent(const std::string& alias, bool success, const std::string& failReason = "");

	/// <summary>
	/// Write an offline session file for mobility enforcement by the C# service.
	/// </summary>
	void WriteOfflineSession(const std::string& userId, const std::string& accountName, const std::string& clientIp);

	/// <summary>
	/// Evaluate mobility policies from cache for a login attempt.
	/// </summary>
	/// <param name="userId">The user ID from the cache</param>
	/// <param name="hostname">The endpoint hostname</param>
	/// <param name="clientIp">The client IP</param>
	/// <returns>HRESULT: S_OK if allowed, OFFLINE_TOTP_MOBILITY_DENIED if denied</returns>
	HRESULT EvaluateMobilityPolicies(const std::string& userId, const std::string& hostname, const std::string& clientIp);

	/// <summary>
	/// Get the settings from the loaded cache.
	/// </summary>
	const OfflineCacheSettings& GetSettings() const { return _settings; }

	/// <summary>
	/// Check if offline MFA is enabled.
	/// </summary>
	bool IsEnabled() const { return _enabled; }

	/// <summary>
	/// Get the local IPv4 address of the machine.
	/// </summary>
	static std::string GetLocalIp();

private:
	// DPAPI decryption
	bool DecryptDPAPI(const std::vector<BYTE>& encrypted, std::string& plaintext);

	// Base32 decoding
	static std::vector<BYTE> Base32Decode(const std::string& base32);

	// TOTP computation
	static std::string ComputeTotp(const std::vector<BYTE>& secret, int64_t timeStep, int digits, const std::string& algorithm);
	static std::vector<BYTE> HmacSha(const std::string& algorithm, const std::vector<BYTE>& key, const std::vector<BYTE>& message);

	// Brute force management
	bool IsLockedOut(const std::string& accountName) const;
	void RecordFailure(const std::string& accountName);
	void ClearFailures(const std::string& accountName);
	void LoadLockouts();
	void SaveLockouts();

	// Find user by username/alias (case-insensitive)
	const CachedUser* FindUser(const std::string& username) const;

	// Cache data
	bool _enabled = false;
	OfflineCacheSettings _settings;
	std::vector<CachedUser> _users;
	std::vector<CachedMobilityPolicy> _mobilityPolicies;
	std::string _generatedAt; // ISO 8601 timestamp

	// Brute force state: accountName -> {failCount, lastFailTime}
	struct LockoutState
	{
		int failCount = 0;
		int64_t lastFailTimestamp = 0; // Unix timestamp
	};
	std::map<std::string, LockoutState> _lockouts;

	// File paths
	static constexpr const wchar_t* CACHE_DIR = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache";
	static constexpr const wchar_t* CACHE_FILE = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache\\offline_cache.dat";
	static constexpr const wchar_t* LOCKOUT_FILE = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache\\offline_lockouts.json";
	static constexpr const wchar_t* EVENTS_DIR = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache\\events";
	static constexpr const wchar_t* SESSIONS_DIR = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache\\offline_sessions";
	static constexpr const wchar_t* LAST_ONLINE_FILE = L"C:\\ProgramData\\Gruppen IT\\GruppenMFA\\cache\\last_online_auth.txt";
};
