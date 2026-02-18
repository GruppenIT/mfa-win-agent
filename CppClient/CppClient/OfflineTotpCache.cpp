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

#include "OfflineTotpCache.h"
#include "Logger.h"
#include "Convert.h"
#include <nlohmann/json.hpp>
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ShlObj.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

using json = nlohmann::json;
using namespace std;

OfflineTotpCache::OfflineTotpCache()
{
	// Ensure directories exist
	CreateDirectoryW(CACHE_DIR, NULL);
	CreateDirectoryW(EVENTS_DIR, NULL);
	CreateDirectoryW(SESSIONS_DIR, NULL);
	LoadLockouts();
}

bool OfflineTotpCache::LoadCache()
{
	PIDebug("OfflineTotpCache::LoadCache");

	// Read the encrypted file
	wstring filePath(CACHE_FILE);
	HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PIDebug("Offline cache file not found");
		return false;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == 0 || fileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(hFile);
		PIDebug("Offline cache file is empty or invalid");
		return false;
	}

	vector<BYTE> encrypted(fileSize);
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, encrypted.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize)
	{
		CloseHandle(hFile);
		PIError("Failed to read offline cache file");
		return false;
	}
	CloseHandle(hFile);

	// Decrypt via DPAPI
	string jsonStr;
	if (!DecryptDPAPI(encrypted, jsonStr))
	{
		PIError("Failed to decrypt offline cache (DPAPI)");
		return false;
	}

	// Parse JSON
	try
	{
		auto j = json::parse(jsonStr);

		_enabled = j.value("enabled", false);
		if (!_enabled)
		{
			PIDebug("Offline MFA is disabled in cache");
			return true;
		}

		// Parse settings
		if (j.contains("settings") && !j["settings"].is_null())
		{
			auto& s = j["settings"];
			_settings.cacheTtlDays = s.value("cacheTtlDays", 7);
			_settings.maxCachedUsers = s.value("maxCachedUsers", 200);
			_settings.bruteForceLimitOffline = s.value("bruteForceLimitOffline", 3);
			_settings.lockoutMinutesOffline = s.value("lockoutMinutesOffline", 30);
			_settings.requireOnlineEveryDays = s.value("requireOnlineEveryDays", 30);
			_settings.onTheFlyGraceSeconds = s.value("onTheFlyGraceSeconds", 60);
			_settings.totpPeriod = s.value("totpPeriod", 30);
			_settings.totpDigits = s.value("totpDigits", 6);
			_settings.totpAlgorithm = s.value("totpAlgorithm", "SHA1");
		}

		// Parse users
		_users.clear();
		if (j.contains("users") && j["users"].is_array())
		{
			for (auto& u : j["users"])
			{
				CachedUser user;
				user.userId = u.value("userId", "");
				user.accountName = u.value("accountName", "");
				user.totpSecret = u.value("totpSecret", "");

				if (u.contains("aliases") && u["aliases"].is_array())
				{
					for (auto& a : u["aliases"])
						user.aliases.push_back(a.get<string>());
				}
				if (u.contains("tagIds") && u["tagIds"].is_array())
				{
					for (auto& t : u["tagIds"])
						user.tagIds.push_back(t.get<string>());
				}
				_users.push_back(user);
			}
		}

		// Parse mobility policies
		_mobilityPolicies.clear();
		if (j.contains("mobilityPolicies") && j["mobilityPolicies"].is_array())
		{
			for (auto& p : j["mobilityPolicies"])
			{
				CachedMobilityPolicy policy;
				policy.id = p.value("id", "");
				policy.policyNumber = p.value("policyNumber", 0);
				policy.name = p.value("name", "");
				policy.type = p.value("type", "");
				policy.action = p.value("action", "");
				policy.priority = p.value("priority", 0);
				policy.enforceOnTheFly = p.value("enforceOnTheFly", false);
				policy.startDate = p.value("startDate", "");
				policy.endDate = p.value("endDate", "");
				policy.timeStart = p.value("timeStart", "");
				policy.timeEnd = p.value("timeEnd", "");

				if (p.contains("daysOfWeek") && p["daysOfWeek"].is_array())
					for (auto& d : p["daysOfWeek"]) policy.daysOfWeek.push_back(d.get<int>());
				if (p.contains("cidrs") && p["cidrs"].is_array())
					for (auto& c : p["cidrs"]) policy.cidrs.push_back(c.get<string>());
				if (p.contains("userIds") && p["userIds"].is_array())
					for (auto& u : p["userIds"]) policy.userIds.push_back(u.get<string>());
				if (p.contains("userTagIds") && p["userTagIds"].is_array())
					for (auto& t : p["userTagIds"]) policy.userTagIds.push_back(t.get<string>());
				if (p.contains("endpointHostnames") && p["endpointHostnames"].is_array())
					for (auto& h : p["endpointHostnames"]) policy.endpointHostnames.push_back(h.get<string>());
				if (p.contains("endpointTagIds") && p["endpointTagIds"].is_array())
					for (auto& t : p["endpointTagIds"]) policy.endpointTagIds.push_back(t.get<string>());

				_mobilityPolicies.push_back(policy);
			}
		}

		_generatedAt = j.value("generatedAt", "");

		PIDebug("Offline cache loaded: " + to_string(_users.size()) + " users, " +
			to_string(_mobilityPolicies.size()) + " mobility policies");
		return true;
	}
	catch (const json::exception& e)
	{
		PIError(string("Failed to parse offline cache JSON: ") + e.what());
		return false;
	}
}

bool OfflineTotpCache::IsCacheValid() const
{
	if (!_enabled) return false;
	if (_generatedAt.empty()) return false;

	// Parse generatedAt ISO 8601 timestamp
	tm tm = {};
	istringstream ss(_generatedAt);
	ss >> get_time(&tm, "%Y-%m-%dT%H:%M:%S");
	if (ss.fail()) return false;

	time_t generatedTime = _mkgmtime(&tm);
	time_t now = time(nullptr);

	double daysElapsed = difftime(now, generatedTime) / (60.0 * 60.0 * 24.0);
	return daysElapsed <= _settings.cacheTtlDays;
}

bool OfflineTotpCache::IsOnlineRequired() const
{
	// Read the last online auth file
	wstring filePath(LAST_ONLINE_FILE);
	HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return true; // No record = online required

	char buf[128] = {};
	DWORD bytesRead = 0;
	ReadFile(hFile, buf, sizeof(buf) - 1, &bytesRead, NULL);
	CloseHandle(hFile);

	string lastOnline(buf, bytesRead);
	// Trim whitespace
	while (!lastOnline.empty() && (lastOnline.back() == '\n' || lastOnline.back() == '\r' || lastOnline.back() == ' '))
		lastOnline.pop_back();

	if (lastOnline.empty()) return true;

	tm tm = {};
	istringstream ss(lastOnline);
	ss >> get_time(&tm, "%Y-%m-%dT%H:%M:%S");
	if (ss.fail()) return true;

	time_t lastTime = _mkgmtime(&tm);
	time_t now = time(nullptr);

	double daysElapsed = difftime(now, lastTime) / (60.0 * 60.0 * 24.0);
	return daysElapsed > _settings.requireOnlineEveryDays;
}

HRESULT OfflineTotpCache::ValidateTotp(const std::wstring& username, const std::wstring& totpCode, OfflineTotpResult& result)
{
	PIDebug("OfflineTotpCache::ValidateTotp");

	if (!_enabled)
	{
		result.failReason = "OFFLINE_DISABLED";
		result.errorMessage = "Offline MFA is not enabled.";
		return OFFLINE_TOTP_DISABLED;
	}

	if (!IsCacheValid())
	{
		result.failReason = "CACHE_EXPIRED";
		result.errorMessage = "Cache offline expirado. Conecte-se a rede.";
		return OFFLINE_TOTP_CACHE_EXPIRED;
	}

	if (IsOnlineRequired())
	{
		result.failReason = "ONLINE_REQUIRED";
		result.errorMessage = "Autenticacao online necessaria. Conecte-se a rede.";
		return OFFLINE_TOTP_ONLINE_REQUIRED;
	}

	// Look up user
	string szUsername = Convert::ToString(username);
	const CachedUser* user = FindUser(szUsername);
	if (!user)
	{
		result.failReason = "USER_NOT_FOUND";
		result.errorMessage = "Usuario nao disponivel no cache offline.";
		return OFFLINE_TOTP_USER_NOT_FOUND;
	}

	result.userId = user->userId;
	result.accountName = user->accountName;

	// Check brute force lockout
	if (IsLockedOut(user->accountName))
	{
		auto it = _lockouts.find(user->accountName);
		if (it != _lockouts.end())
		{
			int64_t now = (int64_t)time(nullptr);
			int64_t lockoutEnd = it->second.lastFailTimestamp + (_settings.lockoutMinutesOffline * 60);
			int remainingMins = (int)((lockoutEnd - now) / 60) + 1;
			result.lockoutRemainingMinutes = max(0, remainingMins);
		}
		result.failReason = "OFFLINE_LOCKOUT";
		result.errorMessage = "Conta bloqueada por tentativas excessivas. Aguarde " +
			to_string(result.lockoutRemainingMinutes) + " minutos.";
		return OFFLINE_TOTP_BRUTE_FORCE_LOCKOUT;
	}

	// Decode TOTP secret from Base32
	vector<BYTE> secret = Base32Decode(user->totpSecret);
	if (secret.empty())
	{
		PIError("Failed to decode Base32 TOTP secret for user " + user->accountName);
		result.failReason = "INVALID_SECRET";
		result.errorMessage = "Erro interno: segredo TOTP invalido.";
		return E_FAIL;
	}

	// Get current time step
	auto now = chrono::system_clock::now();
	int64_t unixTime = chrono::duration_cast<chrono::seconds>(now.time_since_epoch()).count();
	int64_t currentStep = unixTime / _settings.totpPeriod;

	// Validate with window +-1
	string inputCode = Convert::ToString(totpCode);

	for (int offset = -1; offset <= 1; offset++)
	{
		string expected = ComputeTotp(secret, currentStep + offset, _settings.totpDigits, _settings.totpAlgorithm);
		if (expected == inputCode)
		{
			PIDebug("Offline TOTP validation successful for " + user->accountName + " (offset=" + to_string(offset) + ")");
			result.success = true;
			ClearFailures(user->accountName);
			return S_OK;
		}
	}

	// Invalid code
	PIDebug("Offline TOTP validation failed for " + user->accountName);
	RecordFailure(user->accountName);
	result.failReason = "INVALID_TOTP";
	result.errorMessage = "Codigo TOTP invalido.";
	return OFFLINE_TOTP_INVALID_CODE;
}

void OfflineTotpCache::WriteOfflineEvent(const std::string& alias, bool success, const std::string& failReason)
{
	try
	{
		// Get current time as ISO 8601
		auto now = chrono::system_clock::now();
		time_t t = chrono::system_clock::to_time_t(now);
		tm utcTm;
		gmtime_s(&utcTm, &t);
		char timeBuf[64];
		strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", &utcTm);

		// Get hostname
		wchar_t hostBuf[MAX_COMPUTERNAME_LENGTH + 1] = {};
		DWORD hostLen = MAX_COMPUTERNAME_LENGTH + 1;
		GetComputerNameW(hostBuf, &hostLen);
		string hostname = Convert::ToString(wstring(hostBuf));

		string ip = GetLocalIp();

		json evt;
		evt["alias"] = alias;
		evt["success"] = success;
		evt["timestamp"] = string(timeBuf);
		evt["hostname"] = hostname;
		evt["ipAddress"] = ip;
		evt["agentType"] = "CP";
		if (!failReason.empty())
			evt["failReason"] = failReason;

		// Write to unique file in events directory
		wstring eventsDir(EVENTS_DIR);
		CreateDirectoryW(eventsDir.c_str(), NULL);

		int64_t ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
		wstring fileName = eventsDir + L"\\evt_" + to_wstring(ms) + L".json";

		string jsonStr = evt.dump();
		HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD written;
			WriteFile(hFile, jsonStr.c_str(), (DWORD)jsonStr.size(), &written, NULL);
			CloseHandle(hFile);
		}
	}
	catch (const exception& e)
	{
		PIError(string("Failed to write offline event: ") + e.what());
	}
}

void OfflineTotpCache::WriteOfflineSession(const std::string& userId, const std::string& accountName, const std::string& clientIp)
{
	try
	{
		auto now = chrono::system_clock::now();
		time_t t = chrono::system_clock::to_time_t(now);
		tm utcTm;
		gmtime_s(&utcTm, &t);
		char timeBuf[64];
		strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%dT%H:%M:%SZ", &utcTm);

		json session;
		session["userId"] = userId;
		session["accountName"] = accountName;
		session["clientIp"] = clientIp;
		session["timestamp"] = string(timeBuf);

		wstring sessDir(SESSIONS_DIR);
		CreateDirectoryW(sessDir.c_str(), NULL);

		int64_t ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
		wstring fileName = sessDir + L"\\sess_" + to_wstring(ms) + L".json";

		string jsonStr = session.dump();
		HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD written;
			WriteFile(hFile, jsonStr.c_str(), (DWORD)jsonStr.size(), &written, NULL);
			CloseHandle(hFile);
		}
	}
	catch (const exception& e)
	{
		PIError(string("Failed to write offline session: ") + e.what());
	}
}

HRESULT OfflineTotpCache::EvaluateMobilityPolicies(const std::string& userId, const std::string& hostname, const std::string& clientIp)
{
	if (_mobilityPolicies.empty()) return S_OK;

	// Find user tags
	vector<string> userTags;
	for (const auto& u : _users)
	{
		if (_stricmp(u.userId.c_str(), userId.c_str()) == 0)
		{
			userTags = u.tagIds;
			break;
		}
	}

	// Get current time for active policy check
	time_t now = time(nullptr);
	tm localTm;
	localtime_s(&localTm, &now);

	// Sort policies by priority
	vector<const CachedMobilityPolicy*> sorted;
	for (const auto& p : _mobilityPolicies) sorted.push_back(&p);
	sort(sorted.begin(), sorted.end(), [](const CachedMobilityPolicy* a, const CachedMobilityPolicy* b) {
		return a->priority < b->priority;
	});

	// Check DENY policies first
	for (const auto* policy : sorted)
	{
		if (policy->action != "DENY") continue;
		// Check if active... (simplified: skip date/time checks for now in C++ offline, full logic in C# service)

		// Check match
		bool matched = false;
		if (policy->type == "USER")
		{
			for (const auto& uid : policy->userIds)
				if (_stricmp(uid.c_str(), userId.c_str()) == 0) { matched = true; break; }
			if (!matched)
			{
				for (const auto& tagId : policy->userTagIds)
					for (const auto& userTag : userTags)
						if (_stricmp(tagId.c_str(), userTag.c_str()) == 0) { matched = true; break; }
			}
		}
		else if (policy->type == "ENDPOINT")
		{
			for (const auto& h : policy->endpointHostnames)
				if (_stricmp(h.c_str(), hostname.c_str()) == 0) { matched = true; break; }
		}

		if (matched)
		{
			PIError("Mobility policy DENY matched: #" + to_string(policy->policyNumber) + " " + policy->name);
			return OFFLINE_TOTP_MOBILITY_DENIED;
		}
	}

	return S_OK;
}

// ============ Private methods ============

bool OfflineTotpCache::DecryptDPAPI(const std::vector<BYTE>& encrypted, std::string& plaintext)
{
	DATA_BLOB input;
	input.pbData = const_cast<BYTE*>(encrypted.data());
	input.cbData = (DWORD)encrypted.size();

	DATA_BLOB output = { 0 };

	// CRYPTPROTECT_LOCAL_MACHINE scope (matches DataProtectionScope.LocalMachine in C#)
	if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &output))
	{
		PIError("CryptUnprotectData failed: " + to_string(GetLastError()));
		return false;
	}

	plaintext.assign(reinterpret_cast<char*>(output.pbData), output.cbData);
	LocalFree(output.pbData);
	return true;
}

std::vector<BYTE> OfflineTotpCache::Base32Decode(const std::string& base32)
{
	static const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	vector<BYTE> result;

	string input;
	for (char c : base32)
	{
		if (c == '=' || c == ' ') continue;
		input += (char)toupper(c);
	}

	int bits = 0;
	int value = 0;

	for (char c : input)
	{
		size_t idx = alphabet.find(c);
		if (idx == string::npos) continue;

		value = (value << 5) | (int)idx;
		bits += 5;

		if (bits >= 8)
		{
			bits -= 8;
			result.push_back((BYTE)((value >> bits) & 0xFF));
		}
	}

	return result;
}

std::string OfflineTotpCache::ComputeTotp(const std::vector<BYTE>& secret, int64_t timeStep, int digits, const std::string& algorithm)
{
	// Convert time step to 8-byte big-endian
	vector<BYTE> message(8);
	for (int i = 7; i >= 0; i--)
	{
		message[i] = (BYTE)(timeStep & 0xFF);
		timeStep >>= 8;
	}

	// Compute HMAC
	vector<BYTE> hmac = HmacSha(algorithm, secret, message);
	if (hmac.empty()) return "";

	// Dynamic truncation (RFC 4226 / 6238)
	int offset = hmac.back() & 0x0F;
	uint32_t binary =
		((uint32_t)(hmac[offset] & 0x7F) << 24) |
		((uint32_t)(hmac[offset + 1] & 0xFF) << 16) |
		((uint32_t)(hmac[offset + 2] & 0xFF) << 8) |
		((uint32_t)(hmac[offset + 3] & 0xFF));

	// Modulo 10^digits
	uint32_t modulo = 1;
	for (int i = 0; i < digits; i++) modulo *= 10;
	uint32_t otp = binary % modulo;

	// Pad with leading zeros
	ostringstream oss;
	oss << setfill('0') << setw(digits) << otp;
	return oss.str();
}

std::vector<BYTE> OfflineTotpCache::HmacSha(const std::string& algorithm, const std::vector<BYTE>& key, const std::vector<BYTE>& message)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	vector<BYTE> result;

	LPCWSTR algId = BCRYPT_SHA1_ALGORITHM;
	if (algorithm == "SHA256") algId = BCRYPT_SHA256_ALGORITHM;
	else if (algorithm == "SHA512") algId = BCRYPT_SHA512_ALGORITHM;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algId, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!BCRYPT_SUCCESS(status))
	{
		PIError("BCryptOpenAlgorithmProvider failed: " + to_string(status));
		return result;
	}

	// Get hash size
	DWORD hashLength = 0;
	DWORD cbData = 0;
	BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &cbData, 0);

	result.resize(hashLength);

	status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
	if (!BCRYPT_SUCCESS(status))
	{
		PIError("BCryptCreateHash failed: " + to_string(status));
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return {};
	}

	status = BCryptHashData(hHash, (PUCHAR)message.data(), (ULONG)message.size(), 0);
	if (!BCRYPT_SUCCESS(status))
	{
		PIError("BCryptHashData failed: " + to_string(status));
		BCryptDestroyHash(hHash);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		return {};
	}

	status = BCryptFinishHash(hHash, result.data(), (ULONG)result.size(), 0);
	if (!BCRYPT_SUCCESS(status))
	{
		PIError("BCryptFinishHash failed: " + to_string(status));
		result.clear();
	}

	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return result;
}

const CachedUser* OfflineTotpCache::FindUser(const std::string& username) const
{
	for (const auto& user : _users)
	{
		if (_stricmp(user.accountName.c_str(), username.c_str()) == 0)
			return &user;

		for (const auto& alias : user.aliases)
		{
			if (_stricmp(alias.c_str(), username.c_str()) == 0)
				return &user;
		}
	}
	return nullptr;
}

bool OfflineTotpCache::IsLockedOut(const std::string& accountName) const
{
	auto it = _lockouts.find(accountName);
	if (it == _lockouts.end()) return false;

	if (it->second.failCount < _settings.bruteForceLimitOffline) return false;

	int64_t now = (int64_t)time(nullptr);
	int64_t lockoutEnd = it->second.lastFailTimestamp + (_settings.lockoutMinutesOffline * 60);
	return now < lockoutEnd;
}

void OfflineTotpCache::RecordFailure(const std::string& accountName)
{
	auto& state = _lockouts[accountName];
	state.failCount++;
	state.lastFailTimestamp = (int64_t)time(nullptr);
	SaveLockouts();
}

void OfflineTotpCache::ClearFailures(const std::string& accountName)
{
	_lockouts.erase(accountName);
	SaveLockouts();
}

void OfflineTotpCache::LoadLockouts()
{
	try
	{
		wstring filePath(LOCKOUT_FILE);
		ifstream file(filePath);
		if (!file.is_open()) return;

		string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
		file.close();

		auto j = json::parse(content);
		_lockouts.clear();
		for (auto& [key, val] : j.items())
		{
			LockoutState state;
			state.failCount = val.value("failCount", 0);
			state.lastFailTimestamp = val.value("lastFailTimestamp", (int64_t)0);
			_lockouts[key] = state;
		}
	}
	catch (...) {}
}

void OfflineTotpCache::SaveLockouts()
{
	try
	{
		json j;
		for (const auto& [key, state] : _lockouts)
		{
			j[key] = {
				{"failCount", state.failCount},
				{"lastFailTimestamp", state.lastFailTimestamp}
			};
		}

		wstring filePath(LOCKOUT_FILE);
		ofstream file(filePath);
		if (file.is_open())
		{
			file << j.dump();
			file.close();
		}
	}
	catch (...) {}
}

std::string OfflineTotpCache::GetLocalIp()
{
	string result = "0.0.0.0";
	try
	{
		ULONG bufSize = 0;
		GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &bufSize);
		vector<BYTE> buf(bufSize);
		auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

		if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &bufSize) == NO_ERROR)
		{
			for (auto* adapter = addrs; adapter; adapter = adapter->Next)
			{
				if (adapter->OperStatus != IfOperStatusUp) continue;
				if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

				for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next)
				{
					if (unicast->Address.lpSockaddr->sa_family == AF_INET)
					{
						char ipBuf[INET_ADDRSTRLEN];
						auto* sin = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
						inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
						return string(ipBuf);
					}
				}
			}
		}
	}
	catch (...) {}
	return result;
}
