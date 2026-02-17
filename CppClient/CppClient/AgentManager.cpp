/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2026 Gruppen IT
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

#include "AgentManager.h"
#include "Logger.h"
#include "Convert.h"
#include "RegistryReader.h"
#include "nlohmann/json.hpp"
#include <winhttp.h>
#include <chrono>

#pragma comment(lib, "winhttp.lib")

using namespace std;
using json = nlohmann::json;

AgentManager::AgentManager(PIConfig& config)
	: _config(config), _endpoint(config)
{
}

AgentManager::~AgentManager()
{
	StopPollingThread();
}

std::string AgentManager::GetHostname()
{
	WCHAR wsz[256];
	DWORD cch = ARRAYSIZE(wsz);
	if (GetComputerNameW(wsz, &cch))
	{
		return Convert::ToString(wstring(wsz, cch));
	}
	return "unknown";
}

std::string AgentManager::GetOSVersion()
{
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);
	return to_string(info.dwMajorVersion) + "." + to_string(info.dwMinorVersion) + "." + to_string(info.dwBuildNumber);
}

std::string AgentManager::GetAgentVersion()
{
	// Extract version from userAgent string: "gruppen-mfa-cp/X.Y.Z.W [Windows/...]"
	string ua = Convert::ToString(_config.userAgent);
	size_t slashPos = ua.find('/');
	if (slashPos != string::npos)
	{
		size_t spacePos = ua.find(' ', slashPos);
		if (spacePos != string::npos)
			return ua.substr(slashPos + 1, spacePos - slashPos - 1);
		else
			return ua.substr(slashPos + 1);
	}
	return "unknown";
}

// Parse serverUrl into hostname, port.
// serverUrl format: "https://mfa.empresa.com.br" or "https://mfa.empresa.com.br:10999"
static void ParseServerUrl(const wstring& serverUrl, wstring& outHostname, int& outPort)
{
	wstring url = serverUrl;

	// Strip protocol prefix
	if (url.find(L"https://") == 0) url = url.substr(8);
	else if (url.find(L"http://") == 0) url = url.substr(7);

	// Strip trailing slash
	if (!url.empty() && url.back() == L'/') url.pop_back();

	// Check for port
	size_t colonPos = url.find(L':');
	if (colonPos != wstring::npos)
	{
		outHostname = url.substr(0, colonPos);
		outPort = _wtoi(url.substr(colonPos + 1).c_str());
	}
	else
	{
		outHostname = url;
		outPort = INTERNET_DEFAULT_HTTPS_PORT;
	}
}

// Send a JSON request to the backend using X-API-Key auth, returning the response body.
static string SendJsonRequest(
	const PIConfig& config,
	const wstring& fullPath,
	const string& jsonBody,
	const string& method)
{
	PIDebug("AgentManager::SendJsonRequest to " + Convert::ToString(fullPath) + " method=" + method);

	wstring wHostname;
	int realPort = INTERNET_DEFAULT_HTTPS_PORT;

	// Use serverUrl for management API calls
	if (!config.serverUrl.empty())
	{
		ParseServerUrl(config.serverUrl, wHostname, realPort);
	}
	else
	{
		// Fallback to hostname/port from config
		wHostname = config.hostname;
		realPort = (config.port != 0) ? config.port : INTERNET_DEFAULT_HTTPS_PORT;
	}

	DWORD dwAccessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;

	HINTERNET hSession = WinHttpOpen(
		config.userAgent.c_str(),
		dwAccessType,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (!hSession)
	{
		PIError("AgentManager: WinHttpOpen failure: " + to_string(GetLastError()));
		return "";
	}

	HINTERNET hConnect = WinHttpConnect(hSession, wHostname.c_str(), (INTERNET_PORT)realPort, 0);
	if (!hConnect)
	{
		PIError("AgentManager: WinHttpConnect failure: " + to_string(GetLastError()));
		WinHttpCloseHandle(hSession);
		return "";
	}

	wstring wMethod = Convert::ToWString(method);
	HINTERNET hRequest = WinHttpOpenRequest(
		hConnect, wMethod.c_str(), fullPath.c_str(),
		NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

	if (!hRequest)
	{
		PIError("AgentManager: WinHttpOpenRequest failure: " + to_string(GetLastError()));
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return "";
	}

	// Set SSL flags
	DWORD dwReqOpts = 0;
	WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwReqOpts, sizeof(DWORD));

	DWORD dwSSLFlags = 0;
	if (config.ignoreUnknownCA)
		dwSSLFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	if (config.ignoreInvalidCN)
		dwSSLFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
	if (dwSSLFlags)
		WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSSLFlags, sizeof(DWORD));

	// Set timeouts
	WinHttpSetTimeouts(hRequest, config.resolveTimeout, config.connectTimeout, config.sendTimeout, config.receiveTimeout);

	// Add User-Agent header
	wstring userAgent = L"User-Agent: " + config.userAgent;
	WinHttpAddRequestHeaders(hRequest, userAgent.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

	// Add X-API-Key header for authentication
	if (!config.apiKey.empty())
	{
		wstring apiKeyHeader = L"X-API-Key: " + config.apiKey;
		WinHttpAddRequestHeaders(hRequest, apiKeyHeader.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
	}

	// Send the request with JSON body
	LPCWSTR contentType = L"Content-Type: application/json\r\n";
	LPSTR data = nullptr;
	DWORD dataLen = 0;

	if (!jsonBody.empty())
	{
		data = _strdup(jsonBody.c_str());
		dataLen = (DWORD)jsonBody.size();
	}

	BOOL bResults = WinHttpSendRequest(
		hRequest,
		contentType,
		(DWORD)-1,
		(LPVOID)data,
		dataLen,
		dataLen,
		0);

	if (!bResults)
	{
		PIError("AgentManager: WinHttpSendRequest failure: " + to_string(GetLastError()));
		if (data) { SecureZeroMemory(data, dataLen); free(data); }
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return "";
	}

	bResults = WinHttpReceiveResponse(hRequest, NULL);

	string response;
	if (bResults)
	{
		DWORD dwSize = 0;
		do
		{
			dwSize = 0;
			WinHttpQueryDataAvailable(hRequest, &dwSize);
			if (dwSize == 0) break;

			char* pszOutBuffer = new char[(size_t)dwSize + 1];
			ZeroMemory(pszOutBuffer, (size_t)dwSize + 1);

			DWORD dwDownloaded = 0;
			WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded);
			response += string(pszOutBuffer);
			delete[] pszOutBuffer;
		} while (dwSize > 0);
	}

	if (data) { SecureZeroMemory(data, dataLen); free(data); }
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	PIDebug("AgentManager response: " + (response.empty() ? "(empty)" : response.substr(0, 500)));
	return response;
}

std::string AgentManager::BuildCheckinBody()
{
	json body;
	body["hostname"] = GetHostname();
	body["agentType"] = "CP";
	body["osVersion"] = GetOSVersion();
	body["agentVersion"] = GetAgentVersion();
	return body.dump();
}

bool AgentManager::Checkin(std::string& outConfigHash)
{
	PIDebug("AgentManager::Checkin");

	if (_config.apiKey.empty())
	{
		PIError("AgentManager: Cannot checkin - no API key configured");
		return false;
	}

	string jsonBody = BuildCheckinBody();
	PIDebug("AgentManager: Checkin body: " + jsonBody);

	wstring path = Convert::ToWString(string(AGENT_ENDPOINT_CHECKIN));

	string response = SendJsonRequest(_config, path, jsonBody, "POST");

	if (response.empty())
	{
		PIError("AgentManager: Checkin failed - empty response");
		return false;
	}

	try
	{
		json resp = json::parse(response);

		// Parse response: { "id": "...", "status": "ok", "configHash": "..." }
		if (resp.contains("configHash") && !resp["configHash"].is_null())
		{
			outConfigHash = resp["configHash"].get<string>();
		}

		string status = resp.value("status", "");
		string agentId = resp.value("id", "");
		PIDebug("AgentManager: Checkin OK - id=" + agentId + " status=" + status + " configHash=" + outConfigHash);
		return true;
	}
	catch (const json::exception& e)
	{
		PIError("AgentManager: Failed to parse checkin response: " + string(e.what()));
		return false;
	}
}

bool AgentManager::FetchAndApplyConfig(std::string& outConfigHash)
{
	PIDebug("AgentManager::FetchAndApplyConfig");

	if (_config.apiKey.empty())
	{
		PIError("AgentManager: Cannot fetch config - no API key configured");
		return false;
	}

	// Build URL: /api/agents/config?hostname=XXX&agentType=CP
	string hostname = GetHostname();
	wstring path = Convert::ToWString(
		string(AGENT_ENDPOINT_CONFIG) + "?hostname=" + hostname + "&agentType=CP");

	string response = SendJsonRequest(_config, path, "", "GET");

	if (response.empty())
	{
		PIError("AgentManager: Config fetch failed - empty response");
		return false;
	}

	try
	{
		json resp = json::parse(response);

		// Extract configHash
		if (resp.contains("configHash") && !resp["configHash"].is_null())
		{
			outConfigHash = resp["configHash"].get<string>();
		}

		// Extract config object
		if (!resp.contains("config") || !resp["config"].is_object())
		{
			PIError("AgentManager: Config response missing 'config' object");
			return false;
		}

		json configData = resp["config"];

		// Write config values to the CP registry
		RegistryReader rr(CONFIG_REGISTRY_PATH);

		// REG_SZ fields — only write if key is present in JSON
		if (configData.contains("hostname") && configData["hostname"].is_string())
			rr.SetWString(L"hostname", Convert::ToWString(configData["hostname"].get<string>()));

		if (configData.contains("path") && configData["path"].is_string())
			rr.SetWString(L"path", Convert::ToWString(configData["path"].get<string>()));

		if (configData.contains("default_realm") && configData["default_realm"].is_string())
			rr.SetWString(L"default_realm", Convert::ToWString(configData["default_realm"].get<string>()));

		if (configData.contains("otp_text") && configData["otp_text"].is_string())
			rr.SetWString(L"otp_text", Convert::ToWString(configData["otp_text"].get<string>()));

		if (configData.contains("excluded_account") && configData["excluded_account"].is_string())
			rr.SetWString(L"excluded_account", Convert::ToWString(configData["excluded_account"].get<string>()));

		if (configData.contains("excluded_group") && configData["excluded_group"].is_string())
			rr.SetWString(L"excluded_group", Convert::ToWString(configData["excluded_group"].get<string>()));

		// REG_DWORD fields (numbers)
		if (configData.contains("custom_port") && configData["custom_port"].is_number_integer())
			rr.SetDword(L"custom_port", (DWORD)configData["custom_port"].get<int>());

		// REG_DWORD fields (booleans: true->1, false->0)
		if (configData.contains("ssl_ignore_invalid_cn") && configData["ssl_ignore_invalid_cn"].is_boolean())
			rr.SetDword(L"ssl_ignore_invalid_cn", configData["ssl_ignore_invalid_cn"].get<bool>() ? 1 : 0);

		if (configData.contains("hide_fullname") && configData["hide_fullname"].is_boolean())
			rr.SetDword(L"hide_fullname", configData["hide_fullname"].get<bool>() ? 1 : 0);

		if (configData.contains("hide_domainname") && configData["hide_domainname"].is_boolean())
			rr.SetDword(L"hide_domainname", configData["hide_domainname"].get<bool>() ? 1 : 0);

		if (configData.contains("two_step_hide_otp") && configData["two_step_hide_otp"].is_boolean())
			rr.SetDword(L"two_step_hide_otp", configData["two_step_hide_otp"].get<bool>() ? 1 : 0);

		// Store config hash in registry
		if (!outConfigHash.empty())
		{
			rr.SetWString(L"config_hash", Convert::ToWString(outConfigHash));
		}

		// Log applied policies if present
		if (resp.contains("appliedPolicies") && resp["appliedPolicies"].is_array())
		{
			for (const auto& policy : resp["appliedPolicies"])
			{
				string policyName = policy.value("name", "unknown");
				bool isDefault = policy.value("isDefault", false);
				PIDebug("AgentManager: Applied policy: " + policyName + (isDefault ? " (default)" : ""));
			}
		}

		PIDebug("AgentManager: Config applied successfully (configHash: " + outConfigHash + ")");
		return true;
	}
	catch (const json::exception& e)
	{
		PIError("AgentManager: Failed to parse config response: " + string(e.what()));
		return false;
	}
}

bool AgentManager::AckConfig(const std::string& configHash)
{
	PIDebug("AgentManager::AckConfig");

	if (_config.apiKey.empty())
	{
		PIError("AgentManager: Cannot ack config - no API key configured");
		return false;
	}

	json body;
	body["hostname"] = GetHostname();
	body["agentType"] = "CP";
	body["configHash"] = configHash;

	wstring path = Convert::ToWString(string(AGENT_ENDPOINT_CONFIG_ACK));

	string response = SendJsonRequest(_config, path, body.dump(), "POST");

	if (response.empty())
	{
		PIError("AgentManager: Config ACK failed - empty response");
		return false;
	}

	try
	{
		json resp = json::parse(response);
		string status = resp.value("status", "");
		PIDebug("AgentManager: Config ACK response status: " + status);
		return true;
	}
	catch (const json::exception& e)
	{
		PIError("AgentManager: Failed to parse config ACK response: " + string(e.what()));
		return false;
	}
}

void AgentManager::PollingLoop()
{
	PIDebug("AgentManager: Polling thread started (interval: " + to_string(_config.pollingIntervalSeconds) + "s)");

	while (_runPolling.load())
	{
		// Sleep in small increments so we can stop quickly
		int totalSleepMs = _config.pollingIntervalSeconds * 1000;
		int sleptMs = 0;
		while (sleptMs < totalSleepMs && _runPolling.load())
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			sleptMs += 1000;
		}

		if (!_runPolling.load()) break;

		// Step 1: Checkin
		string newConfigHash;
		if (!Checkin(newConfigHash))
		{
			PIDebug("AgentManager: Polling checkin failed, will retry next cycle");
			continue;
		}

		// Step 2: Compare configHash — sync only if changed
		if (!newConfigHash.empty() && newConfigHash != _lastConfigHash)
		{
			PIDebug("AgentManager: Config hash changed (" + _lastConfigHash + " -> " + newConfigHash + "), syncing...");

			string fetchedHash;
			if (FetchAndApplyConfig(fetchedHash))
			{
				// Step 3: ACK config
				AckConfig(fetchedHash);
				_lastConfigHash = fetchedHash;
				_config.configHash = fetchedHash;
			}
		}
		else
		{
			PIDebug("AgentManager: Config is up to date");
		}
	}

	PIDebug("AgentManager: Polling thread stopped");
}

void AgentManager::StartPollingThread()
{
	if (_runPolling.load())
	{
		PIDebug("AgentManager: Polling thread already running");
		return;
	}

	_runPolling.store(true);
	_pollingThread = std::thread(&AgentManager::PollingLoop, this);
	_pollingThread.detach();
}

void AgentManager::StopPollingThread()
{
	PIDebug("AgentManager: Stopping polling thread...");
	_runPolling.store(false);
}

void AgentManager::OnStartup()
{
	PIDebug("AgentManager::OnStartup");

	if (_config.apiKey.empty())
	{
		PIDebug("AgentManager: No API key configured, skipping agent management");
		return;
	}

	// Step 1: Checkin
	string configHash;
	if (!Checkin(configHash))
	{
		PIError("AgentManager: Initial checkin failed, will retry in polling loop");
		StartPollingThread();
		return;
	}

	_lastConfigHash = _config.configHash; // Load from registry (persisted from last run)

	// Step 2: Fetch config if hash changed (or first run)
	if (!configHash.empty() && configHash != _lastConfigHash)
	{
		string fetchedHash;
		if (FetchAndApplyConfig(fetchedHash))
		{
			// Step 3: ACK config
			AckConfig(fetchedHash);
			_lastConfigHash = fetchedHash;
			_config.configHash = fetchedHash;
		}
	}
	else
	{
		_lastConfigHash = configHash;
		PIDebug("AgentManager: Config is up to date on startup");
	}

	// Step 4: Start periodic polling
	StartPollingThread();
}
