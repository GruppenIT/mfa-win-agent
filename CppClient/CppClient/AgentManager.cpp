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
	StopHeartbeatThread();
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
	// Extract version from userAgent string: "mfa-zerobox-cp/X.Y.Z.W [Windows/...]"
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

// Send a JSON request to the backend, returning the response body.
// This is a simplified version of Endpoint::SendRequest that sends JSON instead of form data.
static string SendJsonRequest(
	const PIConfig& config,
	const wstring& fullPath,
	const string& jsonBody,
	const string& method,
	const string& authToken = "")
{
	PIDebug("AgentManager::SendJsonRequest to " + Convert::ToString(fullPath) + " method=" + method);

	wstring wHostname = config.hostname;
	int realPort = (config.port != 0) ? config.port : INTERNET_DEFAULT_HTTPS_PORT;

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

	// Add Authorization header if we have an API key
	if (!authToken.empty())
	{
		wstring authHeader = L"Authorization: Bearer " + Convert::ToWString(authToken);
		WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
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

std::string AgentManager::BuildRegisterBody()
{
	json body;
	body["hostname"] = GetHostname();
	body["osType"] = "Windows";
	body["osVersion"] = GetOSVersion();
	body["agentVersion"] = GetAgentVersion();
	body["agentType"] = "CP";
	return body.dump();
}

std::string AgentManager::BuildHeartbeatBody()
{
	json body;
	body["status"] = "online";

	// Calculate uptime using GetTickCount64
	ULONGLONG uptimeMs = GetTickCount64();
	body["uptimeSeconds"] = uptimeMs / 1000;

	json systemInfo;
	systemInfo["osVersion"] = GetOSVersion();
	systemInfo["agentVersion"] = GetAgentVersion();
	systemInfo["hostname"] = GetHostname();
	body["systemInfo"] = systemInfo;

	return body.dump();
}

bool AgentManager::RegisterAgent()
{
	PIDebug("AgentManager::RegisterAgent");

	if (_config.apiKey.empty())
	{
		PIError("AgentManager: Cannot register - no API key configured");
		return false;
	}

	// If we already have an agentId, skip registration
	if (!_config.agentId.empty())
	{
		PIDebug("AgentManager: Agent already registered with ID: " + Convert::ToString(_config.agentId));
		return true;
	}

	string jsonBody = BuildRegisterBody();
	PIDebug("AgentManager: Registration body: " + jsonBody);

	wstring path = Convert::ToWString(Convert::ToString(_config.path) + string(AGENT_ENDPOINT_REGISTER));
	string apiKeyStr = Convert::ToString(_config.apiKey);

	string response = SendJsonRequest(_config, path, jsonBody, "POST", apiKeyStr);

	if (response.empty())
	{
		PIError("AgentManager: Registration failed - empty response");
		return false;
	}

	try
	{
		json resp = json::parse(response);

		// Check for agentId in response (backend returns { agentId: "..." } or { data: { id: "..." } })
		string agentId;
		if (resp.contains("agentId"))
		{
			agentId = resp["agentId"].get<string>();
		}
		else if (resp.contains("data") && resp["data"].contains("id"))
		{
			agentId = resp["data"]["id"].get<string>();
		}
		else if (resp.contains("id"))
		{
			agentId = resp["id"].get<string>();
		}

		if (!agentId.empty())
		{
			_config.agentId = Convert::ToWString(agentId);
			PIDebug("AgentManager: Registered successfully with agentId: " + agentId);

			// Store agentId in registry
			RegistryReader rr(CONFIG_REGISTRY_PATH);
			if (!rr.SetWString(L"agent_id", _config.agentId))
			{
				PIError("AgentManager: Failed to store agentId in registry");
			}
			return true;
		}
		else
		{
			PIError("AgentManager: Registration response missing agentId");
			return false;
		}
	}
	catch (const json::exception& e)
	{
		PIError("AgentManager: Failed to parse registration response: " + string(e.what()));
		return false;
	}
}

bool AgentManager::SendHeartbeat()
{
	if (_config.agentId.empty())
	{
		PIDebug("AgentManager: Cannot send heartbeat - no agentId");
		return false;
	}

	if (_config.apiKey.empty())
	{
		PIDebug("AgentManager: Cannot send heartbeat - no API key");
		return false;
	}

	string agentId = Convert::ToString(_config.agentId);
	string endpoint = string(AGENT_ENDPOINT_HEARTBEAT_PREFIX) + agentId + string(AGENT_ENDPOINT_HEARTBEAT_SUFFIX);
	wstring path = Convert::ToWString(Convert::ToString(_config.path) + endpoint);
	string apiKeyStr = Convert::ToString(_config.apiKey);

	string jsonBody = BuildHeartbeatBody();
	string response = SendJsonRequest(_config, path, jsonBody, "POST", apiKeyStr);

	if (response.empty())
	{
		PIError("AgentManager: Heartbeat failed - empty response");
		return false;
	}

	PIDebug("AgentManager: Heartbeat sent successfully");
	return true;
}

bool AgentManager::SyncConfig()
{
	if (_config.agentId.empty())
	{
		PIDebug("AgentManager: Cannot sync config - no agentId");
		return false;
	}

	if (_config.apiKey.empty())
	{
		PIDebug("AgentManager: Cannot sync config - no API key");
		return false;
	}

	string agentId = Convert::ToString(_config.agentId);
	string endpoint = string(AGENT_ENDPOINT_CONFIG_PREFIX) + agentId + string(AGENT_ENDPOINT_CONFIG_SUFFIX);
	wstring path = Convert::ToWString(Convert::ToString(_config.path) + endpoint);
	string apiKeyStr = Convert::ToString(_config.apiKey);

	string response = SendJsonRequest(_config, path, "", "GET", apiKeyStr);

	if (response.empty())
	{
		PIError("AgentManager: Config sync failed - empty response");
		return false;
	}

	try
	{
		json resp = json::parse(response);

		// Extract config data — the backend returns CpConfigPolicy fields
		json configData;
		if (resp.contains("data"))
		{
			configData = resp["data"];
		}
		else
		{
			configData = resp;
		}

		// Check configVersion to see if we need to update
		string newVersion;
		if (configData.contains("configVersion"))
		{
			newVersion = configData["configVersion"].get<string>();
		}
		else if (configData.contains("version"))
		{
			newVersion = configData["version"].get<string>();
		}

		string currentVersion = Convert::ToString(_config.configVersion);
		if (!newVersion.empty() && newVersion == currentVersion)
		{
			PIDebug("AgentManager: Config is up to date (version: " + currentVersion + ")");
			return true;
		}

		RegistryReader rr(CONFIG_REGISTRY_PATH);

		// Apply config fields from the policy if they exist
		// These override local registry values when policy is set
		if (configData.contains("hostname"))
		{
			wstring val = Convert::ToWString(configData["hostname"].get<string>());
			rr.SetWString(L"hostname", val);
		}

		if (configData.contains("heartbeatInterval"))
		{
			int interval = configData["heartbeatInterval"].get<int>();
			_config.heartbeatIntervalSeconds = interval;
			rr.SetWString(L"heartbeat_interval", to_wstring(interval));
		}

		// Store the new config version
		if (!newVersion.empty())
		{
			_config.configVersion = Convert::ToWString(newVersion);
			rr.SetWString(L"config_version", _config.configVersion);
		}

		PIDebug("AgentManager: Config synced successfully" +
			(newVersion.empty() ? "" : " (version: " + newVersion + ")"));
		return true;
	}
	catch (const json::exception& e)
	{
		PIError("AgentManager: Failed to parse config response: " + string(e.what()));
		return false;
	}
}

void AgentManager::HeartbeatLoop()
{
	PIDebug("AgentManager: Heartbeat thread started (interval: " + to_string(_config.heartbeatIntervalSeconds) + "s)");

	while (_runHeartbeat.load())
	{
		// Sleep in small increments so we can stop quickly
		int totalSleepMs = _config.heartbeatIntervalSeconds * 1000;
		int sleptMs = 0;
		while (sleptMs < totalSleepMs && _runHeartbeat.load())
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			sleptMs += 1000;
		}

		if (!_runHeartbeat.load()) break;

		SendHeartbeat();
	}

	PIDebug("AgentManager: Heartbeat thread stopped");
}

void AgentManager::StartHeartbeatThread()
{
	if (_runHeartbeat.load())
	{
		PIDebug("AgentManager: Heartbeat thread already running");
		return;
	}

	_runHeartbeat.store(true);
	_heartbeatThread = std::thread(&AgentManager::HeartbeatLoop, this);
	_heartbeatThread.detach();
}

void AgentManager::StopHeartbeatThread()
{
	PIDebug("AgentManager: Stopping heartbeat thread...");
	_runHeartbeat.store(false);
}

void AgentManager::OnStartup()
{
	PIDebug("AgentManager::OnStartup");

	if (_config.apiKey.empty())
	{
		PIDebug("AgentManager: No API key configured, skipping agent management");
		return;
	}

	// Step 1: Register if needed
	if (_config.agentId.empty())
	{
		if (!RegisterAgent())
		{
			PIError("AgentManager: Registration failed, will retry on next startup");
			return;
		}
	}

	// Step 2: Sync config
	SyncConfig();

	// Step 3: Send initial heartbeat
	SendHeartbeat();

	// Step 4: Start periodic heartbeat
	StartHeartbeatThread();
}
