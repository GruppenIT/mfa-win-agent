/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 Gruppen it Security
** Author: Nils Behlen
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
#include <map>

/// <summary>
/// This is a subset of the configuration loaded by the application using the cpp-client.
/// These values are required for the operation of the cpp-client.
/// </summary>
struct PIConfig
{
	std::wstring hostname = L"";
	std::wstring path = L"";
	int port = 0;

	std::wstring fallbackHostname = L"";
	std::wstring fallbackPath = L"";
	int fallbackPort = 0;

	bool ignoreInvalidCN = false;
	bool ignoreUnknownCA = false;
	std::wstring userAgent = L"gruppen-mfa-cp";

	std::map<std::wstring, std::wstring> realmMap = std::map<std::wstring, std::wstring>();
	std::wstring defaultRealm = L"";
	bool logPasswords = false;
	std::wstring offlineFilePath = L"C:\\offlineFile.json";
	int offlineTryWindow = 10;
	bool sendUPN = false;
	
	// optionals
	int resolveTimeout = 0; // = infinite
	int connectTimeout = 60000;
	int sendTimeout = 30000;
	int receiveTimeout = 30000;

	// Can be "system" or a valid language code like "en-US" or "de-DE"
	// If format is wrong, use system
	std::string acceptLanguage = "system";

	// GruppenMFA Agent Management
	std::wstring serverUrl = L"";		// Full management server URL (e.g. "https://mfa.empresa.com.br")
	std::wstring apiKey = L"";			// API Key for backend auth (X-API-Key: mfa_xxxxx)
	int pollingIntervalSeconds = 120;	// Checkin/polling interval (default 2 min)
	std::string configHash = "";		// Config hash from last checkin (for change detection)

	// Offline MFA settings (synced from server config via registry)
	bool offlineMfaEnabled = false;
	int offlineCacheTtlDays = 7;
	int offlineMaxCachedUsers = 200;
	int offlineBruteForceLimit = 3;
	int offlineLockoutMinutes = 30;
	int offlineRequireOnlineDays = 30;
	int offlineOnTheFlyGraceSeconds = 60;
};
