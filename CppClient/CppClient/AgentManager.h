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
#pragma once

#include "PIConfig.h"
#include "Endpoint.h"
#include <string>
#include <atomic>
#include <thread>
#include <functional>

constexpr auto AGENT_ENDPOINT_CHECKIN = "/api/agents/checkin";
constexpr auto AGENT_ENDPOINT_CONFIG = "/api/agents/config";
constexpr auto AGENT_ENDPOINT_CONFIG_ACK = "/api/agents/config/ack";

/// <summary>
/// Manages agent lifecycle with the GruppenMFA backend:
/// - Checkin on startup and periodically (every 2 min)
/// - Configuration download and apply when configHash changes
/// - Configuration ACK after successful apply
/// </summary>
class AgentManager
{
public:
	AgentManager(PIConfig& config);
	~AgentManager();

	AgentManager(const AgentManager&) = delete;
	AgentManager& operator=(const AgentManager&) = delete;

	/// <summary>
	/// Send a checkin to the backend. Returns the configHash from the response.
	/// </summary>
	/// <param name="outConfigHash">Receives the configHash from the server</param>
	/// <returns>true if checkin succeeded</returns>
	bool Checkin(std::string& outConfigHash);

	/// <summary>
	/// Fetch configuration from the backend and apply it to the registry.
	/// </summary>
	/// <param name="outConfigHash">Receives the configHash from the config response</param>
	/// <returns>true if config was fetched and applied</returns>
	bool FetchAndApplyConfig(std::string& outConfigHash);

	/// <summary>
	/// Send a config ACK to the backend to confirm config was applied.
	/// </summary>
	/// <param name="configHash">The configHash to acknowledge</param>
	/// <returns>true if ACK succeeded</returns>
	bool AckConfig(const std::string& configHash);

	/// <summary>
	/// Start the background polling thread (checkin + config refresh every 2 min).
	/// </summary>
	void StartPollingThread();

	/// <summary>
	/// Stop the background polling thread.
	/// </summary>
	void StopPollingThread();

	/// <summary>
	/// Run initial startup tasks: checkin, fetch config if needed, ack, start polling.
	/// </summary>
	void OnStartup();

private:
	void PollingLoop();

	std::string BuildCheckinBody();

	std::string GetOSVersion();
	std::string GetHostname();
	std::string GetAgentVersion();

	PIConfig& _config;
	Endpoint _endpoint;
	std::atomic<bool> _runPolling{ false };
	std::thread _pollingThread;
	std::string _lastConfigHash;
};
