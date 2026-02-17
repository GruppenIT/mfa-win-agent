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

constexpr auto AGENT_ENDPOINT_REGISTER = "/api/agents/register";
constexpr auto AGENT_ENDPOINT_HEARTBEAT_PREFIX = "/api/agents/";
constexpr auto AGENT_ENDPOINT_HEARTBEAT_SUFFIX = "/heartbeat";
constexpr auto AGENT_ENDPOINT_CONFIG_PREFIX = "/api/agents/";
constexpr auto AGENT_ENDPOINT_CONFIG_SUFFIX = "/config";

/// <summary>
/// Manages agent lifecycle with the GruppenMFA backend:
/// - Registration on startup
/// - Periodic heartbeat
/// - Configuration/policy sync
/// </summary>
class AgentManager
{
public:
	AgentManager(PIConfig& config);
	~AgentManager();

	AgentManager(const AgentManager&) = delete;
	AgentManager& operator=(const AgentManager&) = delete;

	/// <summary>
	/// Register this agent with the backend. Stores agentId in registry on success.
	/// </summary>
	/// <returns>true if registration succeeded</returns>
	bool RegisterAgent();

	/// <summary>
	/// Send a heartbeat to the backend.
	/// </summary>
	/// <returns>true if heartbeat succeeded</returns>
	bool SendHeartbeat();

	/// <summary>
	/// Fetch configuration/policy from the backend and apply it.
	/// </summary>
	/// <returns>true if config sync succeeded</returns>
	bool SyncConfig();

	/// <summary>
	/// Start the background heartbeat thread.
	/// </summary>
	void StartHeartbeatThread();

	/// <summary>
	/// Stop the background heartbeat thread.
	/// </summary>
	void StopHeartbeatThread();

	/// <summary>
	/// Run initial startup tasks: register (if needed), sync config, start heartbeat.
	/// </summary>
	void OnStartup();

private:
	void HeartbeatLoop();

	std::string BuildRegisterBody();
	std::string BuildHeartbeatBody();

	std::string GetOSVersion();
	std::string GetHostname();
	std::string GetAgentVersion();

	PIConfig& _config;
	Endpoint _endpoint;
	std::atomic<bool> _runHeartbeat{ false };
	std::thread _heartbeatThread;
};
