#include "pch.h"
#include "SettingsWnd.h"

#include <sniffer/Config.h>
#include <sniffer/packet/PacketManager.h>

namespace sniffer::gui
{
	SettingsWnd::SettingsWnd()
	{ }

	SettingsWnd& SettingsWnd::instance()
	{
		static SettingsWnd instance;
		return instance;
	}

	void SettingsWnd::Draw()
	{
		auto& config = Config::instance();

		if (ImGui::BeginGroupPanel("Packet"))
		{
			static bool shouldConnect = true;
			const bool isConnecting = shouldConnect && !packet::PacketManager::IsConnected();
			const char* connectText = isConnecting ? "Connecting..." : (shouldConnect ? "Disconnect Pipe" : "Connect Pipe");

			if (isConnecting)
				ImGui::BeginDisabled();

			if (ImGui::Button(connectText))
			{
				shouldConnect = !shouldConnect;
				packet::PacketManager::UpdateConnection(shouldConnect);
			}

			if (isConnecting)
				ImGui::EndDisabled();

			ConfigWidget(config.f_PacketLevelFilter, "Filtering will be executed on the packet level,\nso packets will not be saved if they don't pass filter conditions."
				"\nFiltered packets will not be passed to modify scripts.\nIt helps reduce memory consumption.");

			if (config.f_PacketLevelFilter)
				ImGui::BeginDisabled();

			ConfigWidget(config.f_PassThroughMode, "If enabled, packets will pass filters but won't save.\nNot compatible with packet level filter."
				"\nModify scripts will also be ignored.\nUseful for filter script logging without eating too much memory.");

			if (config.f_PacketLevelFilter)
				ImGui::EndDisabled();

			ConfigWidget(config.f_ShowUnknownPackets, "Show unknown packets in capture list.");
		}
		ImGui::EndGroupPanel();

		if (ImGui::BeginGroupPanel("Display"))
		{
			ConfigWidget(config.f_ShowUnknownFields, "Show unknown fields in packet view.");
			ConfigWidget(config.f_ShowUnsettedFields, "Show fields with missing data in packet view.");
			ConfigWidget(config.f_ScrollFollowing, "Follow items when new data appears above the scroll region.");
			ConfigWidget(config.f_HighlightRelativities, "Highlight packet relativities in capture list.");
		}
		ImGui::EndGroupPanel();

		if (ImGui::BeginGroupPanel("Proto"))
		{
			ConfigWidget(config.f_ProtoIDMode, "The mode for searching id's for .proto");

			static bool isChanging = false;
			static std::string protoDirPathTemp = config.f_ProtoDirPath;
			static std::string protoIDsPathTemp = config.f_ProtoIDsPath;

			if (!isChanging)
				ImGui::BeginDisabled();

			ImGui::InputText("Proto dir", &protoDirPathTemp);

			if (config.f_ProtoIDMode.value() == Config::ProtoIDMode::SeparateFile)
				ImGui::InputText("Proto IDs", &protoIDsPathTemp);

			if (!isChanging)
				ImGui::EndDisabled();

			if (isChanging)
			{
				if (ImGui::Button("Save"))
				{
					if (protoDirPathTemp != config.f_ProtoDirPath.value() || protoIDsPathTemp != config.f_ProtoIDsPath.value())
					{
						config.f_ProtoDirPath = protoDirPathTemp;
						config.f_ProtoIDsPath = protoIDsPathTemp;
					}
					isChanging = false;
				}

				if (ImGui::Button("Cancel"))
				{
					protoDirPathTemp = config.f_ProtoDirPath;
					protoIDsPathTemp = config.f_ProtoIDsPath;
					isChanging = false;
				}
			}
			else
			{
				if (ImGui::Button("Change"))
				{
					isChanging = true;
				}
			}
		}
		ImGui::EndGroupPanel();
	}

	WndInfo& SettingsWnd::GetInfo()
	{
		static WndInfo info = { "Settings", true };
		return info;
	}
}