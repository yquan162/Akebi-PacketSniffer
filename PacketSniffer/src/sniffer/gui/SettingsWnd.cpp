#include "pch.h"
#include "SettingsWnd.h"

#include <sniffer/Config.h>

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

		ImGui::BeginGroupPanel("Packet");
		ConfigWidget(config.f_CapturePackets, "Manual toggle for capturing packets.");
		ConfigWidget(config.f_PacketLevelFilter, "Filtering will be executed on the packet level,\nso packets will not be saved if they don't pass filter conditions."
			"\nFiltered packets will not be passed to modify scripts.\nIt helps reduce memory consumption.");
		ConfigWidget(config.f_ShowUnknownPackets, "Show unknown packets in capture list.");
		ImGui::EndGroupPanel();

		ImGui::BeginGroupPanel("Display");
		ConfigWidget(config.f_ShowUnknownFields, "Show unknown fields in packet view.");
		ConfigWidget(config.f_ShowUnsettedFields, "Show fields with missing data in packet view.");
		ConfigWidget(config.f_ScrollFollowing, "Follow items when new data appears above the scroll region.");
		ConfigWidget(config.f_HighlightRelativities, "Highlight packet relativities in capture list.");
		ImGui::EndGroupPanel();
	}

	WndInfo& SettingsWnd::GetInfo()
	{
		static WndInfo info = { "Settings", true };
		return info;
	}
}