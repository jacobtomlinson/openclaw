import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discordPlugin } from "../../../../extensions/discord/channel-plugin-api.js";
import { imessagePlugin } from "../../../../extensions/imessage/channel-plugin-api.js";
import { mattermostPlugin } from "../../../../extensions/mattermost/channel-plugin-api.js";
import { signalPlugin } from "../../../../extensions/signal/channel-plugin-api.js";
import { slackPlugin } from "../../../../extensions/slack/channel-plugin-api.js";
import { telegramPlugin } from "../../../../extensions/telegram/channel-plugin-api.js";
import { whatsappPlugin } from "../../../../extensions/whatsapp/channel-plugin-api.js";
import { createOpenClawCodingToolsInternalAsync } from "../../../agents/agent-tools.js";
import { clearRuntimeConfigSnapshot, setRuntimeConfigSnapshot } from "../../../config/io.js";
import type { OpenClawConfig } from "../../../config/types.openclaw.js";
import {
  resetPluginRuntimeStateForTest,
  setActivePluginRegistry,
} from "../../../plugins/runtime.js";
import { createTestRegistry } from "../../../test-utils/channel-plugins.js";

const config: OpenClawConfig = {
  agents: { entries: { main: {} } },
  plugins: { enabled: false },
  tools: { allow: ["ask_user"] },
};

beforeEach(() => {
  setRuntimeConfigSnapshot(config);
  setActivePluginRegistry(
    createTestRegistry(
      [
        discordPlugin,
        imessagePlugin,
        mattermostPlugin,
        signalPlugin,
        slackPlugin,
        telegramPlugin,
        whatsappPlugin,
      ].map((plugin) => ({ pluginId: plugin.id, plugin, source: "test" })),
    ),
  );
});

afterEach(() => {
  resetPluginRuntimeStateForTest();
  clearRuntimeConfigSnapshot();
});

describe("ask_user channel catalogs", () => {
  it.each([
    { messageChannel: "webchat", available: true },
    { messageChannel: "discord", available: true },
    { messageChannel: "slack", available: true },
    { messageChannel: "telegram", available: true },
    { messageChannel: "whatsapp", available: false },
    { messageChannel: "imessage", available: false },
    { messageChannel: "signal", available: false },
    { messageChannel: "mattermost", available: false },
    { messageChannel: "unknown-channel", available: false },
    { messageChannel: "webchat", available: false, deny: true },
  ])(
    "uses the inbound $messageChannel capability (available: $available, deny: $deny)",
    async ({ messageChannel, available, deny }) => {
      const tools = await createOpenClawCodingToolsInternalAsync({
        config: deny ? { ...config, tools: { allow: ["ask_user"], deny: ["ask_user"] } } : config,
        sessionKey: "agent:main:run",
        messageChannel,
        messageProvider: "discord",
        toolConstructionPlan: {
          includeBaseCodingTools: false,
          includeShellTools: false,
          includeChannelTools: false,
          includeOpenClawTools: true,
          includePluginTools: false,
        },
      });
      expect(tools.some((tool) => tool.name === "ask_user")).toBe(available);
    },
  );
});
