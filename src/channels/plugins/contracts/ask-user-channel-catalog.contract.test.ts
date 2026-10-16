import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createOpenClawCodingToolsInternalAsync } from "../../../agents/agent-tools.js";
import { clearRuntimeConfigSnapshot, setRuntimeConfigSnapshot } from "../../../config/io.js";
import type { OpenClawConfig } from "../../../config/types.openclaw.js";
import {
  resetPluginRuntimeStateForTest,
  setActivePluginRegistry,
} from "../../../plugins/runtime.js";
import { createTestRegistry } from "../../../test-utils/channel-plugins.js";
import { getBundledChannelPluginAsync } from "./test-helpers/bundled-channel-plugin-loader.js";

const config: OpenClawConfig = {
  agents: { entries: { main: {} } },
  plugins: { enabled: false },
  tools: { allow: ["ask_user"] },
};

beforeEach(async () => {
  setRuntimeConfigSnapshot(config);
  setActivePluginRegistry(
    createTestRegistry(
      await Promise.all(
        ["discord", "imessage", "mattermost", "signal", "slack", "telegram", "whatsapp"].map(
          async (pluginId) => {
            const plugin = await getBundledChannelPluginAsync(pluginId);
            if (!plugin) {
              throw new Error(`Missing bundled channel plugin for ${pluginId}`);
            }
            return { pluginId, plugin, source: "test" };
          },
        ),
      ),
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
