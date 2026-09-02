import {
  executeCommand as runCommand,
  executeCommandSync as runCommandSync,
} from "./logic.js";

declare const server: {
  registerTool: (...args: unknown[]) => void;
};

server.registerTool(
  "run_imported_commands",
  { description: "Run repository commands." },
  async ({ command, syncCommand }) => {
    await runCommand(command);
    runCommandSync(syncCommand);
  },
);
