import { exec, execSync } from "node:child_process";

export async function executeCommand(command: string): Promise<void> {
  exec(command);
}

export const executeCommandSync = (command: string): void => {
  execSync(`git ${command}`);
};
