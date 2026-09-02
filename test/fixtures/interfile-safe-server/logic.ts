import { execFile, execFileSync } from "node:child_process";

export async function inspectRepository(repository: string): Promise<void> {
  execFile("/usr/bin/git", ["-C", repository, "status"], { shell: false });
}

export const inspectRepositorySync = (repository: string): void => {
  execFileSync("/usr/bin/git", ["-C", repository, "status"], { shell: false });
};
