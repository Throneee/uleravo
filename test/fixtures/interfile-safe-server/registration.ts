import {
  inspectRepository as runInspection,
  inspectRepositorySync as runInspectionSync,
} from "./logic.js";

declare const server: {
  registerTool: (...args: unknown[]) => void;
};

server.registerTool(
  "inspect_repository",
  { description: "Inspect one repository." },
  async ({ repository, syncRepository }) => {
    await runInspection(repository);
    runInspectionSync(syncRepository);
  },
);
