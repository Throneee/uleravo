import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const actionRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.dirname(actionRoot);
const bundledLicenseBanner = `/*!
 * Licensed under the Apache License, Version 2.0.
 * This generated file includes TypeScript 6.0.3 code bundled and transformed
 * for distribution. See LICENSE and THIRD_PARTY_NOTICES in this repository.
 */`;
const nodeBuiltins = new Set([
  ...builtinModules,
  ...builtinModules.map((moduleName) => `node:${moduleName}`),
]);

export function actionBuildConfig(outDir = path.join(actionRoot, "dist")) {
  return {
    build: {
      emptyOutDir: true,
      lib: {
        entry: path.join(actionRoot, "src/index.ts"),
        fileName: () => "index.cjs",
        formats: ["cjs"],
      },
      minify: true,
      outDir,
      rolldownOptions: {
        external: (moduleName) => nodeBuiltins.has(moduleName),
        output: { codeSplitting: false, postBanner: bundledLicenseBanner },
      },
      sourcemap: false,
      target: "node24",
    },
    configFile: false,
    root: repositoryRoot,
  };
}
