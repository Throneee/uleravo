import { build } from "vite";
import { actionBuildConfig } from "../action/vite.config.mjs";

await build(actionBuildConfig());
