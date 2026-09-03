import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

writeFileSync(fileURLToPath(new URL("../EXECUTED", import.meta.url)), "unsafe\n");
