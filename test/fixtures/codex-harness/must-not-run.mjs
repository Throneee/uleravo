import { writeFileSync } from "node:fs";

writeFileSync(new URL("./executed.txt", import.meta.url), "executed\n");
