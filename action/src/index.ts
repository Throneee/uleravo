import process from "node:process";
import { runAction } from "../../src/action.js";
import { PRODUCT_SLUG } from "../../src/version.js";

runAction()
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch(() => {
    process.stderr.write(`${PRODUCT_SLUG} action: unexpected adapter failure.\n`);
    process.exitCode = 2;
  });
