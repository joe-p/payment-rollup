import { spawn } from "node:child_process";
import { glob } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const OUT_DIR = path.join(__dirname, "..", "contracts", "out");
const CLIENTS_DIR = path.join(__dirname, "..", "contracts", "clients");

glob("*.arc56.json", { cwd: OUT_DIR }, (err, matches) => {
  if (err) throw err;
  for (const file of matches) {
    const contractName = path.basename(file).replace(".arc56.json", "");
    const clientPath = path.join(CLIENTS_DIR, `${contractName}Client.ts`);
    spawn(
      "npx",
      [
        "algokit-client-generator",
        "generate",
        "-a",
        path.join(OUT_DIR, file),
        "-o",
        clientPath,
      ],
      { stdio: "inherit" },
    );
  }
});
