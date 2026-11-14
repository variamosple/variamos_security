// Checks what `npm pack` would publish: the entry points of package.json are
// in it, and nothing but the build output, the manifest and the readme.
// Run after the build: npm run check-package
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// npm gives the exact path of its own script: nothing is looked up in PATH
const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("Run it through npm: npm run check-package");
  process.exit(1);
}

const manifest = JSON.parse(readFileSync("package.json", "utf8"));
const [pack] = JSON.parse(
  execFileSync(
    process.execPath,
    [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts"],
    { encoding: "utf8" },
  ),
);
const files = pack.files.map((file) => file.path);

const expected = [manifest.main, manifest.types]
  .filter(Boolean)
  .map((path) => path.replace(/^\.\//, ""));
const missing = expected.filter((path) => !files.includes(path));
const unexpected = files.filter(
  (path) => !/^(dist\/|package\.json$|README\.md$|LICENSE)/.test(path),
);

if (missing.length > 0 || unexpected.length > 0) {
  if (missing.length > 0) console.error("Missing from the package:", missing);
  if (unexpected.length > 0)
    console.error("Not meant to be published:", unexpected);
  process.exit(1);
}
console.log(
  `${manifest.name}@${manifest.version}: ${files.length} files, ${pack.size} bytes`,
);
