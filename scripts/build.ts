import { spawnSync } from "child_process";
import { readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

function run(cmd: string, args: string[]) {
  console.debug(`+${cmd} ${args.join(" ")}`);
  const result = spawnSync(cmd, args, { stdio: 'inherit' });
  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(`${cmd} exited with status code ${result.status}`);
  }

  return result;
}

function isDirEmpty(path: string) {
  try {
    return readdirSync(path).length === 0;
  } catch {
    return true
  }
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const falconDir = resolve(scriptDir, "../falcon/")
const emsdkDir = resolve(scriptDir, "../emsdk")

const emsdkBin = resolve(scriptDir, "../emsdk/emsdk");
const emsdkVersion = "5.0.7";

if (isDirEmpty(falconDir) || isDirEmpty(emsdkDir)) {
  run("git", ["submodule", "update", "--init", "--recursive"]);
}
run(emsdkBin, ["install", emsdkVersion]);
run(emsdkBin, ["activate", emsdkVersion]);

try {
  process.chdir(resolve(scriptDir, "../falcon"));
} catch (error) {
  throw new Error(
    "Failed to enter the falcon directory. Make sure the falcon submodule is initialized: git submodule update --init"
  );
}

const srcFiles: string[] = [];

for (const file of readdirSync(".")) {
  if (file.endsWith(".c")) {
    srcFiles.push(file);
  }
}

srcFiles.sort();

const exportedFunctions = [
  "falcon_det1024_sign_compressed",
  "falcon_det1024_verify_compressed",
  "shake256_init_prng_from_seed",
  "falcon_det1024_keygen",
  // Randomized (salted) Falcon, as in the Round 3 specification.
  "falcon_sign_dyn",
  "falcon_verify",
  "malloc",
  "free",
]
  .map((f) => `_${f}`)
  .join(",");

const emccBin = resolve(scriptDir, "../emsdk/upstream/emscripten/emcc");

function baseEmccArgs(asyncCompilation: boolean): string[] {
  return [
    "-O3",
    "-s", "WASM=1",
    "-s", `EXPORTED_FUNCTIONS=[${exportedFunctions}]`,
    "-s", "EXPORTED_RUNTIME_METHODS=[HEAPU8,HEAPU32]",
    "-s", "STACK_SIZE=262144",
    "-s", "MODULARIZE=1",
    "-s", "EXPORT_ES6=1",
    "-s", "ENVIRONMENT=web,worker",
    // Embed the WASM as a binary string inside the JS glue so nothing is
    // fetched at runtime — the module loads in Node, browsers and bundlers
    // without a `fetch` shim or external `.wasm` asset wiring.
    "-s", "SINGLE_FILE=1",
    "-s", `WASM_ASYNC_COMPILATION=${asyncCompilation ? 1 : 0}`,
    "-s", "DYNAMIC_EXECUTION=0",
  ];
}

/**
 * We emit two glue variants because the ESM and CJS builds need to instantiate
 * the WASM differently:
 *
 *   - falcon_wasm.js (async): used by the ESM build, which awaits it at the top
 *     level. Asynchronous compilation works on a browser main thread for WASM
 *     of any size, so the ESM build stays browser-safe.
 *   - falcon_wasm_sync.js (sync): used by the CJS build. CommonJS cannot contain
 *     top-level await, so it needs a factory that returns the module
 *     synchronously. Synchronous compilation of a >4KB module would throw on a
 *     browser main thread, but CJS only runs under Node, which has no such limit.
 */
function buildGlue(asyncCompilation: boolean, outName: string) {
  run(emccBin, [...baseEmccArgs(asyncCompilation), "-o", "falcon_wasm.js", ...srcFiles]);

  const outPath = resolve(scriptDir, "../src", outName);
  try {
    renameSync("falcon_wasm.js", outPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to move output file to ${outName}: ${message}. emcc may have succeeded but did not generate the expected falcon_wasm.js file.`,
    );
  }

  if (!asyncCompilation) {
    // Emscripten always declares the MODULARIZE factory as `async function`, so
    // `createModule()` returns a Promise even though synchronous compilation
    // makes instantiation fully synchronous (no top-level `await` survives in
    // the factory body). Strip the leading `async` so the factory returns the
    // module object directly — this is what lets the CJS build exist at all,
    // since CommonJS cannot contain top-level await.
    const glue = readFileSync(outPath, "utf8");
    const marker = "async function Module(";
    if (!glue.includes(marker)) {
      throw new Error(
        `Expected to find '${marker}' in ${outName} so the leading 'async' could be stripped. ` +
        `Emscripten output may have changed; review the generated glue before shipping.`,
      );
    }
    writeFileSync(outPath, glue.replace(marker, "function Module("));
  }
}

buildGlue(true, "falcon_wasm.js");
buildGlue(false, "falcon_wasm_sync.js");
