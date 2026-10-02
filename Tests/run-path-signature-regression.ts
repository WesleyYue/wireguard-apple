import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const source = await Bun.file(new URL("../Sources/WireGuardKit/WireGuardAdapter.swift", import.meta.url)).text();
const start = source.indexOf("private struct PathSignature: Equatable");
const end = source.indexOf("/// A receiver bound to", start);
if (start < 0 || end <= start) throw new Error("Production PathSignature boundaries changed; update the runner explicitly");
const fixture = await Bun.file(new URL("./PathSignatureRegression.swift", import.meta.url)).text();
const directory = await mkdtemp(join(tmpdir(), "wireguard-path-regression-"));
try {
    const path = join(directory, "main.swift");
    await Bun.write(path, "import Foundation\nimport Network\nimport Darwin\n" + source.slice(start, end) + fixture);
    console.log("Running the production path signature against Network.framework snapshots...");
    const child = Bun.spawn(["xcrun", "swift", path], { stdout: "inherit", stderr: "inherit" });
    process.exitCode = await child.exited;
} finally {
    await rm(directory, { recursive: true });
}
