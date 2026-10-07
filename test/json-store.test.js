/** The JSON file store behind accounts, sessions and mailboxes: cached reads, atomic writes, strict about corruption. */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createChecker } = require("./helpers/assert");
const { readJsonFile, writeJsonFile, forget } = require("../json-store");

const { check, report } = createChecker("JSON store: cache, atomic write, corruption");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dmarc-jsonstore-"));
const file = path.join(dir, "users.json");

check("missing file gives the fallback", JSON.stringify(readJsonFile(file, [])) === "[]" && readJsonFile(file, null) === null);
writeJsonFile(file, [{ id: 1, name: "a" }]);
check("written and read back; no temporary file left", JSON.stringify(readJsonFile(file, [])) === JSON.stringify([{ id: 1, name: "a" }]) && fs.readdirSync(dir).join() === "users.json");
const first = readJsonFile(file, []);
first[0].name = "mutated";
check("each read is a fresh copy: mutating one does not change the next", readJsonFile(file, [])[0].name === "a");
// A change made by someone else on disk (another process, an operator) is picked up by mtime/size.
fs.writeFileSync(file, JSON.stringify([{ id: 2, name: "b" }]));
const changed = readJsonFile(file, []);
check("an external edit is seen", changed.length === 1 && changed[0].id === 2, JSON.stringify(changed));
fs.writeFileSync(file, "{not json");
let threw = null;
try { readJsonFile(file, []); } catch (e) { threw = e; }
check("a corrupt file is an error (503), not an empty store", threw && threw.status === 503 && /users\.json/.test(threw.message) && /not valid JSON/.test(threw.message), threw && threw.message);
fs.writeFileSync(file, "null");
check("a file holding null reads as the fallback", JSON.stringify(readJsonFile(file, { x: 1 })) === JSON.stringify({ x: 1 }));
forget(file);
writeJsonFile(file, { a: 1 });
if (process.platform !== "win32") {
  check("mode 600", (fs.statSync(file).mode & 0o777) === 0o600);
}
check("nested directory is created on write", (() => { const deep = path.join(dir, "x", "y", "z.json"); writeJsonFile(deep, [1]); return readJsonFile(deep, [])[0] === 1; })());

fs.rmSync(dir, { recursive: true, force: true });
process.exit(report() ? 0 : 1);
