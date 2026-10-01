// ESLint flat config. Two worlds: Node (server, modules, tests) and the browser
// (public/js), where the classic scripts share one global scope. The browser
// files' top-level declarations are collected here so cross-file references are
// checked for typos (no-undef) rather than waved through.
const fs = require("fs");
const path = require("path");
const js = require("@eslint/js");
const globals = require("globals");

function browserSharedGlobals() {
  const dir = path.join(__dirname, "public", "js");
  const shared = {};
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    for (const m of text.matchAll(/^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm)) shared[m[1]] = "readonly";
    for (const m of text.matchAll(/^(?:const|let|var)\s+([A-Za-z_$][\w$]*)/gm)) shared[m[1]] = "writable";
    for (const m of text.matchAll(/^(?:const|let|var)\s+\{([^}]+)\}/gm)) {
      for (const name of m[1].split(",")) shared[name.trim().split(":").pop().trim()] = "writable";
    }
  }
  return shared;
}

const common = {
  "no-unused-vars": ["warn", { args: "none", caughtErrors: "none", ignoreRestSiblings: true, varsIgnorePattern: "^_" }],
  "no-empty": ["error", { allowEmptyCatch: true }],
  "no-constant-condition": ["error", { checkLoops: false }],
  "prefer-const": "warn",
  eqeqeq: ["error", "smart"],
  "no-var": "error"
};

module.exports = [
  { ignores: ["node_modules/**", "data/**", "certs/**", "public/styles.css"] },
  {
    files: ["*.js", "test/**/*.js", "deploy/**/*.js"],
    languageOptions: { ecmaVersion: 2023, sourceType: "commonjs", globals: { ...globals.node } },
    rules: { ...js.configs.recommended.rules, ...common }
  },
  {
    files: ["public/js/*.js"],
    languageOptions: { ecmaVersion: 2023, sourceType: "script", globals: { ...globals.browser, ...browserSharedGlobals() } },
    rules: { ...js.configs.recommended.rules, ...common, "no-redeclare": "off", "prefer-const": "off", "no-unused-vars": ["warn", { vars: "local", args: "none", caughtErrors: "none", varsIgnorePattern: "^_" }] }
  }
];
