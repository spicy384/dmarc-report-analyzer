// Tiny assertion helper shared by the test files. Keeps output readable without
// pulling in a test framework dependency.
function createChecker(title) {
  const state = { pass: 0, fail: 0 };

  console.log(`\n${title}`);
  console.log("=".repeat(title.length));

  function check(name, condition, extra = "") {
    if (condition) {
      state.pass += 1;
      console.log(`  PASS  ${name}`);
    } else {
      state.fail += 1;
      console.log(`  FAIL  ${name}${extra ? `  -> ${extra}` : ""}`);
    }
  }

  function report() {
    console.log(`\n${state.pass} passed, ${state.fail} failed`);
    return state.fail === 0;
  }

  return { check, report, state };
}

module.exports = { createChecker };
