// Node verification test for the mneme-verify-wasm browser auditor.
// Proves the WASM artifact loads and runs in a JS runtime, verifies a REAL
// receipt offline under a pinned operator key, and fails closed on tamper,
// wrong key, and garbage. Run via scripts/ci/wasm-auditor.sh (which generates
// the pkg-node bindings first).
const assert = require('node:assert');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const m = require(path.join(__dirname, '..', 'pkg-node', 'mneme_verify_wasm.js'));

function main() {
  // 1. honesty() takes no input — proves the wasm loads + executes in Node,
  //    and that the load-bearing caveat is carried across the wasm boundary.
  const h = m.honesty();
  assert(h.includes('authenticated != true'), 'honesty must carry the boundary');
  assert(h.includes('NOT semantic truth'), 'honesty must state the limit');

  const fx = JSON.parse(
    readFileSync(path.join(__dirname, 'fixtures', 'mtl_inclusion.json'), 'utf8'),
  );

  // 2. Positive: a REAL receipt verifies offline under the pinned operator key.
  const res = JSON.parse(m.verify_mtl_inclusion(fx.receipt_b64, fx.operator_pk_hex));
  assert.strictEqual(res.ok, true, 'real receipt verifies');
  assert.strictEqual(res.kind, 'mtl_inclusion');
  assert.strictEqual(typeof res.leaf_index, 'number');
  assert(res.honesty.includes('authenticated != true'), 'result carries honesty');

  // 3. Fail-closed: a one-character tamper is rejected.
  const flip = fx.receipt_b64[40] === 'A' ? 'B' : 'A';
  const tampered = fx.receipt_b64.slice(0, 40) + flip + fx.receipt_b64.slice(41);
  assert.throws(
    () => m.verify_mtl_inclusion(tampered, fx.operator_pk_hex),
    'tampered receipt must fail closed',
  );

  // 4. Fail-closed: a different (wrong) operator key is rejected.
  assert.throws(
    () => m.verify_mtl_inclusion(fx.receipt_b64, '00'.repeat(32)),
    'wrong operator key must fail closed',
  );

  // 5. Fail-closed: garbage / malformed inputs across every entry point.
  assert.throws(() => m.verify_robr('@@@not-base64', '11'.repeat(32)));
  assert.throws(() => m.verify_shapley(fx.receipt_b64, 'short'));

  console.log(
    'wasm-auditor node-verify: OK ' +
      '(load + honesty + real-receipt verify + tamper + wrong-key + garbage all correct)',
  );
}

main();
