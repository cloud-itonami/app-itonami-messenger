#!/bin/sh
# Local Otehon candidate check. Inputs are existing trusted local checkouts;
# this does not publish, deploy or provide access to the private apex source.
set -eu

if [ "$#" -ne 3 ]; then
  echo 'usage: verify-local.sh APEX_CHECKOUT KOTOBA_REPOSITORY KBB_CHECKOUT' >&2
  exit 2
fi
apex=$(cd "$1" && pwd -P)
kotoba=$(cd "$2" && pwd -P)
kbb=$(cd "$3" && pwd -P)
root=$(CDPATH='' cd "$(dirname "$0")/.." && pwd -P)
apex_rev=3a868a631ae71b7d85aabf98f97216bf0d322b94
kotoba_rev=b7d31a1ee3aafdb4c33dd9f7d6b94ae423393b64
kbb_rev=1675e6aab65d5a99e37840cc5012bc2eca6f4a07

[ "$(git -C "$apex" rev-parse HEAD)" = "$apex_rev" ]
[ "$(git -C "$kbb" rev-parse HEAD)" = "$kbb_rev" ]
git -C "$apex" diff --quiet
git -C "$apex" diff --cached --quiet
git -C "$kbb" diff --quiet
git -C "$kbb" diff --cached --quiet
git -C "$kotoba" cat-file -e "$kotoba_rev^{commit}"
git -C "$kotoba" cat-file -e 'b2ae9f9fa598bc1b9a7462b68f93571af8540570^{commit}'

mkdir -p "$root/.agent-output/.agent-output"
out=$(mktemp -d "$root/.agent-output/yoro-check.XXXXXX")
mkdir -p "$out/deps" "$out/test-src/yoro"
cp "$apex/otehon/owner-store/package.json" "$apex/otehon/owner-store/package-lock.json" "$out/deps/"
npm ci --ignore-scripts --prefix "$out/deps"
node "$apex/otehon/owner-store/stage.mjs" "$kotoba" "$out/envelope"
node "$apex/otehon/owner-store/stage-dango.mjs" "$kotoba" "$out/dango"
cp "$root/otehon/test/yoro/private_message_test.cljc" "$out/test-src/yoro/private_message_test.cljs"
cp "$root/otehon/test/yoro/private_message_delivery_test.cljc" "$out/test-src/yoro/private_message_delivery_test.cljs"
cp "$root/otehon/test/yoro/passkey_seal_test.cljc" "$out/test-src/yoro/passkey_seal_test.cljs"
cp "$root/otehon/test/yoro/snapshot_host_test.cljc" "$out/test-src/yoro/snapshot_host_test.cljs"
cp "$root/otehon/test/yoro/browser_delivery_host_test.cljc" "$out/test-src/yoro/browser_delivery_host_test.cljs"
cp "$root/otehon/test/yoro/browser_local_delivery_test.cljc" "$out/test-src/yoro/browser_local_delivery_test.cljs"
cd "$out/deps"
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.browser-delivery-host-test))'
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.browser-local-delivery-test))'
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.snapshot-host-test))'
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.private-message-test))'
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.private-message-delivery-test))'
node "$kbb/cli.js" -cp "$out/dango:$out/envelope:$apex/otehon/owner-store/lib:$root/otehon/src:$out/test-src" \
  -e '(require (quote yoro.passkey-seal-test))'
echo "Yoro local test evidence: $out"
