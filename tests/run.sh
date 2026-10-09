#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
unset DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
launcher=${ZIRAN_BIN:-ziran}
if [ -f ziran.local.toml ]; then
    ziran=${ZIRAN_DIR:-"$("$launcher" pkg path ziran)"}
else
    ziran=${ZIRAN_DIR:-"$("$launcher" pkg path ziran --locked)"}
fi
compiler=${ZI2C_BIN:-"$ziran/build/bin/zi2c"}
ziran_bin=${ZIRAN_BIN:-"$(dirname "$compiler")/ziran"}
if [ -f ziran.local.toml ]; then
    oqs=${OQS_DIR:-"$("$launcher" pkg path oqs)"}
else
    oqs=${OQS_DIR:-"$("$launcher" pkg path oqs --locked)"}
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$compiler" --no-main --root "$root" \
    --module-path "$ziran/std" -o "$work/generated" \
    "$root/client.zi" "$root/transaction.zi" "$root/sync.zi" \
    "$root/social.zi" "$root/account.zi" "$root/events.zi"

for test in wire auth url client transaction sync social account events; do
    "${CC:-cc}" -std=c11 -O0 -Wall -Wextra -Werror \
        -Wno-unused-function -Wno-unused-variable \
        -I"$ziran/include" -I"$work/generated" \
        "$root/tests/${test}_test.c" \
        "$work/generated/auth.c" "$work/generated/client.c" \
        "$work/generated/url.c" "$work/generated/wire.c" \
        "$work/generated/transaction.c" "$work/generated/sync.c" \
        "$work/generated/social.c" "$work/generated/account.c" \
        "$work/generated/events.c" \
        "$work/generated/json_scan.c" "$work/generated/text_buffer.c" \
        "$work/generated/text.c" \
        -o "$work/${test}_test"
    env -u DISPLAY -u WAYLAND_DISPLAY "$work/${test}_test"
done

"$compiler" --no-main --root "$root/tests" --module-path "$root" --module-path "$ziran/std" \
    -o "$work/native-crypto" "$root/tests/crypto_native_api.zi"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -I"$ziran/include" -I"$work/native-crypto" \
    "$root/tests/crypto_native_test.c" "$work/native-crypto"/*.c \
    ${SODIUM_LIBS:--l:libsodium.so.23} -o "$work/native-crypto-test"
"$work/native-crypto-test"

"$compiler" --no-main --root "$root/tests" \
    --module-path "$root" --module-path "$ziran/std" \
    -o "$work/async" "$root/tests/async_behavior.zi"
"${CC:-cc}" -std=c11 -O0 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$ziran/include" -I"$work/async" "$work/async"/*.c \
    -o "$work/async_test"
env -u DISPLAY -u WAYLAND_DISPLAY "$work/async_test"
echo 'Daochi Ziran asynchronous request and signed sync passed'

# Account keys sign through liboqs, built once from the locked source with
# the algorithms exposed by the Oqs package.
liboqs_build="$root/build/liboqs"
liboqs=${LIBOQS_A:-"$liboqs_build/lib/liboqs.a"}
if [ ! -f "$liboqs" ] || ! nm "$liboqs" | rg -q OQS_KEM_ml_kem_768_keypair; then
    cmake -S "$("$ziran_bin" pkg path liboqs)" -B "$liboqs_build" \
        -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_SHARED_LIBS=OFF \
        -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=OFF \
        -DOQS_OPT_TARGET=generic '-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44;KEM_ml_kem_768' > /dev/null
    cmake --build "$liboqs_build" --target oqs > /dev/null
fi
# Use the selected compiler for every test. A nested project build can select
# another toolchain from this package's lock and mix incompatible C headers.
"$compiler" --no-main --root "$root/tests" --module-path "$root" \
    --module-path "$ziran/std" --module-path "oqs=$oqs/src" \
    -o "$work/keys" "$root/tests/keys_behavior.zi"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -I"$ziran/include" -I"$work/keys" -I"$work/keys/tests" \
    "$work/keys"/*.c \
    "$liboqs" -o "$work/keys_test"
env -u DISPLAY -u WAYLAND_DISPLAY "$work/keys_test"
echo 'Daochi account keys, key files, and cryptography passed'

# Shared canonical server fixture and actual recipient-bound key envelopes.
"$compiler" --no-main --root "$root" --module-path "$ziran/std" \
    --module-path "oqs=$oqs/src" -o "$work/authorization" \
    "$root/authorization.zi" "$root/authorization_owner.zi" \
    "$root/delegated.zi" "$root/async_delegated.zi" "$root/envelope.zi"
"${CC:-cc}" -std=c11 -O0 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$ziran/include" -I"$work/authorization" \
    "$root/tests/authorization_test.c" "$work/authorization"/*.c \
    "$liboqs" -o "$work/authorization_test"
env -u DISPLAY -u WAYLAND_DISPLAY -u XAUTHORITY -u DBUS_SESSION_BUS_ADDRESS \
    "$work/authorization_test" "$root/tests/fixtures/authorization_v1.json"

"$ziran_bin" bundle --root "$root/tests" \
    --module-path "$root" --module-path "$ziran/std" \
    --entry url_portable:Check -o "$work/url.zib" \
    "$root/tests/url_portable.zi"
test "$("$ziran_bin" run "$work/url.zib")" = 0
echo 'Daochi Ziran URL portable bundle passed'

"$ziran_bin" bundle --root "$root/tests" \
    --module-path "$root" --module-path "$ziran/std" \
    --entry wire_portable:Check -o "$work/wire.zib" \
    "$root/tests/wire_portable.zi"
test "$("$ziran_bin" run "$work/wire.zib")" = 0
"$ziran_bin" ir --root "$root/tests" \
    --module-path "$root" --module-path "$ziran/std" \
    -o "$work/wire-ir" "$root/tests/wire_portable.zi"
"$ziran_bin" bundle --root "$work/wire-ir" \
    --module-path "$root" --module-path "$ziran/std" \
    --entry wire_portable:Check -o "$work/wire-saved.zib" \
    "$work/wire-ir/wire_portable.zir"
test "$("$ziran_bin" run "$work/wire-saved.zib")" = 0
echo 'Daochi Ziran wire portable bundle passed'
