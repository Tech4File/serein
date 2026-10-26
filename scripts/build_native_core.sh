#!/usr/bin/env bash
# Build the shared Rust core as native static libraries for Android/iOS adapters.
# JNI/Swift expose generic symmetric-ratchet primitives; wiring them into app message/transfer flows remains separate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_MANIFEST="$ROOT/crates/serein-core/Cargo.toml"
OUTPUT="$ROOT/target/native-core"
MODE="${1:-help}"

fail() { printf 'error: %s\n' "$*" >&2; exit 2; }
need_target() {
  local target="$1"
  rustup target list --installed | grep -Fxq "$target" || fail "Rust target '$target' is not installed; run: rustup target add $target"
}
build_target() {
  local target="$1" destination="$2"
  need_target "$target"
  cargo build --manifest-path "$CORE_MANIFEST" --locked --release --target "$target"
  local archive="$ROOT/target/$target/release/libserein_core.a"
  [[ -s "$archive" ]] || fail "Cargo did not produce the expected static library: $archive"
  mkdir -p "$destination"
  install -m 0644 "$archive" "$destination/libserein_core.a"
  install -m 0644 "$ROOT/crates/serein-core/include/serein_core.h" "$destination/serein_core.h"
}

case "$MODE" in
  android)
    NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    if [[ -z "$NDK" && -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk" ]]; then
      NDK="$(python3 - "$ANDROID_HOME/ndk" <<'PY'
import re, sys
from pathlib import Path
root = Path(sys.argv[1])
versions = []
for path in root.iterdir():
    if path.is_dir():
        match = re.fullmatch(r"(\d+(?:\.\d+)+)", path.name)
        if match:
            versions.append((tuple(map(int, match.group(1).split("."))), path))
print(max(versions, default=((0,), Path("")))[1])
PY
      )"
    fi
    [[ -n "$NDK" && -d "$NDK/toolchains/llvm/prebuilt" ]] || fail "Android NDK not found. Set ANDROID_NDK_HOME to the installed NDK directory."
    case "$(uname -s)-$(uname -m)" in
      Linux-x86_64) HOST_TAG=linux-x86_64 ;;
      Darwin-arm64) HOST_TAG=darwin-arm64 ;;
      Darwin-x86_64) HOST_TAG=darwin-x86_64 ;;
      *) fail "Unsupported Android NDK host: $(uname -s)-$(uname -m)" ;;
    esac
    TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
    [[ -d "$TOOLCHAIN" ]] || fail "NDK toolchain directory is missing: $TOOLCHAIN"
    API=26
    build_android() {
      local target="$1" abi="$2" compiler="$3" linker_var="$4"
      local cc="$TOOLCHAIN/$compiler"
      [[ -x "$cc" ]] || fail "Android compiler is missing: $cc"
      export "$linker_var=$cc"
      export "CC_${target//-/_}=$cc"
      build_target "$target" "$OUTPUT/android/$abi"
    }
    build_android aarch64-linux-android arm64-v8a "aarch64-linux-android${API}-clang" CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER
    build_android armv7-linux-androideabi armeabi-v7a "armv7a-linux-androideabi${API}-clang" CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER
    build_android i686-linux-android x86 "i686-linux-android${API}-clang" CARGO_TARGET_I686_LINUX_ANDROID_LINKER
    build_android x86_64-linux-android x86_64 "x86_64-linux-android${API}-clang" CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER
    printf 'Android Rust static libraries written under %s/android (API %s).\n' "$OUTPUT" "$API"
    ;;
  ios)
    [[ "$(uname -s)" == Darwin ]] || fail "Building iOS libraries requires macOS and Xcode; use cargo check for cross-target source checks on other hosts."
    command -v xcodebuild >/dev/null 2>&1 || fail "Xcode command-line tools are required."
    IOS_OUT="$OUTPUT/ios"
    build_target aarch64-apple-ios "$IOS_OUT/iphoneos-arm64"
    build_target aarch64-apple-ios-sim "$IOS_OUT/iphonesimulator-arm64"
    build_target x86_64-apple-ios "$IOS_OUT/iphonesimulator-x86_64"
    IOS_SIM_UNIVERSAL="$IOS_OUT/iphonesimulator-universal"
    mkdir -p "$IOS_SIM_UNIVERSAL"
    lipo -create \
      "$IOS_OUT/iphonesimulator-arm64/libserein_core.a" \
      "$IOS_OUT/iphonesimulator-x86_64/libserein_core.a" \
      -output "$IOS_SIM_UNIVERSAL/libserein_core.a"
    install -m 0644 "$IOS_OUT/iphonesimulator-arm64/serein_core.h" "$IOS_SIM_UNIVERSAL/serein_core.h"
    cat > "$IOS_OUT/iphoneos-arm64/module.modulemap" <<'MODULEMAP'
module SereinCore {
  header "serein_core.h"
  export *
}
MODULEMAP
    cat > "$IOS_SIM_UNIVERSAL/module.modulemap" <<'MODULEMAP'
module SereinCore {
  header "serein_core.h"
  export *
}
MODULEMAP
    xcodebuild -create-xcframework \
      -library "$IOS_OUT/iphoneos-arm64/libserein_core.a" -headers "$IOS_OUT/iphoneos-arm64" \
      -library "$IOS_SIM_UNIVERSAL/libserein_core.a" -headers "$IOS_SIM_UNIVERSAL" \
      -output "$IOS_OUT/SereinCore.xcframework"
    printf 'iOS Rust XCFramework written to %s\n' "$IOS_OUT/SereinCore.xcframework"
    ;;
  all)
    "$0" android
    "$0" ios
    ;;
  *)
    printf 'Usage: %s {android|ios|all}\n' "$0"
    printf 'Outputs go under target/native-core; app message/transfer flows do not yet call the exposed ratchet primitives.\n'
    exit 0
    ;;
esac
