const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('Android packages the Rust core through the C ABI/JNI bridge and tests version alignment', () => {
  const gradle = read('apps/android/app/build.gradle');
  const cmake = read('apps/android/app/src/main/cpp/CMakeLists.txt');
  const shim = read('apps/android/app/src/main/cpp/serein_core_jni.c');
  const java = read('apps/android/app/src/main/java/io/serein/chat/SereinCoreNative.java');
  const instrumented = read('apps/android/app/src/androidTest/java/io/serein/chat/SereinCoreLinkTest.java');
  assert.match(gradle, /externalNativeBuild\s*\{\s*cmake/);
  assert.match(gradle, /buildSereinCoreAndroid/);
  assert.match(cmake, /target\/native-core\/android\/\$\{ANDROID_ABI\}\/libserein_core\.a/);
  assert.match(shim, /serein_core_version\(\)/);
  assert.match(shim, /nativeEncryptRatchet/);
  assert.match(shim, /nativeDecryptRatchet/);
  assert.match(java, /System\.loadLibrary\("serein_core_jni"\)/);
  assert.match(java, /static RatchetHandle createRatchet/);
  assert.match(java, /nativeEncryptRatchet/);
  assert.match(instrumented, /testRatchetJniRoundTripAndSnapshotRestore/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java'), /ratchet_version/);
  assert.match(instrumented, /BuildConfig\.VERSION_NAME/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java'), /verifySharedCore\(\)/);
  assert.match(read('apps/ios/SereinChat/SereinChatApp.swift'), /precondition\(SereinCoreBridge\.version == appVersion/);
});

test('iOS links the generated Rust XCFramework and exposes its C ABI through Swift', () => {
  const project = read('apps/ios/SereinChat.xcodeproj/project.pbxproj');
  const swift = read('apps/ios/SereinChat/SereinCoreBridge.swift');
  const app = read('apps/ios/SereinChat/SereinChatApp.swift');
  assert.match(project, /SereinCore\.xcframework in Frameworks/);
  assert.match(project, /SereinCoreBridge\.swift in Sources/);
  assert.match(swift, /import SereinCore/);
  assert.match(swift, /serein_core_version\(\)/);
  assert.match(swift, /static func deriveChains/);
  assert.match(swift, /func encrypt\(nonce:/);
  assert.match(swift, /func decrypt\(header:/);
  assert.match(read('apps/ios/SereinChat/SereinAPI.swift'), /ratchet_version/);
  assert.match(app, /SereinCoreBridge\.version/);
});

test('native core helper builds static archives without adding dependencies or pretending they are complete E2EE', () => {
  const manifest = read('crates/serein-core/Cargo.toml');
  const script = read('scripts/build_native_core.sh');
  assert.match(manifest, /crate-type\s*=\s*\["rlib",\s*"cdylib",\s*"staticlib"\]/);
  assert.match(script, /target\/native-core/);
  assert.match(script, /lipo -create/);
  assert.match(script, /IOS_SIM_UNIVERSAL="\$IOS_OUT\/iphonesimulator-universal"/);
  assert.match(script, /\$IOS_SIM_UNIVERSAL\/libserein_core\.a/);
  assert.doesNotMatch(script, /-library "\$IOS_OUT\/iphonesimulator-arm64/);
  assert.doesNotMatch(script, /-library "\$IOS_OUT\/iphonesimulator-x86_64/);
  for (const target of ['aarch64-linux-android', 'armv7-linux-androideabi', 'i686-linux-android', 'x86_64-linux-android', 'aarch64-apple-ios', 'aarch64-apple-ios-sim', 'x86_64-apple-ios']) {
    assert.ok(script.includes(target), `native build script must cover ${target}`);
  }
  const androidEngine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const iosEngine = read('apps/ios/SereinChat/SereinChatEngine.swift');
  assert.match(androidEngine, /SereinRatchetSession\.open/);
  assert.match(androidEngine, /snapshots\.values\(\)/);
  assert.match(iosEngine, /SereinCoreBridge\.Ratchet/);
  assert.match(iosEngine, /SereinLayeredRatchet/);
});
