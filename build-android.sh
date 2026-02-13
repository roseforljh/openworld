#!/bin/bash
# OpenWorld Android 构建脚本
# 用法: ./build-android.sh [release|debug]

set -e

MODE="${1:-release}"
TARGETS="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android"
OUT_DIR="target/android-libs"

echo "=== OpenWorld Android Build (${MODE}) ==="

# 检查 rustup targets
for target in $TARGETS; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Installing target: $target"
        rustup target add "$target"
    fi
done

# 编译
for target in $TARGETS; do
    echo "Building for $target..."
    if [ "$MODE" = "release" ]; then
        cargo build --target "$target" --features android --no-default-features --release
    else
        cargo build --target "$target" --features android --no-default-features
    fi
done

# 拷贝到 jniLibs 目录结构
mkdir -p "$OUT_DIR/arm64-v8a" "$OUT_DIR/armeabi-v7a" "$OUT_DIR/x86_64"

if [ "$MODE" = "release" ]; then
    PROFILE="release"
else
    PROFILE="debug"
fi

cp "target/aarch64-linux-android/$PROFILE/libopenworld.so"    "$OUT_DIR/arm64-v8a/"
cp "target/armv7-linux-androideabi/$PROFILE/libopenworld.so"  "$OUT_DIR/armeabi-v7a/"
cp "target/x86_64-linux-android/$PROFILE/libopenworld.so"     "$OUT_DIR/x86_64/"

# 显示产物大小
echo ""
echo "=== Build artifacts ==="
ls -lh "$OUT_DIR"/*/libopenworld.so

echo ""
echo "Done! Copy $OUT_DIR/* to your Android project's app/src/main/jniLibs/"
