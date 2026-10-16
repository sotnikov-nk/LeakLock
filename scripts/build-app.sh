#!/bin/bash
# Builds "LeakLock.app" (universal, ad-hoc signed) and a DMG into ./build.
# Usage: scripts/build-app.sh [version]
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${1:-0.1.0}"
BUILD_NUMBER="${GITHUB_RUN_NUMBER:-1}"
OUT=build
APP="$OUT/LeakLock.app"
DMG="$OUT/LeakLock-$VERSION.dmg"

ARCHS=(--arch arm64 --arch x86_64)
swift build -c release "${ARCHS[@]}"
BIN="$(swift build -c release "${ARCHS[@]}" --show-bin-path)"

rm -rf "$OUT"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN/LeakLock" "$APP/Contents/MacOS/LeakLock"
cp "$BIN/leaklockd" "$APP/Contents/Resources/leaklockd"
cp Resources/com.leaklock.daemon.plist Resources/install-helper.sh Resources/uninstall-helper.sh "$APP/Contents/Resources/"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD_NUMBER/" Resources/Info.plist > "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

swift scripts/make-icon.swift "$OUT/AppIcon.iconset"
iconutil -c icns "$OUT/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$OUT/AppIcon.iconset"

# Ad-hoc signatures: no Apple Developer account. The helper is signed on its own
# because codesign --deep does not look inside Resources.
codesign --force --sign - --identifier com.leaklock.daemon "$APP/Contents/Resources/leaklockd"
codesign --force --sign - --identifier com.leaklock.app "$APP"
codesign --verify --strict --verbose=2 "$APP"

STAGE="$OUT/dmg"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "LeakLock" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

echo "Built $APP"
echo "Built $DMG"
