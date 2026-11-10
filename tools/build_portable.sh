#!/bin/zsh
set -eu
cd -- "$(dirname -- "$0")/.."

stage="$PWD/build/portable"
disk="$stage/disk"
app="$disk/Code 启动器.app"
binary="$app/Contents/MacOS/CodeLauncher"
out="$PWD/deliveries/便携版-0.1.1"
identifier=local.code-launcher.mac
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" build/module-cache "$out"

for arch in arm64 x86_64; do
    xcrun swiftc -target "$arch-apple-macos14.0" -swift-version 5 -O \
        -module-cache-path "$PWD/build/module-cache" src/portable/*.swift -o "$stage/CodeLauncher-$arch"
done
xcrun lipo -create "$stage/CodeLauncher-arm64" "$stage/CodeLauncher-x86_64" -output "$binary"

# Reuse the existing icon artwork, with no dependency on a previously built app.
iconset="$stage/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" assets/AppIcon.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
    /usr/bin/sips -z "$((size * 2))" "$((size * 2))" assets/AppIcon.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
python3 - "$iconset" "$app/Contents/Resources/AppIcon.icns" <<'PY'
from pathlib import Path
from struct import pack
import sys

iconset, destination = map(Path, sys.argv[1:])
images = {
    b"icp4": "16x16", b"icp5": "32x32", b"ic07": "128x128",
    b"ic08": "256x256", b"ic09": "512x512",
    b"ic11": "16x16@2x", b"ic12": "32x32@2x", b"ic13": "128x128@2x",
    b"ic14": "256x256@2x", b"ic10": "512x512@2x",
}
chunks = []
for kind, size in images.items():
    png = (iconset / f"icon_{size}.png").read_bytes()
    chunks.append(pack(">4sI", kind, len(png) + 8) + png)
body = b"".join(chunks)
destination.write_bytes(pack(">4sI", b"icns", len(body) + 8) + body)
PY

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>local.code-launcher.mac</string>
    <key>CFBundleExecutable</key><string>CodeLauncher</string>
    <key>CFBundleName</key><string>Code 启动器</string>
    <key>CFBundleDisplayName</key><string>Code 启动器</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.1</string>
    <key>CFBundleVersion</key><string>2</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
/usr/bin/plutil -lint "$app/Contents/Info.plist"
/usr/bin/codesign --force --sign - --identifier "$identifier" "$app"
/usr/bin/codesign --verify --strict --verbose=2 "$app"
/usr/bin/xattr -cr "$app"
test -L "$disk/Applications" || /bin/ln -s /Applications "$disk/Applications"
/bin/cp src/portable/安装说明.txt "$disk/安装说明.txt"
image="$out/Code启动器-0.1.1-macOS.dmg"
/usr/bin/hdiutil create -ov -volname 'Code 启动器' -fs HFS+ -format UDZO -srcfolder "$disk" "$image"
/usr/bin/hdiutil verify "$image"
(cd "$out" && /usr/bin/shasum -a 256 "${image:t}" > SHA256.txt)
