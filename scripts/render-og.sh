#!/bin/sh
# Renders docs/assets/header.svg to docs/assets/og.png (1200x630) with the first renderer found:
# resvg, rsvg-convert, ImageMagick, then headless Chrome/Chromium. The SVG contains outlined text only, so the
# result does not depend on installed fonts.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
svg="$root/docs/assets/header.svg"
png="$root/docs/assets/og.png"

if command -v resvg >/dev/null 2>&1; then
    resvg --width 1200 --height 630 "$svg" "$png"
elif command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert --width 1200 --height 630 --output "$png" "$svg"
elif command -v magick >/dev/null 2>&1; then
    magick -background none -density 96 "$svg" -resize 1200x630 "$png"
else
    chrome=""
    for candidate in \
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
        google-chrome google-chrome-stable chromium chromium-browser chrome; do
        if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
            chrome=$candidate
            break
        fi
    done
    if [ -z "$chrome" ]; then
        echo "render-og.sh: install resvg, rsvg-convert, ImageMagick or Chrome" >&2
        exit 1
    fi
    page=$(mktemp "${TMPDIR:-/tmp}/inveil-og.XXXXXX.html")
    trap 'rm -f "$page"' EXIT
    printf '<!doctype html><meta charset="utf-8"><style>html,body{margin:0;background:#0a0a0a}img{display:block}</style><img src="file://%s" width="1200" height="630">' "$svg" > "$page"
    "$chrome" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
        --window-size=1200,630 --screenshot="$png" "file://$page" >/dev/null 2>&1
fi

echo "wrote $png"
