# Image assets

| File | Purpose |
|---|---|
| `header.svg` | README header (dark). Text is converted to outlines, so it renders the same everywhere. |
| `header-light.svg` | README header for light GitHub themes (used through `<picture>`). |
| `og.png` | 1200x630 social preview, rendered from `header.svg`. Upload it under Settings, Social preview. |
| `logo.svg` | The mark, copied from the Inveil frontend. See [TRADEMARKS.md](../../TRADEMARKS.md). |
| `architecture.svg`, `trust-model.svg` | Hand-written diagrams on a solid dark background, readable on light and dark themes. |
| `build_header.py` | Generates both header SVGs from the Inter font. |
| `inter-latin-wght-normal.woff2` | Inter Variable (SIL Open Font License 1.1), used only to build outlines. |

## Regenerating

```sh
python3 -m venv .venv && .venv/bin/pip install fonttools brotli uharfbuzz
.venv/bin/python docs/assets/build_header.py   # header.svg and header-light.svg
scripts/render-og.sh                           # og.png
```

`scripts/render-og.sh` uses the first renderer it finds: `resvg`, `rsvg-convert`, ImageMagick, then headless Chrome or Chromium. Change the copy by editing `HEADLINE` and `SUBCOPY` in `build_header.py`.
