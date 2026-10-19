"""Builds header.svg and header-light.svg with all text converted to outlines (Inter, variable font).

Requires: pip install fonttools brotli uharfbuzz
Usage: python3 docs/assets/build_header.py
"""

import io
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

ASSETS = Path(__file__).parent
FONT_FILE = ASSETS / "inter-latin-wght-normal.woff2"
WIDTH, HEIGHT = 1200, 630
LEFT = 80
MAX_HEADLINE_WIDTH = 1040

HEADLINE = ["Data loss prevention for AI", "open source, bring your own backend."]
SUBCOPY = "A local proxy that blocks or redacts sensitive data before it reaches an AI tool."

THEMES = {
    "header.svg": {
        "background": ("#0a0a0a", "#171717"),
        "headline": "#ffffff",
        "muted": "#737373",
        "sub": "#a3a3a3",
        "wordmark": "#ffffff",
    },
    "header-light.svg": {
        "background": ("#ffffff", "#f5f5f5"),
        "headline": "#0a0a0a",
        "muted": "#737373",
        "sub": "#525252",
        "wordmark": "#0a0a0a",
    },
}


def load_font() -> tuple[hb.Font, TTFont]:
    ttfont = TTFont(FONT_FILE)
    ttfont.flavor = None
    buffer = io.BytesIO()
    ttfont.save(buffer)
    face = hb.Face(buffer.getvalue())
    return hb.Font(face), ttfont


def shape(font: hb.Font, ttfont: TTFont, text: str, size: float, weight: int, tracking_em: float):
    """Returns (svg path data, advance width) with the baseline at y = 0."""
    font.set_variations({"wght": weight})
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": True})
    scale = size / ttfont["head"].unitsPerEm
    glyph_order = ttfont.getGlyphOrder()
    x = 0.0
    commands = []
    for info, position in zip(buf.glyph_infos, buf.glyph_positions):
        pen = SVGPathPen(None, ntos=lambda value: f"{value:.2f}".rstrip("0").rstrip("."))
        transform = (scale, 0, 0, -scale, x + position.x_offset * scale, -position.y_offset * scale)
        font.draw_glyph_with_pen(info.codepoint, TransformPen(pen, transform))
        commands.append(pen.getCommands())
        x += position.x_advance * scale + tracking_em * size
    return " ".join(command for command in commands if command), x - tracking_em * size


def logo_group(x: int, y: int, size: int) -> str:
    scale = size / 100
    return f"""<g transform="translate({x} {y}) scale({scale})">
    <clipPath id="logo-clip"><rect width="100" height="100" rx="23.4375"/></clipPath>
    <g clip-path="url(#logo-clip)">
      <rect width="100" height="100" fill="#171717"/>
      <path d="M19.7847 24.5417C39.9699 18.4861 60.1551 18.4861 80.3403 24.5417L84.125 73.3646C76.5556 80.934 68.9861 80.934 61.4167 73.3646C53.8472 80.934 46.2778 80.934 38.7083 73.3646C31.1389 80.934 23.5694 80.934 16 73.3646L19.7847 24.5417Z" fill="url(#logo-veil)"/>
      <path d="M36.8159 23.7832L34.9236 73.7415M63.309 23.7832L65.2014 73.7415" stroke="white" stroke-opacity="0.14" stroke-width="0.5" stroke-linecap="round"/>
      <path d="M17.5139 25.2971C39.213 18.7369 60.9121 18.7369 82.6111 25.2971" stroke="white" stroke-width="1.2" stroke-linecap="round"/>
      <path d="M50.0625 26.8125C53.4688 40.4375 59.1459 46.1146 72.7709 49.5208C59.1459 52.9271 53.4688 58.6042 50.0625 72.2292C46.6563 58.6042 40.9792 52.9271 27.3542 49.5208C40.9792 46.1146 46.6563 40.4375 50.0625 26.8125Z" fill="white" stroke="white" stroke-width="0.5" stroke-linejoin="round"/>
    </g>
  </g>"""


def build(name: str, theme: dict[str, str]) -> None:
    font, ttfont = load_font()

    headline_size = 72.0
    widths = [shape(font, ttfont, line, headline_size, 700, -0.03)[1] for line in HEADLINE]
    headline_size = round(headline_size * min(1.0, MAX_HEADLINE_WIDTH / max(widths)), 1)

    wordmark, _ = shape(font, ttfont, "Inveil", 34, 600, -0.01)
    line_one, _ = shape(font, ttfont, HEADLINE[0], headline_size, 700, -0.03)
    line_two, _ = shape(font, ttfont, HEADLINE[1], headline_size, 700, -0.03)
    sub, _ = shape(font, ttfont, SUBCOPY, 26, 400, 0)

    top, bottom = theme["background"]
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="Inveil: Data loss prevention for AI, open source, bring your own backend.">
  <title>Inveil: Data loss prevention for AI, open source, bring your own backend.</title>
  <defs>
    <linearGradient id="background" x1="0" y1="0" x2="{WIDTH}" y2="{HEIGHT}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{top}"/>
      <stop offset="1" stop-color="{bottom}"/>
    </linearGradient>
    <linearGradient id="logo-veil" x1="50.0625" y1="19.2431" x2="50.0625" y2="79.7986" gradientUnits="userSpaceOnUse">
      <stop stop-color="white" stop-opacity="0.5"/>
      <stop offset="1" stop-color="white" stop-opacity="0.08"/>
    </linearGradient>
  </defs>
  <rect width="{WIDTH}" height="{HEIGHT}" fill="url(#background)"/>
  {logo_group(LEFT, 72, 72)}
  <path transform="translate(172 120)" fill="{theme['wordmark']}" d="{wordmark}"/>
  <path transform="translate({LEFT} 300)" fill="{theme['headline']}" d="{line_one}"/>
  <path transform="translate({LEFT} {300 + round(headline_size * 1.16)})" fill="{theme['muted']}" d="{line_two}"/>
  <path transform="translate({LEFT} 540)" fill="{theme['sub']}" d="{sub}"/>
</svg>
"""
    (ASSETS / name).write_text(svg)
    print(f"wrote {name} (headline {headline_size}px)")


if __name__ == "__main__":
    for file_name, colours in THEMES.items():
        build(file_name, colours)
