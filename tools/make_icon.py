#!/usr/bin/env python3
"""Иконка TwoKey: два скрещённых ключа — белый и оранжевый, как «Two» и «Key» в логотипе.

  python tools/make_icon.py   → icon.ico (16–256 px) и icon.png (256 px) в корне репозитория

Нужен Pillow — только для этой сборки: самой программе он не нужен, готовые файлы лежат в репозитории.
"""
import os

from PIL import Image, ImageDraw, ImageOps

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BG, EDGE, WHITE, ORANGE = (18, 27, 37, 255), (58, 78, 98, 255), (244, 247, 250, 255), (255, 107, 44, 255)
SIZE = 2048  # рисуем крупно и уменьшаем — края получаются гладкими
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
SMALL = 32  # до этого размера — толстый рисунок с одной бородкой: мелкие детали на панели задач сливаются


def key_mask(small, grow=0):
    """Ключ кольцом вверх, наклон 45°, бородка смотрит внутрь (наружу она читалась как галочка).
    grow — на сколько раздуть: зазор на пересечении."""
    u = SIZE / 1024
    cy, ring, hole, half, bottom = (186, 158, 66, 54, 900) if small else (176, 128, 56, 35, 890)
    teeth = ((770, 900, 112),) if small else ((752, 794, 86), (848, 890, 86))  # (верх, низ, длина)
    cx = 512
    mask = Image.new("L", (SIZE, SIZE), 0)
    d = ImageDraw.Draw(mask)
    r = ring + grow
    d.ellipse([(cx - r) * u, (cy - r) * u, (cx + r) * u, (cy + r) * u], fill=255)
    d.rectangle([(cx - half - grow) * u, cy * u, (cx + half + grow) * u, (bottom + grow) * u], fill=255)
    for top, low, length in teeth:
        d.rectangle([(cx - half - length - grow) * u, (top - grow) * u, cx * u, (low + grow) * u], fill=255)
    h = max(hole - grow, 0)
    d.ellipse([(cx - h) * u, (cy - h) * u, (cx + h) * u, (cy + h) * u], fill=0)
    return mask.rotate(45, resample=Image.BICUBIC)


def draw(px):
    small = px <= SMALL
    radius, border = int(SIZE * (0.2 if small else 0.22)), 0 if small else int(SIZE * 0.012)
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius, fill=EDGE if border else BG)
    if border:
        d.rounded_rectangle([border, border, SIZE - 1 - border, SIZE - 1 - border], radius - border, fill=BG)
    white = key_mask(small)
    img.paste(ORANGE, (0, 0), ImageOps.mirror(white))
    img.paste(BG, (0, 0), key_mask(small, grow=26 if small else 20))  # зазор: белый ключ лежит поверх оранжевого
    img.paste(WHITE, (0, 0), white)
    return img.resize((px, px), Image.LANCZOS)


def main():
    frames = {px: draw(px) for px in SIZES}
    frames[256].save(os.path.join(ROOT, "icon.png"), optimize=True)
    frames[256].save(os.path.join(ROOT, "icon.ico"), format="ICO", sizes=[(p, p) for p in SIZES],
                     append_images=[frames[p] for p in SIZES if p != 256])
    print("icon.ico, icon.png:", ", ".join(map(str, SIZES)))


if __name__ == "__main__":
    main()
