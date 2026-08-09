from __future__ import annotations

import io
import math
import random
from typing import Any

from PIL import Image, ImageDraw

COLORS = {
    "roxo": "#7258E8",
    "azul": "#2E8FE8",
    "verde": "#32B875",
    "laranja": "#ED8A36",
}
SHAPES = ("círculo", "quadrado", "triângulo", "estrela")


def create_visual_challenge(rng: random.Random | None = None) -> tuple[dict[str, Any], list[int]]:
    rng = rng or random.SystemRandom()
    target_shape = rng.choice(SHAPES)
    target_color = rng.choice(tuple(COLORS))
    target_indexes = set(rng.sample(range(9), rng.choice((2, 3))))
    cells = []
    for index in range(9):
        if index in target_indexes:
            shape, color = target_shape, target_color
        else:
            shape, color = rng.choice(SHAPES), rng.choice(tuple(COLORS))
            while shape == target_shape and color == target_color:
                shape, color = rng.choice(SHAPES), rng.choice(tuple(COLORS))
        cells.append({
            "shape": shape,
            "color": color,
            "rotation": rng.randint(-18, 18),
            "offset_x": rng.randint(-9, 9),
            "offset_y": rng.randint(-9, 9),
        })
    payload = {
        "target_shape": target_shape,
        "target_color": target_color,
        "target_label": f"{target_shape} {target_color}",
        "cells": cells,
        "noise_seed": rng.randint(1, 2**31 - 1),
    }
    return payload, sorted(target_indexes)


def _polygon(center_x: float, center_y: float, radius: float, points: int, rotation: float):
    return [
        (
            center_x + math.cos(math.radians(rotation + index * 360 / points)) * radius,
            center_y + math.sin(math.radians(rotation + index * 360 / points)) * radius,
        )
        for index in range(points)
    ]


def render_visual_challenge(payload: dict[str, Any]) -> bytes:
    size, cell_size, scale = 540, 180, 2
    image = Image.new("RGB", (size * scale, size * scale), "#F8F8FC")
    draw = ImageDraw.Draw(image, "RGBA")
    rng = random.Random(payload["noise_seed"])
    for _ in range(85):
        x, y = rng.randrange(size * scale), rng.randrange(size * scale)
        radius = rng.randrange(1, 5)
        draw.ellipse((x-radius, y-radius, x+radius, y+radius), fill=(80, 70, 140, 22))

    for index, cell in enumerate(payload["cells"]):
        row, column = divmod(index, 3)
        left, top = column * cell_size * scale, row * cell_size * scale
        draw.rounded_rectangle(
            (left + 8, top + 8, left + cell_size * scale - 8, top + cell_size * scale - 8),
            radius=22, fill="#FFFFFF", outline="#DEDDE8", width=3,
        )
        center_x = left + cell_size * scale / 2 + cell["offset_x"] * scale
        center_y = top + cell_size * scale / 2 + cell["offset_y"] * scale
        radius = 49 * scale
        color = COLORS[cell["color"]]
        rotation = cell["rotation"] - 90
        if cell["shape"] == "círculo":
            draw.ellipse(
                (center_x-radius, center_y-radius, center_x+radius, center_y+radius),
                fill=color, outline="#24212F", width=3,
            )
        elif cell["shape"] == "quadrado":
            draw.regular_polygon(
                (center_x, center_y, radius), 4, rotation=rotation,
                fill=color, outline="#24212F",
            )
        elif cell["shape"] == "triângulo":
            draw.polygon(
                _polygon(center_x, center_y, radius * 1.08, 3, rotation),
                fill=color, outline="#24212F",
            )
        else:
            points = []
            for point in range(10):
                star_radius = radius if point % 2 == 0 else radius * 0.43
                angle = math.radians(rotation + point * 36)
                points.append((center_x + math.cos(angle)*star_radius, center_y + math.sin(angle)*star_radius))
            draw.polygon(points, fill=color, outline="#24212F")

    image = image.resize((size, size), Image.Resampling.LANCZOS)
    output = io.BytesIO()
    image.save(output, "PNG", optimize=True)
    return output.getvalue()

