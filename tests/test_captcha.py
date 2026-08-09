import random

from inlock.captcha import create_visual_challenge, render_visual_challenge


def test_visual_challenge_answer_and_png_are_generated_server_side():
    payload, answer = create_visual_challenge(random.Random(42))
    matching = [
        index for index, cell in enumerate(payload["cells"])
        if cell["shape"] == payload["target_shape"]
        and cell["color"] == payload["target_color"]
    ]

    assert answer == matching
    assert len(answer) in {2, 3}
    assert render_visual_challenge(payload).startswith(b"\x89PNG\r\n\x1a\n")
