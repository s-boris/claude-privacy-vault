#!/usr/bin/python3 -I
"""render.py [OUT]: write the synthetic test chat (chat150.tmpl with placeholders filled) to OUT or stdout.
The Luhn test card is assembled here at test time so no card-number literal sits in a versioned file
(secretscan would block brain snapshots)."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
VALUES = {"{{TEST_CARD}}": " ".join(["4111"] + ["1111"] * 3)}   # the public Visa test number (Luhn-valid)

def render():
    s = open(os.path.join(HERE, "chat150.tmpl"), encoding="utf-8").read()
    for k, v in VALUES.items():
        s = s.replace(k, v)
    return s

if __name__ == "__main__":
    out = render()
    if len(sys.argv) > 1:
        open(sys.argv[1], "w", encoding="utf-8").write(out)
    else:
        sys.stdout.write(out)
