import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "pwn-agent"


def fenced_code_blocks(markdown: str) -> list[str]:
    return re.findall(r"^```[^\n]*\n(.*?)^```", markdown, flags=re.MULTILINE | re.DOTALL)


class PwnAgentLayoutTests(unittest.TestCase):
    def test_notebook_mcp_names_are_declared_in_metadata(self) -> None:
        metadata = yaml.safe_load(
            (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        tools = metadata["dependencies"]["tools"]
        names = {tool["value"] for tool in tools if tool["type"] == "mcp"}

        self.assertEqual(names, {"gdb", "idalib"})

    def test_challenge_asset_declares_the_pwn_category(self) -> None:
        challenge = yaml.safe_load(
            (SKILL_DIR / "assets" / "challenge.yaml").read_text(encoding="utf-8")
        )

        self.assertEqual(challenge["category"], "pwn")

    def test_skill_material_has_no_stale_windows_or_wsl_user_paths(self) -> None:
        material = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [SKILL_DIR / "SKILL.md", *sorted((SKILL_DIR / "references").glob("*.md"))]
        )

        self.assertNotRegex(material, r"[A-Za-z]:\\Users\\")
        self.assertNotIn("/home/boblab04/", material)

    def test_documented_python_commands_use_python3(self) -> None:
        blocks = []
        for path in [SKILL_DIR / "SKILL.md", *sorted((SKILL_DIR / "references").glob("*.md"))]:
            blocks.extend(fenced_code_blocks(path.read_text(encoding="utf-8")))
        commands = [line.strip() for block in blocks for line in block.splitlines()]

        self.assertTrue(any(line.startswith("python3 ") for line in commands))
        self.assertFalse(any(re.match(r"^python(?:\s|$)", line) for line in commands))
