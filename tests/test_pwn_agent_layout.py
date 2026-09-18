import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "pwn-agent"

class PwnAgentLayoutTests(unittest.TestCase):
    def test_notebook_mcp_names_are_declared_in_metadata(self) -> None:
        metadata = yaml.safe_load(
            (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        tools = metadata["dependencies"]["tools"]
        mcp_tools = [tool for tool in tools if tool["type"] == "mcp"]

        self.assertEqual([tool["value"] for tool in mcp_tools], ["gdb", "idalib"])
        self.assertTrue(all(tool["transport"] == "stdio" for tool in mcp_tools))
        self.assertTrue(metadata["policy"]["allow_implicit_invocation"])

    def test_challenge_asset_declares_the_pwn_category(self) -> None:
        challenge = yaml.safe_load(
            (SKILL_DIR / "assets" / "challenge.yaml").read_text(encoding="utf-8")
        )

        self.assertEqual(
            challenge,
            {"id": "example", "category": "pwn", "binary": "input/chall"},
        )
