from agent.collect import CollectionResult
from agent.prompts import SYSTEM_PROMPT, format_baseline, build_initial_prompt


def _sample():
    return [
        CollectionResult("System & kernel", "uname -a", True, 0,
                         "Linux ia 6.8.0\n", ""),
        CollectionResult("Network & firewall", "nft list ruleset", False,
                         None, "", "binary 'nft' ... blocked"),
    ]


def test_format_baseline_groups_and_shows_output():
    text = format_baseline(_sample())
    assert "System & kernel" in text
    assert "uname -a" in text
    assert "Linux ia 6.8.0" in text
    # rejected command marked as skipped, not executed
    assert "nft list ruleset" in text
    assert "skipped" in text.lower()


def test_build_initial_prompt_includes_host_and_baseline():
    prompt = build_initial_prompt("ialocal", _sample())
    assert "ialocal" in prompt
    assert "uname -a" in prompt
    assert "write_report" in prompt


def test_system_prompt_defines_findings_and_severity():
    assert "read-only" in SYSTEM_PROMPT.lower()
    assert "write_report" in SYSTEM_PROMPT
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        assert sev in SYSTEM_PROMPT
