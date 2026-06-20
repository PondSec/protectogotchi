from protectogotchi.tools import get_tool, list_tools


def test_tool_catalog_contains_available_and_planned_tools():
    tools = list_tools()
    assert len(tools) >= 15
    assert get_tool("scan") is not None
    assert get_tool("map").status == "available"
    assert get_tool("trust-device").status == "available"
    assert get_tool("enforcement").status == "available"
    assert get_tool("simulate").status == "available"
    assert get_tool("macos-pf-block").status == "planned"


def test_available_only_filters_planned_tools():
    tools = list_tools(include_planned=False)
    assert tools
    assert all(tool.status == "available" for tool in tools)
