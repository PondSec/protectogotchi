from protectogotchi.web import dashboard_html


def test_dashboard_html_references_local_api_endpoints():
    html = dashboard_html()
    assert "/api/status" in html
    assert "/api/topology" in html
    assert "/api/tools" in html
    assert "Protectogotchi" in html
