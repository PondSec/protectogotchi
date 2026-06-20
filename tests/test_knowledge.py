from protectogotchi.knowledge import get_topic, list_topics


def test_knowledge_base_contains_mvp_and_planned_topics():
    topics = list_topics()
    names = {topic.name for topic in topics}
    assert "arp-spoofing" in names
    assert "linux-ebpf-sensor" in names
    assert get_topic("ids-integration").maturity == "planned"


def test_mvp_only_filters_planned_topics():
    topics = list_topics(include_planned=False)
    assert topics
    assert all(topic.maturity == "mvp" for topic in topics)
