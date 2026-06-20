from protectogotchi.netutil import is_relevant_neighbor


def test_relevant_neighbor_filters_noise_addresses():
    assert is_relevant_neighbor("192.168.1.10", "00:11:22:33:44:55")
    assert not is_relevant_neighbor("224.0.0.251", "01:00:5e:00:00:fb")
    assert not is_relevant_neighbor("192.168.1.255", "ff:ff:ff:ff:ff:ff")
    assert not is_relevant_neighbor("169.254.1.2", "00:11:22:33:44:55")
