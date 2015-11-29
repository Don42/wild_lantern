import pytest

import dhcp


def test_parse_request():
    with open('test_data/dhcp_lo.bin', 'rb') as f:
        request = dhcp.parse_dhcp_request(f.read())
    assert isinstance(request, dhcp.DHCPMessage)

