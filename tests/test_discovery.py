import tempfile
import unittest
from unittest import mock

from netshaper.models import Device
from netshaper.network.discovery import NetworkDiscovery


class DiscoveryHostnameTests(unittest.TestCase):
    def test_resolve_hostnames_uses_lan_fallbacks(self):
        disc = NetworkDiscovery("eth0")
        device = Device(ip="192.0.2.20", mac="00:11:22:33:44:55")

        with mock.patch.object(disc, "_hostname_from_reverse_dns", return_value=""), \
             mock.patch.object(disc, "_hostname_from_getnameinfo", return_value=""), \
             mock.patch.object(disc, "_hostname_from_hosts_file", return_value=""), \
             mock.patch.object(disc, "_hostname_from_lease_files", return_value=""), \
             mock.patch.object(disc, "_hostname_from_system_resolvers", return_value=""), \
             mock.patch.object(disc, "_hostname_from_nbns", return_value="DESKTOP-01"):
            disc.resolve_hostnames([device])

        self.assertEqual(device.hostname, "desktop-01")

    def test_parse_resolver_output_accepts_getent_format(self):
        disc = NetworkDiscovery("eth0")

        name = disc._parse_resolver_output(
            "192.0.2.20 phone.local phone\n", "192.0.2.20")

        self.assertEqual(name, "phone.local")

    def test_hostname_from_lease_file_accepts_dnsmasq_format(self):
        disc = NetworkDiscovery("eth0")
        with tempfile.NamedTemporaryFile("w") as fh:
            fh.write("1710000000 00:11:22:33:44:55 192.0.2.20 laptop *\n")
            fh.flush()

            name = disc._hostname_from_lease_file(fh.name, "192.0.2.20")

        self.assertEqual(name, "laptop")

    def test_parse_nbns_response_prefers_unique_workstation_name(self):
        disc = NetworkDiscovery("eth0")
        rdata = (
            b"\x02"
            + b"DESKTOP-01      "[:15] + b"\x00" + b"\x00\x00"
            + b"WORKGROUP       "[:15] + b"\x00" + b"\x80\x00"
        )
        response = (
            b"\x12\x34\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00"
            + disc._encode_netbios_name("*")
            + b"\x00\x21\x00\x01"
            + b"\xc0\x0c\x00\x21\x00\x01\x00\x00\x00\x00"
            + len(rdata).to_bytes(2, "big")
            + rdata
        )

        name = disc._parse_nbns_response(response, "192.0.2.20")

        self.assertEqual(name, "desktop-01")


if __name__ == "__main__":
    unittest.main(verbosity=2)
