import tempfile
import unittest
from ipaddress import IPv4Network, ip_network
from unittest import mock

from netshaper.models import Device
from netshaper.network.discovery import NetworkDiscovery


class DiscoveryHostnameTests(unittest.TestCase):
    def test_target_batches_chunks_large_subnet_probe(self):
        targets = [f"192.0.2.{idx}" for idx in range(1, 70)]

        batches = NetworkDiscovery._target_batches(targets, batch_size=32)

        self.assertEqual([len(batch) for batch in batches], [32, 32, 5])
        self.assertEqual(batches[0][0], "192.0.2.1")
        self.assertEqual(batches[-1][-1], "192.0.2.69")

    def test_target_batches_from_scopes_apply_budget_without_full_materialization(self):
        batches = list(NetworkDiscovery._target_batches_from_scopes(
            [IPv4Network("10.0.0.0/8")],
            gateway_ip=None,
            batch_size=64,
            max_hosts=130,
        ))

        self.assertEqual([len(batch) for batch in batches], [64, 64, 2])
        self.assertEqual(batches[0][0], "10.0.0.1")
        self.assertEqual(batches[-1][-1], "10.0.0.130")

    def test_merge_proc_arp_cache_adds_valid_neighbors_only(self):
        arp_table = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.0.2.1        0x1         0x2         aa:bb:cc:dd:ee:01   *        eth0\n"
            "192.0.2.20       0x1         0x2         aa:bb:cc:dd:ee:20   *        eth0\n"
            "192.0.2.21       0x1         0x2         ff:ff:ff:ff:ff:ff   *        eth0\n"
            "192.0.2.22       0x1         0x2         aa:bb:cc:dd:ee:22   *        wlan0\n"
            "198.51.100.10    0x1         0x2         aa:bb:cc:dd:ee:10   *        eth0\n"
        )
        disc = NetworkDiscovery("eth0")

        with mock.patch("builtins.open", mock.mock_open(read_data=arp_table)):
            disc._merge_proc_arp_cache(
                IPv4Network("192.0.2.0/24"),
                "192.0.2.1",
            )

        self.assertEqual(list(disc.devices_dict), ["192.0.2.20"])
        self.assertEqual(
            disc.devices_dict["192.0.2.20"].mac,
            "aa:bb:cc:dd:ee:20",
        )

    @mock.patch("netshaper.network.discovery.subprocess.run")
    def test_merge_ip_neighbor_cache_adds_lladdr_neighbors(self, run_mock):
        run_mock.return_value = mock.Mock(
            returncode=0,
            stdout=(
                "192.0.2.20 lladdr aa:bb:cc:dd:ee:20 REACHABLE\n"
                "192.0.2.21 INCOMPLETE\n"
                "192.0.2.1 lladdr aa:bb:cc:dd:ee:01 STALE\n"
            ),
        )
        disc = NetworkDiscovery("eth0")

        disc._merge_ip_neighbor_cache(
            IPv4Network("192.0.2.0/24"),
            "192.0.2.1",
        )

        self.assertEqual(list(disc.devices_dict), ["192.0.2.20"])
        run_mock.assert_called_once_with(
            ["ip", "-4", "neigh", "show", "dev", "eth0"],
            capture_output=True,
            text=True,
            check=False,
            timeout=1.0,
        )

    def test_arp_sweep_refreshes_even_when_neighbor_cache_is_rich(self):
        disc = NetworkDiscovery("eth0")

        class FakeLayer:
            def __init__(self, *args, **kwargs):
                pass

            def __truediv__(self, _other):
                return self

            def __contains__(self, _item):
                return False

        def seed_cache(_subnet, _gateway_ip, _scope_networks=None):
            for idx in range(20, 36):
                disc._remember_device(
                    f"192.0.2.{idx}",
                    f"aa:bb:cc:dd:ee:{idx:02x}",
                )
            return disc._device_count()

        with mock.patch("netshaper.network.discovery._ensure_scapy_layers"), \
             mock.patch.object(disc, "_merge_neighbor_caches",
                               side_effect=seed_cache), \
             mock.patch("netshaper.network.discovery.Ether", FakeLayer), \
             mock.patch("netshaper.network.discovery.ARP", FakeLayer), \
             mock.patch("netshaper.network.discovery.srp") as srp_mock, \
             mock.patch("netshaper.network.discovery.sniff"), \
             mock.patch("netshaper.network.discovery.time.sleep"), \
             mock.patch("netshaper.network.discovery.print_flush"):
            srp_mock.return_value = ([], None)
            devices = disc.arp_sweep("192.0.2.0/24", "192.0.2.1")

        self.assertEqual(len(devices), 16)
        self.assertEqual(srp_mock.call_count, 8)

    def test_arp_sweep_limits_active_targets_to_authorized_scope(self):
        disc = NetworkDiscovery("eth0")

        class FakeLayer:
            def __init__(self, *args, **kwargs):
                pass

            def __truediv__(self, _other):
                return self

            def __contains__(self, _item):
                return False

        with mock.patch("netshaper.network.discovery._ensure_scapy_layers"), \
             mock.patch.object(disc, "_merge_neighbor_caches",
                               return_value=0), \
             mock.patch.object(disc, "_target_batches_from_scopes",
                               wraps=disc._target_batches_from_scopes) as batches_mock, \
             mock.patch("netshaper.network.discovery.Ether", FakeLayer), \
             mock.patch("netshaper.network.discovery.ARP", FakeLayer), \
             mock.patch("netshaper.network.discovery.srp",
                        return_value=([], None)), \
             mock.patch("netshaper.network.discovery.sniff"), \
             mock.patch("netshaper.network.discovery.time.sleep"), \
             mock.patch("netshaper.network.discovery.print_flush"):
            disc.arp_sweep(
                "192.0.2.0/24",
                "192.0.2.1",
                [ip_network("192.0.2.64/28")],
            )

        scope_networks = batches_mock.call_args.args[0]
        self.assertEqual(scope_networks, [IPv4Network("192.0.2.64/28")])
        self.assertEqual(batches_mock.call_args.kwargs["max_hosts"], 4096)

    def test_authorized_scope_filters_neighbor_cache_entries(self):
        arp_table = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.0.2.65       0x1         0x2         aa:bb:cc:dd:ee:65   *        eth0\n"
            "192.0.2.20       0x1         0x2         aa:bb:cc:dd:ee:20   *        eth0\n"
        )
        disc = NetworkDiscovery("eth0")

        with mock.patch("builtins.open", mock.mock_open(read_data=arp_table)):
            disc._merge_proc_arp_cache(
                IPv4Network("192.0.2.0/24"),
                "192.0.2.1",
                [IPv4Network("192.0.2.64/28")],
            )

        self.assertEqual(list(disc.devices_dict), ["192.0.2.65"])

    def test_default_gateway_uses_selected_interface_and_lowest_metric(self):
        route_table = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            "lo\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
            "wlan0\t00000000\t0102A8C0\t0003\t0\t0\t5\t00000000\t0\t0\t0\n"
            "eth0\t00000000\t010200C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n"
            "eth0\t00000000\tFE0200C0\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
        )
        disc = NetworkDiscovery("eth0")

        with mock.patch("builtins.open", mock.mock_open(read_data=route_table)):
            gateway = disc.get_default_gateway()

        self.assertEqual(gateway, "192.0.2.254")

    def test_default_gateway_ipv6_uses_selected_interface_and_lowest_metric(self):
        zero = "00000000000000000000000000000000"
        route_table = (
            f"{zero} 00 {zero} 00 fe800000000000000000000000000001 "
            "00000001 00000000 00000000 00000000 lo\n"
            f"{zero} 00 {zero} 00 20010db8000000000000000000000001 "
            "00000020 00000000 00000000 00000000 eth0\n"
            f"{zero} 00 {zero} 00 20010db8000000000000000000000002 "
            "00000010 00000000 00000000 00000000 eth0\n"
        )
        disc = NetworkDiscovery("eth0")

        with mock.patch("builtins.open", mock.mock_open(read_data=route_table)):
            gateway = disc.get_default_gateway_ipv6()

        self.assertEqual(gateway, "2001:0db8:0000:0000:0000:0000:0000:0002")

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
