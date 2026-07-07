from contextlib import contextmanager
from ipaddress import IPv4Network
import sys
import types
import unittest

from netshaper.network.exploit.arp_amplification import (
    ARPAmplificationError,
    ARPAmplificationProfile,
    ARPAmplifier,
)


ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"
GATEWAY_MAC = "00:11:22:33:44:55"


class Ether:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __truediv__(self, other):
        return FakePacket([self, other])


class ARP:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class FakePacket:
    def __init__(self, layers):
        self.layers = layers

    def __truediv__(self, other):
        return FakePacket([*self.layers, other])

    def __getitem__(self, layer_type):
        for layer in self.layers:
            if isinstance(layer, layer_type):
                return layer
        raise KeyError(layer_type)


class FakePacketBackend:
    def __init__(self):
        self.calls = []

    def send(self, packet, interface: str) -> None:
        self.calls.append((packet, interface))


def _profile(**overrides) -> ARPAmplificationProfile:
    values = {
        "gateway_ip": "192.0.2.1",
        "gateway_mac": GATEWAY_MAC,
        "attacker_mac": ATTACKER_MAC,
        "subnet": IPv4Network("192.0.2.0/24"),
        "phantom_count": 128,
        "burst_size": 5,
        "cycle_interval": 0.05,
        "randomize_phantom_order": False,
    }
    values.update(overrides)
    return ARPAmplificationProfile(**values)


@contextmanager
def fake_scapy_all():
    module = types.ModuleType("scapy.all")
    module.ARP = ARP
    module.Ether = Ether
    previous = sys.modules.get("scapy.all")
    sys.modules["scapy.all"] = module
    try:
        yield
    finally:
        if previous is None:
            sys.modules.pop("scapy.all", None)
        else:
            sys.modules["scapy.all"] = previous


class ARPAmplificationTests(unittest.TestCase):
    def test_amplification_cycle_uses_burst_as_total_frame_budget(self):
        for burst_size in (1, 5, 50):
            with self.subTest(burst_size=burst_size):
                backend = FakePacketBackend()
                amplifier = ARPAmplifier(
                    "eth0",
                    ATTACKER_MAC,
                    packet_backend=backend,
                )
                profile = _profile(burst_size=burst_size)

                with fake_scapy_all():
                    sent = amplifier._send_amplification_cycle(
                        profile,
                        amplifier._phantom_ip_pool(profile),
                    )

                self.assertEqual(sent, burst_size)
                self.assertEqual(len(backend.calls), burst_size)
                self.assertEqual(
                    {interface for _, interface in backend.calls},
                    {"eth0"},
                )

    def test_poison_gateway_false_omits_gateway_directed_packets(self):
        backend = FakePacketBackend()
        amplifier = ARPAmplifier("eth0", ATTACKER_MAC, packet_backend=backend)
        profile = _profile(
            burst_size=10,
            poison_gateway=False,
            use_gratuitous=True,
        )

        with fake_scapy_all():
            sent = amplifier._send_amplification_cycle(
                profile,
                amplifier._phantom_ip_pool(profile),
            )

        self.assertEqual(sent, 10)
        self.assertTrue(
            all(packet[ARP].pdst != profile.gateway_ip for packet, _ in backend.calls)
        )
        self.assertTrue(
            all(
                packet[ARP].hwdst == "ff:ff:ff:ff:ff:ff"
                for packet, _ in backend.calls
            )
        )

    def test_phantom_pool_is_bounded_for_broad_subnets(self):
        profile = _profile(
            gateway_ip="10.0.0.1",
            subnet=IPv4Network("10.0.0.0/8"),
            phantom_count=256,
        )

        pool = ARPAmplifier._phantom_ip_pool(profile)

        self.assertEqual(len(pool), 256)
        self.assertNotIn(profile.gateway_ip, pool)

    def test_profile_validates_direct_library_safety_bounds(self):
        with self.assertRaisesRegex(ARPAmplificationError, "Burst size"):
            _profile(burst_size=51)

        with self.assertRaisesRegex(ARPAmplificationError, "Cycle interval"):
            _profile(cycle_interval=0.001)

        with self.assertRaisesRegex(ARPAmplificationError, "Phantom count"):
            _profile(phantom_count=4097)

    def test_cam_options_validate_direct_library_safety_bounds(self):
        with self.assertRaisesRegex(ARPAmplificationError, "CAM burst"):
            ARPAmplifier._validate_cam_options(
                phantom_count=256,
                burst=51,
                interval=0.05,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
