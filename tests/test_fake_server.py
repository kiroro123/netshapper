import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper import fake_server3


class FakeServerStartupTests(unittest.TestCase):
    def test_packaged_fake_server_exposes_main(self):
        self.assertTrue(callable(fake_server3.main))

    @mock.patch("netshaper.fake_server3.socket.socket")
    def test_bind_dns_socket_binds_before_returning(self, socket_mock):
        sock = mock.Mock()
        socket_mock.return_value = sock

        result = fake_server3.bind_dns_socket(5353)

        self.assertIs(result, sock)
        socket_mock.assert_called_once_with(
            fake_server3.socket.AF_INET6,
            fake_server3.socket.SOCK_DGRAM,
        )
        sock.bind.assert_called_once_with(("::", 5353))

    @mock.patch("netshaper.fake_server3.socket.socket")
    def test_bind_dns_socket_exits_on_bind_failure(self, socket_mock):
        sock = mock.Mock()
        sock.bind.side_effect = OSError("in use")
        socket_mock.return_value = sock

        with self.assertRaises(SystemExit):
            fake_server3.bind_dns_socket(5353)

        sock.close.assert_called_once()

    def test_main_binds_dns_before_dropping_privileges(self):
        events = []
        args = SimpleNamespace(
            host_ip="192.0.2.10",
            dns_port=5353,
            http_port=8080,
        )
        dns_sock = mock.Mock()
        httpd = mock.Mock()
        httpd.serve_forever.side_effect = KeyboardInterrupt
        thread_obj = mock.Mock()

        def bind_dns(port):
            events.append(("bind_dns", port))
            return dns_sock

        def http_server(addr, handler):
            events.append(("http_bind", addr, handler))
            return httpd

        def drop(user):
            events.append(("drop", user))

        def make_thread(target, args, daemon):
            events.append(("thread", target, args, daemon))
            return thread_obj

        with mock.patch("netshaper.fake_server3.parse_args", return_value=args), \
             mock.patch("netshaper.fake_server3.configure_dns"), \
             mock.patch("netshaper.fake_server3.bind_dns_socket", side_effect=bind_dns), \
             mock.patch("netshaper.fake_server3.DualStackHTTPServer", side_effect=http_server), \
             mock.patch("netshaper.fake_server3.drop_privileges", side_effect=drop), \
             mock.patch("netshaper.fake_server3.print_dns_startup"), \
             mock.patch("netshaper.fake_server3.threading.Thread", side_effect=make_thread), \
             mock.patch("builtins.print"):
            fake_server3.main()

        self.assertEqual(events[0], ("bind_dns", 5353))
        self.assertEqual(events[1][0], "http_bind")
        self.assertEqual(events[2], ("drop", "nobody"))
        self.assertEqual(
            events[3],
            ("thread", fake_server3.serve_dns, (dns_sock,), True),
        )
        thread_obj.start.assert_called_once()
        httpd.serve_forever.assert_called_once()


class ParseDnsQuestionTests(unittest.TestCase):
    def _make_query(self, name: str, qtype: int = 1) -> bytes:
        """Build a minimal DNS query for the given name."""
        header = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        labels = b''
        for part in name.split('.'):
            encoded = part.encode('ascii')
            labels += bytes([len(encoded)]) + encoded
        labels += b'\x00'
        question = labels + qtype.to_bytes(2, 'big') + b'\x00\x01'
        return header + question

    def test_parse_simple_name_returns_correct_domain_and_qtype(self):
        data = self._make_query('example.com', qtype=1)
        domain, qtype, question_end = fake_server3.parse_dns_question(data)
        self.assertEqual(domain, 'example.com')
        self.assertEqual(qtype, 1)
        self.assertEqual(question_end, len(data))

    def test_parse_aaaa_query_returns_qtype_28(self):
        data = self._make_query('example.com', qtype=28)
        domain, qtype, question_end = fake_server3.parse_dns_question(data)
        self.assertEqual(qtype, 28)

    def test_parse_too_short_returns_none(self):
        domain, qtype, question_end = fake_server3.parse_dns_question(b'\x00' * 11)
        self.assertIsNone(domain)
        self.assertIsNone(qtype)
        self.assertIsNone(question_end)

    def test_parse_compressed_name_uses_wire_position_for_qtype(self):
        """
        Compression pointer in question: wire QTYPE must be read from just after
        the 2-byte pointer, NOT from the end of the pointed-to label sequence.

        Layout: header(12) | pointer(2) | QTYPE(2) | QCLASS(2) | suffix(12)
                0..11       | 12,13      | 14,15     | 16,17     | 18..29
        The pointer at offset 12 points to the suffix at offset 18.
        """
        header      = b'\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        suffix      = b'\x04test\x05local\x00'   # 12 bytes
        suffix_off  = 18                          # header(12) + pointer(2) + qtype(2) + qclass(2)
        pointer     = bytes([0xC0, suffix_off])
        qtype_bytes = b'\x00\x01'                # A record
        qclass_bytes = b'\x00\x01'               # IN
        data = header + pointer + qtype_bytes + qclass_bytes + suffix

        domain, qtype, question_end = fake_server3.parse_dns_question(data)
        self.assertEqual(domain, 'test.local')
        self.assertEqual(qtype, 1)
        # wire_end = 14 (pointer offset 12 + 2), question_end = 14 + 4 = 18
        self.assertEqual(question_end, 18)

    def test_parse_pointer_loop_returns_none(self):
        """A self-referential pointer must not loop forever."""
        # Header + a pointer that points to itself (offset 12)
        header = b'\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        data = header + b'\xc0\x0c' + b'\x00\x01\x00\x01'
        domain, qtype, question_end = fake_server3.parse_dns_question(data)
        self.assertIsNone(domain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
