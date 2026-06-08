import unittest
from types import SimpleNamespace
from unittest import mock

import fake_server3
from netshaper import fake_server3 as packaged_fake_server


class FakeServerStartupTests(unittest.TestCase):
    def test_packaged_fake_server_exposes_main(self):
        self.assertTrue(callable(packaged_fake_server.main))

    @mock.patch("fake_server3.socket.socket")
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

    @mock.patch("fake_server3.socket.socket")
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

        with mock.patch("fake_server3.parse_args", return_value=args), \
             mock.patch("fake_server3.configure_dns"), \
             mock.patch("fake_server3.bind_dns_socket", side_effect=bind_dns), \
             mock.patch("fake_server3.DualStackHTTPServer", side_effect=http_server), \
             mock.patch("fake_server3.drop_privileges", side_effect=drop), \
             mock.patch("fake_server3.print_dns_startup"), \
             mock.patch("fake_server3.threading.Thread", side_effect=make_thread), \
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
