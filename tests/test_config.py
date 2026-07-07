import logging
import os
import stat
import tempfile
import unittest
from logging.handlers import RotatingFileHandler
from unittest import mock

from netshaper import config


class ConfigLoggingTests(unittest.TestCase):
    def test_configured_log_level_accepts_known_level(self):
        with mock.patch.dict(os.environ, {"NETSHAPER_LOG_LEVEL": "debug"}):
            self.assertEqual(config._configured_log_level(), logging.DEBUG)

    def test_configured_log_level_rejects_unknown_level(self):
        with mock.patch.dict(os.environ, {"NETSHAPER_LOG_LEVEL": "loud"}):
            self.assertEqual(config._configured_log_level(), logging.INFO)

    def test_secure_log_handler_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "nested", "netshaper.log")
            handler = config._secure_log_handler(log_file)

            self.assertIsInstance(handler, RotatingFileHandler)
            self.assertEqual(
                stat.S_IMODE(os.stat(log_file).st_mode),
                0o600,
            )
            self.assertEqual(handler.maxBytes, config.LOG_MAX_BYTES)
            self.assertEqual(handler.backupCount, config.LOG_BACKUP_COUNT)
            handler.close()

    def test_secure_log_handler_rejects_symlink_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target.log")
            log_file = os.path.join(tmp, "netshaper.log")
            with open(target, "w", encoding="utf-8"):
                pass
            os.symlink(target, log_file)

            handler = config._secure_log_handler(log_file)

            self.assertIsNone(handler)

    def test_root_logging_rejects_non_root_owned_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_lstat = os.lstat
            untrusted = os.path.abspath(tmp)

            def fake_lstat(path):
                result = original_lstat(path)
                if os.path.abspath(os.fspath(path)) == untrusted:
                    values = list(result)
                    values[4] = 1234
                    return os.stat_result(values)
                return result

            with mock.patch("netshaper.config.os.geteuid", return_value=0), \
                 mock.patch("netshaper.config.os.lstat", side_effect=fake_lstat):
                handler = config._secure_log_handler(
                    os.path.join(tmp, "netshaper.log")
                )

            self.assertIsNone(handler)

    def test_configure_logging_uses_environment_overrides(self):
        root_logger = mock.Mock()
        root_logger.handlers = []
        file_handler = mock.Mock()

        with mock.patch.dict(
            os.environ,
            {
                "NETSHAPER_LOG_FILE": "/tmp/netshaper-custom.log",
                "NETSHAPER_LOG_LEVEL": "warning",
            },
        ), mock.patch(
            "netshaper.config.logging.getLogger",
            return_value=root_logger,
        ), mock.patch(
            "netshaper.config._secure_log_handler",
            return_value=file_handler,
        ) as handler_mock, mock.patch(
            "netshaper.config.logging.basicConfig",
        ) as basic_config_mock:
            config.configure_logging()

        handler_mock.assert_called_once_with("/tmp/netshaper-custom.log")
        basic_config_mock.assert_called_once()
        kwargs = basic_config_mock.call_args.kwargs
        self.assertEqual(kwargs["level"], logging.WARNING)
        self.assertIs(kwargs["handlers"][0], file_handler)


if __name__ == "__main__":
    unittest.main(verbosity=2)
