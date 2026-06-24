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
