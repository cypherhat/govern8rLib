import configparser
import os
import socket
import logging


class NotaryConfiguration(object):
    """An encapsulated configuration reading.
    """

    def __init__(self, file_name):
        self.host = socket.gethostname()
        self.file_name = file_name
        if not self.config_exists():
            raise ValueError('Configuration does not exist!')
        self.config = self.read_configuration()

    def config_exists(self):
        if os.path.exists(self.file_name) and os.path.isfile(self.file_name):
            return True
        else:
            return False

    def read_configuration(self):
        if self.config_exists():
            config = configparser.ConfigParser()
            config.read(self.file_name)
            return config

    def is_local_host(self):
        local_hosts = self.get_local_hosts().split(",")
        for local_host in local_hosts:
            if self.host.strip() == local_host.strip():
                return True
        return False

    def get_local_hosts(self):
        if self.config.has_option('DEFAULT', 'local_hosts'):
            return str(self.config.get('DEFAULT', 'local_hosts'))
        else:
            raise ValueError('Value does not exist!')

    def get_block_cypher_url(self):
        if self.config.has_option('DEFAULT', 'block_cypher_url'):
            return str(self.config.get('DEFAULT', 'block_cypher_url'))
        else:
            raise ValueError('Value does not exist!')

    def get_sender_email(self):
        if self.config.has_option('DEFAULT', 'sender_email'):
            return str(self.config.get('DEFAULT', 'sender_email'))
        else:
            raise ValueError('Value does not exist!')

    def get_recipient_emails(self):
        if self.config.has_option('DEFAULT', 'recipient_emails'):
            return str(self.config.get('DEFAULT', 'recipient_emails')).split(",")
        else:
            raise ValueError('Value does not exist!')

    def get_debug_log(self):
        if self.config.has_option('DEFAULT', 'debug_log'):
            return str(self.config.get('DEFAULT', 'debug_log'))
        else:
            raise ValueError('Value does not exist!')

    def get_local_server_url(self):
        if self.config.has_option('DEFAULT', 'local_server_url'):
            return str(self.config.get('DEFAULT', 'local_server_url'))
        else:
            raise ValueError('Value does not exist!')

    def get_remote_server_url(self):
        if self.config.has_option('DEFAULT', 'remote_server_url'):
            return str(self.config.get('DEFAULT', 'remote_server_url'))
        else:
            raise ValueError('Value does not exist!')

    def get_server_url(self):
        if self.is_local_host():
            return self.get_local_server_url()
        else:
            return self.get_remote_server_url()

    def get_local_db_url(self):
        if self.config.has_option('DEFAULT', 'local_db_url'):
            return str(self.config.get('DEFAULT', 'local_db_url'))
        else:
            raise ValueError('Value does not exist!')

    def get_remote_db_url(self):
        if self.config.has_option('DEFAULT', 'remote_db_url'):
            return str(self.config.get('DEFAULT', 'remote_db_url'))
        else:
            raise ValueError('Value does not exist!')

    def get_db_url(self):
        if self.is_local_host():
            return self.get_local_db_url()
        else:
            return self.get_remote_db_url()

    def get_aws_region(self):
        if self.config.has_option('DEFAULT', 'region_name'):
            return str(self.config.get('DEFAULT', 'region_name'))
        else:
            raise ValueError('Value does not exist!')

    def get_block_cypher_token(self):
        if self.config.has_option('DEFAULT', 'block_cypher_token'):
            return str(self.config.get('DEFAULT', 'block_cypher_token'))
        else:
            raise ValueError('Value does not exist!')

    def is_remote_testing(self):
        if self.config.has_option('DEFAULT', 'remote_testing'):
            return self.config.getboolean('DEFAULT', 'remote_testing')
        else:
            return True

    def get_log_level(self):
        if self.config.has_option('DEFAULT', 'logging_level'):
            logging_level = str(self.config.get('DEFAULT', 'logging_level'))
            if logging_level == 'CRITICAL':
                return logging.CRITICAL
            elif logging_level == 'ERROR':
                return logging.ERROR
            elif logging_level == 'WARN':
                return logging.WARNING
            elif logging_level == 'WARNING':
                return logging.WARNING
            elif logging_level == 'INFO':
                return logging.INFO
            elif logging_level == 'DEBUG':
                return logging.DEBUG
            else:
                return logging.NOTSET
        else:
            return logging.NOTSET

    def get_coin_network(self):
        if self.config.has_option('DEFAULT', 'coin_network'):
            return str(self.config.get('DEFAULT', 'coin_network'))
        else:
            raise ValueError('Value does not exist!')

    def get_ssl_verify_mode(self):
        if self.config.has_option('DEFAULT', 'verify_ssl'):
            return self.config.getboolean('DEFAULT', 'verify_ssl')
        else:
            raise ValueError('Value does not exist!')

    def get_key_id(self):
        if self.config.has_option('DEFAULT', 'key_id'):
            return str(self.config.get('DEFAULT', 'key_id'))
        else:
            raise ValueError('Value does not exist!')

    def get_bucket_name(self):
        if self.config.has_option('DEFAULT', 'bucket_name'):
            return str(self.config.get('DEFAULT', 'bucket_name'))
        else:
            raise ValueError('Value does not exist!')

    def get_wallet_type(self):
        if self.config.has_option('DEFAULT', 'wallet_type'):
            return str(self.config.get('DEFAULT', 'wallet_type'))
        else:
            raise ValueError('Value does not exist!')
