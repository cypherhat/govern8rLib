import configparser
import os

file_name = 'notaryconfig.ini'


def config_exists():
    if os.path.exists(file_name) and os.path.isfile(file_name):
        return True
    else:
        return False


def read_configuration():
    if config_exists():
        config = configparser.ConfigParser()
        config.read(file_name)
        return config


class NotaryConfiguration(object):
    """An encapsulated configuration reading.
    """

    def __init__(self):
        if not config_exists():
            raise ValueError('Configuration does not exist!')
        self.config = read_configuration()

    def get_block_cypher_url(self):
        if self.config.has_option('DEFAULT', 'block_cypher_url'):
            return self.config.get('DEFAULT', 'block_cypher_url')
        else:
            raise ValueError('Value does not exist!')

    def get_server_url(self):
        if self.config.has_option('DEFAULT', 'server_url'):
            return self.config.get('DEFAULT', 'server_url')
        else:
            raise ValueError('Value does not exist!')

    def get_db_url(self):
        if self.config.has_option('DEFAULT', 'db_url'):
            return self.config.get('DEFAULT', 'db_url')
        else:
            raise ValueError('Value does not exist!')

    def get_block_cypher_token(self):
        if self.config.has_option('DEFAULT', 'block_cypher_token'):
            return self.config.get('DEFAULT', 'block_cypher_token')
        else:
            raise ValueError('Value does not exist!')
    def get_test_mode(self):
        if self.config.has_option('DEFAULT', 'test_mode'):
            return self.config.getboolean('DEFAULT', 'test_mode')
        else:
            raise ValueError('Value does not exist!')
    def get_ssl_verify_mode(self):
        if self.config.has_option('DEFAULT', 'verify_ssl'):
            return self.config.getboolean('DEFAULT', 'verify_ssl')
        else:
            raise ValueError('Value does not exist!')

    def get_uploads_directory(self):
        if self.config.has_option('DEFAULT', 'uploads_directory'):
            return self.config.get('DEFAULT', 'uploads_directory')
        else:
            raise ValueError('Value does not exist!')