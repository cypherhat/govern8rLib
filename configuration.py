import configparser
import os
import socket


class NotaryConfiguration(object):
    """An encapsulated configuration reading.
    """

    def __init__(self, file_name):
        self.host = socket.gethostname()
        print ("Host: %s" % self.host)
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
        local_hosts = self.get_local_hosts()
        for local_host in local_hosts:
            if self.host in local_host or local_host in self.host:
                return True
        return False

    def get_local_hosts(self):
        if self.config.has_option('DEFAULT', 'local_hosts'):
            return self.config.get('DEFAULT', 'local_hosts')
        else:
            raise ValueError('Value does not exist!')

    def get_block_cypher_url(self):
        if self.config.has_option('DEFAULT', 'block_cypher_url'):
            return self.config.get('DEFAULT', 'block_cypher_url')
        else:
            raise ValueError('Value does not exist!')

    def get_local_server_url(self):
        if self.config.has_option('DEFAULT', 'local_server_url'):
            return self.config.get('DEFAULT', 'local_server_url')
        else:
            raise ValueError('Value does not exist!')

    def get_remote_server_url(self):
        if self.config.has_option('DEFAULT', 'remote_server_url'):
            return self.config.get('DEFAULT', 'remote_server_url')
        else:
            raise ValueError('Value does not exist!')

    def get_server_url(self):
        if self.is_local_host():
            return self.get_local_server_url()
        else:
            return self.get_remote_server_url()

    def get_local_db_url(self):
        if self.config.has_option('DEFAULT', 'local_db_url'):
            return self.config.get('DEFAULT', 'local_db_url')
        else:
            raise ValueError('Value does not exist!')

    def get_remote_db_url(self):
        if self.config.has_option('DEFAULT', 'remote_db_url'):
            return self.config.get('DEFAULT', 'remote_db_url')
        else:
            raise ValueError('Value does not exist!')

    def get_db_url(self):
        if self.is_local_host():
            return self.get_local_db_url()
        else:
            return self.get_remote_db_url()

    def get_block_cypher_token(self):
        if self.config.has_option('DEFAULT', 'block_cypher_token'):
            return self.config.get('DEFAULT', 'block_cypher_token')
        else:
            raise ValueError('Value does not exist!')

    def is_remote_testing(self):
        if self.config.has_option('DEFAULT', 'remote_testing'):
            return self.config.getboolean('DEFAULT', 'remote_testing')
        else:
            return True

    def get_coin_network(self):
        if self.config.has_option('DEFAULT', 'coin_network'):
            return self.config.get('DEFAULT', 'coin_network')
        else:
            raise ValueError('Value does not exist!')

    def get_ssl_verify_mode(self):
        if self.config.has_option('DEFAULT', 'verify_ssl'):
            return self.config.getboolean('DEFAULT', 'verify_ssl')
        else:
            raise ValueError('Value does not exist!')
