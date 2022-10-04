import os, sys
import json
import hvac

import warnings

def noop(*args, **kargs): pass

warnings.warn = noop

class Vault(object):
    __VAULT_CLIENT = None
    __TOKEN = None
    __MOUNT_POINT = None        # This variable is expecting the vault project name or mount point.

    @classmethod
    def login(cls, vault_mount_point):
        """
        Login to vault using app_role method and assigned values to the following private global variables:
        """
        client = hvac.Client(url=os.environ.get('VAULT_ADDR'))
        response = client.auth.approle.login(role_id=os.getenv('VAULT_ROLE_ID'), secret_id=os.getenv('VAULT_SECRET_ID'))
        cls.__TOKEN = response['auth']['client_token']
        cls.__MOUNT_POINT = vault_mount_point
        client.token = cls.__TOKEN
        cls.__CLIENT = client
        cls.__TOKEN = response['auth']['client_token']

        assert client.is_authenticated()

    @classmethod
    def is_authenticated(cls):
        """
        :returns: a boolean value associated with the token status
        """
        return cls.__CLIENT.is_authenticated()

    @classmethod
    def get_client(cls):
        return cls.__CLIENT

    @classmethod
    def get_vault_token(cls):
        """
        Returns the token id associated with the vault authentication
        :returns: str vault token id
        """
        return cls.__TOKEN


    @classmethod
    def read_all_secrets(cls, path):
        """
        Reads the value of a key in Vault given its absolute path
        :param str path: full vault key path excluding the project/mount_point name
        :returns: a dict with the values associated with the specified path
        """

        try:
            secrets_dict = cls.__CLIENT.secrets.kv.read_secret_version(path=path, mount_point=cls.__MOUNT_POINT)
            # check if 'data' exists in the read json response

            if 'data' in secrets_dict.keys():
                return secrets_dict['data']['data']
            else:
                return None
        except Exception as e:
            raise AssertionError('Failed to read from Vault %s\n' % str(e))


    @classmethod
    def read_secret(cls, path, key):
        """
        Reads the value of a key in Vault given its absolute path excluding the project/mount_point name
        :param str path: full vault key path excluding the project/mount_point name
        :param str key: the secret key
        :returns: a single value associated with the specified key
        """
        try:
            # read a dictionary of items in the specified path
            secrets_dict = cls.__CLIENT.secrets.kv.read_secret_version(path=path, mount_point=cls.__MOUNT_POINT)
            # check if 'data' exists in the read json response
            if 'data' in secrets_dict.keys():
                return secrets_dict['data']['data'][key]
            else:
                return None
        except Exception as e:
            raise AssertionError("Failed to read or find the param {} from Vault".format(key))

    @classmethod
    def delete_secret(cls, path):
        pass

# Tests
if __name__ == "__main__":
    login('atf')

