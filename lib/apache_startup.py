#! /usr/bin/python

from axsess import Password
from lxml import etree
import os
import hvac
import warnings
def noop(*args, **kargs): pass
warnings.warn = noop


DOCROOT = '/var/www/html/htdocs'


def submit_passphrase(length=8, boolval=False, data=None):

    with open('/var/www/html/htdocs/apache_trace', 'a') as f:
        f.write('entered function\n')
    common_xml = etree.parse('/var/www/html/htdocs/admin/%s_servers.xml' % os.environ['TestEnv'])
    with open('/var/www/html/htdocs/apache_trace', 'a') as f:
        f.write('parsed config\n')
    atf = common_xml.find('atf')
    vnode = atf.find('vault')
    key_path = vnode.text
    client = hvac.Client(url=os.environ.get('VAULT_ADDR'))
    with open('/var/www/html/htdocs/apache_trace', 'w') as f:
        f.write('called vault\n')
    response = client.auth_approle(os.environ.get('VAULT_ROLE_ID'), os.environ.get('VAULT_SECRET_ID'))
    TOKEN = response['auth']['client_token']
    client.token = TOKEN

    if client.is_authenticated():
        with open('/var/www/html/htdocs/apache_trace', 'a') as f:
                f.write('authenticated\n')
    try:
        with open('/var/www/html/htdocs/apache_trace', 'a') as f:
                f.write('fetching secrets from %s\n' % key_path)
        secrets_dict = client.secrets.kv.read_secret_version(path=key_path, mount_point='atf')
        with open('/var/www/html/htdocs/apache_trace', 'a') as f:
                f.write('obtained secrets\n')
        #assert 'data' in secrets_dict.keys(), 'failed to fetch data from %s' % key_path
        keys = secrets_dict['data']['data']
        passphrase = keys['password']

    except Exception as e:
        passphrase = raw_input('Enter passphrase for certificate key: ')

    return (passphrase)


if __name__ == '__main__':
    print submit_passphrase()

