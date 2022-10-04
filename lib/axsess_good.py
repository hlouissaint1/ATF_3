#! /usr/bin/python

import sys
import os
import config
import base64
import inspect
from Crypto.Cipher import AES
from Crypto import Random
from os import stat, path, unlink
from hashlib import sha256
from tempfile import mkstemp
from lxml import etree
from lxml.builder import E
from subprocess import call
from os.path import dirname
from copy import deepcopy
from vault import Vault as V

BLOCK_SIZE = 32
PADDING = '}'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

SEED = '/etc/machine-id' if not 'ATF_PRIVATE_KEY' in os.environ else os.environ['ATF_PRIVATE_KEY']
PARSER = etree.XMLParser(remove_blank_text=True)
###########DOCROOT = '/var/www/html/htdocs'
MOUNT_POINT = 'atf'


class vfetch():
    def __call__(self, obj):

        def pw_wrapper(self, env=None, session_user=None, **opts):
            import re

            os.environ['ATF_LIBPATH'] = '/var/www/cgi-bin/lib'
            if env == None and 'TestEnv' in os.environ:
                self.environment = env = os.environ['TestEnv'].lower()
            elif env != None and env.lower() in ['agile', 'pilot', 'production']:
                os.environ['TestEnv'] = self.environment = env.lower()
            else:
                self.environment = 'pilot'
            try:
                V.login(MOUNT_POINT)

            except Exception as estr:
                raise AssertionError('Unable to log into Vault: %s' % str(estr))

            if session_user == None:
                if 'ATF_User' in os.environ:
                    self.session_user = session_user = os.environ['ATF_User']
                elif 'Session_User' in os.environ:
                    os.environ['ATF_User'] = self.session_user = os.environ['Session_User']
                else:
                    os.environ['ATF_User'] = getuser()
            else:
                os.environ['ATF_User'] = self.session_user = session_user
            self.common_server_hosts = '%s/admin/%s_servers.xml' % (config.DOCROOT, self.environment)
            try:
                self.common_xml = etree.parse(self.common_server_hosts, PARSER)
            except Exception as estr:
                print('ERROR: reading server file %s\n%s' % (self.common_server_hosts, str(estr)))
                exit(1)
            self.server_hosts = '%s/%s/%s_servers.xml' % (config.DOCROOT, self.session_user, self.environment)

            try:
                self.xml = etree.parse(self.server_hosts, PARSER)
            except Exception as estr:
                print('ERROR: reading server file %s\n%s' % (self.server_hosts, str(estr)))
                exit(1)

            try:
                self.vault_path = {vpath.getparent().attrib['address'] : [vpath.getparent().tag, vpath.text] for vpath in self.common_xml.xpath('//vault')}
                self.vault_path.update({vpath.getparent().attrib['address'] : [vpath.getparent().tag, vpath.text] for vpath in self.xml.xpath('//vault')})
            except Exception as estr:
                raise AssertionError('Malformed configuration file(s):\n\t%s or \n\t%s:\n\t %s' % (self.common_server_hosts, self.server_hosts, str(estr)))

            """
           :
for vpath in self.xml.xpath('//vault'):
                self.vault_path[vpath.getparent().tag] = vpath.text
            """
            self.rval = obj(self,**opts)

        return (pw_wrapper)


class Password:
    @vfetch()
    def __init__(self, **opts):

        """
          os.environ['ATF_CIPHER'] = V.read_secret('cipher/auth', 'value2')
          except:
             raise AssertionError, 'Unable to log into Vault'
        """
        self.device = self.username = self.certificate = self.password = self.key = None


    def get_device(self, device, att, **opts):
        location = 'agile' if not 'environment' in opts else opts['environment']
        dev = self.xml.xpath('//%s' % (device))
        for device in dev:
            if 'inactive' in device.attrib and device.attrib['inactive'] == 'yes':
                continue
            if att == 'content':
                return (device.text)
            elif att in device.attrib:
                return (device.attrib[att])
        return (None)

    @vfetch()
    def get_credentials(self, **atts):
        users = self.xml.xpath('//username')
        supplied_atts = len(atts)
        self.device = self.username = self.certificate = self.password = None
        DEVICE = lambda s: self.vault_path[s][0]
        VPATH = lambda s: self.vault_path[s][1]
        address = None
        matched = False
        for addr in self.vault_path:
                if 'device' in atts:
                        if DEVICE(addr) != atts['device']:
                                continue
                        self.device = atts.pop('device')
                matched = True
                # check if a device in vault is in the session users config
                devs = self.xml.xpath('//%s[@address="%s"]' % (DEVICE(addr), addr))
                if len(devs) == 0:
                        continue
                dev = devs[0]
                if 'inactive' in list(dev.attrib.keys()) and dev.attrib['inactive'] == 'yes':
                        continue
                dev_atts = list(dev.keys())
                att_keys = list(atts.keys())
                attchk = [True if att_keys[x] in dev_atts and atts[att_keys[x]] == dev.attrib[att_keys[x]] else False for x in range(0, len(att_keys))]
                matched = False not in attchk
                if matched == True:
                        address = addr
                        break
        if matched == False or not address:
                return(None)
        self.device = DEVICE(address)
        allsecrets = V.read_all_secrets(VPATH(address))
        for secret in list(allsecrets.keys()):
                if secret != 'certificate' and secret != 'key':
                        self.__dict__[secret] = allsecrets[secret]
                if 'certpath' in list(allsecrets.keys()):
                        self.certificate = self.check_x509_file(allsecrets['certificate'], allsecrets['certpath'])
                if 'keypath' in list(allsecrets.keys()):
                        self.key = self.check_x509_file(allsecrets['key'], allsecrets['keypath'])
        return (None)

    def check_x509_file(self, content, fpath):

#        if 'CERT_RO' in os.environ and os.environ['CERT_RO'] == 'True':
        return(fpath)
        try:
                if path.exists(fpath) is True:
                        with open(fpath, 'r') as C:
                                if C.read() == content:
                                        return(fpath)
                with open(fpath, 'w') as C:
                        C.write(content)
                return(fpath)
        except IOError:
                raise AssertionError('ERROR: a certificate was found in vault but its path is missing or invalid\n\tnowhere to install certificate %s' % path)
        except Exception as estr:
                raise AssertionError('ERROR: unknown error while attempting to read/write certificate %s' % path)

    def getCredentials(self, device=None, **atts):
        if device != None:
            atts['device'] = device
        if 'return_keypath' in atts:
                return_keypath = atts.pop('return_keypath')
        else:
                return_keypath = 'no'
        self.get_credentials(self.environment, self.session_user, **atts)
        device = 'isensor' if self.device == 'alias' else self.device
        if return_keypath == 'yes':
                return (device, self.username, self.password, self.certificate, self.key) 
        return (device, self.username, self.password, self.certificate)

    @vfetch()
    def Run(self, env, session_user, **opts):
        os.system('/bin/bash')
        parent = os.getppid()
        if parent > 1:
            os.kill(parent, 9)
        exit(0)

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

"""
class vaultToken():
    def __call__(self, obj):

        def pw_wrapper(self, env=None, session_user=None, **opts):

"""

if __name__ == '__main__':
    P = Password()
    if len(sys.argv) > 1 and 'encrypt' in sys.argv[1].lower():
        P.encrypt_password_file()
    P.Run()


