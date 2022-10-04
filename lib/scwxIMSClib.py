import os
import sys
import re
from lxml import etree
from lxml.builder import E
from types import *
from robot.api import logger as logging
from robot.api.deco import keyword
import paramiko
from paramiko_expect import SSHClientInteraction
import warnings
from axsess import Password
from atfvars import varImport
from copy import deepcopy


PROMPT = '.*[#\$\>] '
PW_PROMPT = '.*[#\$\>:]'
PROMPT2 = '.*\> '
SESSION_TIMEOUT = 1800

DOCROOT = '/var/www/html/htdocs'
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())

import logging

LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

class SSHKey_Connect:
    def __init__(self, remote_host, **evars):
	import getpass
	self.__dict__.update(evars)
        if not 'device' in evars:
            self.device = remote_host
	if not '%s_IP' % self.device in self.__dict__:
		raise AssertionError, 'device "%s" was not found in the ATF configuration for user "%s"' % (self.device, self.ATF_User)
	user = getpass.getuser()
	paramiko.util.log_to_file('/var/www/cgi-bin/logs/paramiko.log')
        warnings.simplefilter('ignore')
        paramiko.util.log_to_file('/var/www/cgi-bin/logs/paramiko.log')
        self.ip = evars['%s_IP' % self.device]
        self.connection_established = False
        self.sftp_chan = None
        assert len(self.ip) > 0, 'No IP address for device %s' % device
        self.error = ''
        try:
            from paramiko.transport import Transport
            from paramiko.hostkeys import HostKeys

            keys = HostKeys()
            keys.load(os.path.expanduser('~/.ssh/known_hosts'))

            logging.debug('creating transport session for %s' % self.ip)
            T = Transport((self.ip, 22))
            logging.debug('starting transport client for %s' % self.ip)
            T.start_client()
            key = T.get_remote_server_key()
            if self.device == 'isensor':
                logging.debug('attempting to add new nost keys from %s to local known hosts at %s' % (
                    self.ip, os.path.expanduser('~/.ssh/known_hosts')))
                keys.add(self.ip, key.get_name(), key)
                keys.save(os.path.expanduser('~/.ssh/known_hosts'))
        except Exception as estr:
            logging.error('unable to insert key for %s\n%s into known_hosta' % (self.ip, str(estr)))


        self.cnx = paramiko.client.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            keypathstr = '%s_Sshkey' % self.device
	    assert keypathstr in self.__dict__, 'SSH key path missing from %s_servers.xml for device %s' % (self.TestEnv.lower(), self.device)
	    keypath = self.__dict__[keypathstr]
            logging.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
            try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    logging.debug(
                        "Connection established %s (%s) for user %s using shared key" % (self.device, self.ip, user))
                    self.connection_established = True
            except:
                    logging.error(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.connection_established = False
        except Exception as error:
            self.error = "Connection failure to device (%s) at %s, user:%s\n%s" % (
                self.device, self.ip, user, str(error) )
            logging.error(self.error)
            self.connection_established = False
        assert self.connection_established == True, 'Unable to connect to %s @ %s using %s credentials \n%s' % (
            self.device, self.ip, user, str(error))
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
            try:
                self.sftp_client = paramiko.sftp_client.SFTPClient
            except Exception as error:
                print str(error)
                trap
        self.user = user

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            logging.error(self.error)
            raise AssertionError, self.error

    def cmd(self, command, **kwords):
        log = logging.debug if not 'logdebug' in kwords or kwords['logdebug'] != True else logging.info

        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            log("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)
        except:
            self.reconnect()
            stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)

        response = stdout.read()
        if response == '':
            respone = stderr.read()
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            log("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def sudo(self, command, **flags):
        flist = ''
        if len(flags) > 0:
            for f in flags.keys():
                flist += " \-%s %s" % (f, flags[f])

        logging.info('Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
        stdin, stdout, stderr = self.cnx.exec_command("sudo -S %s 2>&1" % command)
        stdin.write("%s\n" % self.password)
        stdin.flush()
        response = stdout.read()
        if response == '':
            respone = stderr.read()
        logging.info("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def pushfile(self, source, destination):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        try:
            filestats = os.stat(source)
            size = filestats.st_size
        except Exception as error:
            raise AssertionError, 'ERROR - cannot read source file %s' % source

        try:
            self.sftp_chan = self.sftp_client.from_transport(self.transport)
            self.sftp_chan.put(source, destination)
        except Exception as error:
            raise AssertionError, 'ERROR - failed to copy %s to %s (%s)' % (source, destination, str(error))

    def pullfile(self, destination, source):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        try:
            self.sftp_chan = self.sftp_client.from_transport(self.transport)
            self.sftp_chan.get(source, destination)
        except Exception as error:
            raise AssertionError, 'ERROR - failed to copy %s to %s (%s)' % (source, destination, str(error))

def get_private_key():
    try:
        fxml = etree.parse('%s/admin/%s_servers.xml' % (DOCROOT, os.environ['TestEnv']))
        keynode = fxml.find('atf/private-key')
        if keynode == None:
            return (None)
        keypath = keynode.attrib['name']
        return (keypath)
    except Exception as estr:
        raise AssertionError, 'Cannot locate private key path: %s' % str(estr)





class mq_xmit_call(object):
    def __call__(self, pFunction):
	def mq_xmit_call(self, **opts):
	    warnings.simplefilter('ignore')
	    if not 'rcms_IP' in self.__dict__ or self.rcms_IP == None:
		return ('ERROR: the IMSC device address is not in the configuration')
            rcms_expect = paramiko.SSHClient()
            rcms_expect.load_system_host_keys()
            rcms_expect.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            rcms_expect.connect(hostname=self.rcms_IP) #, username=self.rcms_User, password=self.rcms_Password)
            try:
                interact = SSHClientInteraction(rcms_expect, timeout=200, display=False)
		interact.expect(PROMPT)
		interact.send('/secureworks/bin/RCMSMQTransmit\n')

		"""
		print('Expecting prompt "%s"' % PW_PROMPT)
		interact.expect(PW_PROMPT)
		assert interact.current_output_clean.find('ERROR') < 0, '%s' % interact.current_output_clean.replace('/secureworks/bin/RCMSMQTransmit\n','')
		#print('expect: "Enter PEM pass phrase:"')	
                #interact.expect('Enter PEM pass phrase:')
                interact.send(r'%s\n' % self.rcms_Password)
		print('\nsent: password: "%s"' % self.rcms_Password)
		"""

                interact.expect(PROMPT)
		error = interact.current_output_clean.find('ERROR')
		if error >=0:
			raise AssertionError, interact.current_output_clean
            except Exception as estr:
		interact.send('quit\n')
		interact.expect(PROMPT)
                return ('ERROR:\tunable to establish an RCMSMQTransmit dialog @ %s...\n\t%s' % (
				self.rcms_IP, re.split(self.prompt,str(estr).replace('\n','\n\t'))[0] ))
            try:
		
                rval = pFunction(self, interact, **opts)
            except Exception as estr:
                return ('ERROR: the RCMSMQTransmit command resulted in an exception:\nexception=%s' % (estr))	
	    interact.send('quit\n')
	    interact.expect(PROMPT)
            rcms_expect.close()
	    if rval.find('ERROR') >= 0:
		error = re.findall('^.*(ERROR.*$)', rval, re.MULTILINE)
		if len(error) > 0:
			return (error[0])
            return (rval)

        return (mq_xmit_call)
		



class RCMS:
    @varImport()
    def __init__(self, **evars):
	self.__dict__.update(evars)
	self.device = evars['device'] = 'rcms'
	self.keypath = evars['keypath'] = get_private_key()
	self.evars = evars
	self.imsc = SSHKey_Connect('rcms', **evars)
	self.cmd = self.imsc.cmd
	self.cnx = self.imsc.cnx
	self.identity = self.cmd('whoami').rstrip('\n')
	self.hostname = self.cmd('hostname').rstrip('\n')
	self.prompt = '\[%s@%s.*\]\$' % (self.identity, self.hostname)

    @mq_xmit_call()
    def call_rcms_mq_command(self, dialog, **opts):
	cmd = opts['command']
	dialog.send('%s\n' % cmd)
	dialog.expect(PROMPT)
	response = dialog.current_output_clean.replace(cmd,'')
	s = re.findall('^Command Accepted - ID is \d+$',response, re.MULTILINE)
	try:
		strip_prefix = response.replace('\n%s\n' % s[0],'')
	except:
		return(response)
	suffix = strip_prefix.find('====== END OF RESULTS')
	rstr = re.findall('(?<=\s\>\s).*$', strip_prefix[:suffix], re.MULTILINE)
	try:
		return(rstr[0].rstrip('\n'))
	except IndexError:
		return(strip_prefix[:suffix])
	
	#return(dialog.current_output_clean)

    @keyword()
    def RCMSMQTransmit(self, cmd, **opts):
	starts_with_3 = re.findall('^3.*',cmd, re.MULTILINE)
	if len(starts_with_3) > 0:
		prefix = None
	else:
		prefix = '3'
	
	try:
		parse_for_uin = re.findall('((F|G|V)(\-\d{5}))',cmd)
		uin = parse_for_uin[0][0]
		cmdstr = cmd
	except:
		try:
			uin = self.Get_UIN_From_iSensor()
			if prefix == None:
				cmdstr = '%s %s' % (uin, cmd)
			else:
				cmdstr = '%s 3 %s' % (uin, cmd)
		except:
			raise AssertionError, 'missing UIN'
	#cmdstr = cmd
	response = self.call_rcms_mq_command(command=cmdstr)
	offline = response.find('Device appears to be offline')
	if offline >= 0:
		return('ERROR: device "%s" appears to be offline' % str(uin))
	return(response)

    @keyword()
    def Get_UIN_From_iSensor(self, **opts):
	self.__dict__.update(opts)
	self.device = 'isensor'
	try:
		isensor_vars = {
				'isensor_IP' 		: self.isensor_IP,
				'isensor_Sshkey'	: self.isensor_Sshkey,
				'TestEnv'		: self.TestEnv,
				'ATF_User'		: self.ATF_User,
				}
		self.isensor = SSHKey_Connect('isensor', **isensor_vars)
		uin = self.isensor.cmd('cat /var/iSensor/uin')
		assert uin != None, 'UIN does no appear to be on the isensor at %s' % self.isensor_IP 
		self.uin = uin.rstrip('\n')
	except Exception as estr:
		return('ERROR: Unable to communicate with iSensor at %s...' % (self.isensor_IP, str(estr)))
	return(self.uin)




