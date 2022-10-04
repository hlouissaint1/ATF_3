#!/usr/bin/python
import sys
import os
from time import time, strftime, sleep, gmtime
import paramiko
import warnings
from robot.api import logger as logging
from robot.api.deco import keyword
import logging
from copy import deepcopy
from lxml import etree


LOGPATH = '/var/www/cgi-bin/logs'
PARAMIKO_LOG = '%s/paramiko.log' % LOGPATH
LOG = 'auto_regression.log'
ISO_PATH = '/var/www/cgi-bin/lib'

if not os.path.exists('%s/%s' % (LOGPATH, LOG)):
    with open('%s/%s' % (LOGPATH, LOG), 'w') as create:
        create.write('created new log')

logging.basicConfig(format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

ATF_LIB = 'scwxDRAClib'


class Connect:
    CLASS_INIT = 'scwxIDRAClib:Connect'

    def __init__(self, **kword):
        from axsess import Password
        from paramiko.hostkeys import HostKeys

        self.error = ''
        keys = HostKeys()
        keys.load(os.path.expanduser('~/.ssh/known_hosts'))
        P = Password()
        if 'remote_host' in kword:
            self.device = device = kword['remote_host']
        else:
            self.device = device = 'idrac'
        warnings.simplefilter('ignore')
        paramiko.util.log_to_file(PARAMIKO_LOG)
        self.ip = P.get_device(self.device, 'address') if not 'address' in kword else kword['address']
        os.environ['%s_IP' % self.device] = self.ip
        if 'username' in kword and 'password' in kword:
            dev = self.device
            user = kword['username']
            pword = kword['password']
            cert = None
        else:
            dev, user, pword, cert = P.getCredentials(address=self.ip)
        assert dev == self.device, 'Invalid remote servers file'
        self.connection_established = False
        self.sftp_chan = None
        self.cert_path = kword['cert_path'] if 'cert_path' in kword else None
        try:
            from paramiko.transport import Transport

            T = Transport((self.ip, 22))
            T.start_client()
            key = T.get_remote_server_key()
            if self.device == 'isensor':
                keys.add(self.ip, key.get_name(), key)
                keys.save(os.path.expanduser('~/.ssh/known_hosts'))
        except Exception as estr:
            pass
        self.error = ''
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        keypath = kword['keypath'] if 'keypath' in kword else None
        try:
            if keypath == None:
                logging.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword)
                logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                logging.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    logging.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except:
                    logging.debug(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.error = ''
                    self.cnx.connect(self.ip, username=user, password=pword)
                    logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                    self.connection_established = True

        except Exception as error:
            self.error = "Connection failure to device at %s, user:%s \n%s" % (self.ip, user, str(error))
            logging.debug(self.error)
            self.connection_established = False
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
            try:
                self.sftp_client = paramiko.sftp_client.SFTPClient
            except Exception as error:
                print str(error)
                trap
        self.user = user
        self.device = device


    def cmd(self, command, **kwords):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            logging.debug("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        cmdstr = 'racadm %s' % command if self.device == 'idrac' else command
        try:
            stdin, stdout, stderr = self.cnx.exec_command(cmdstr)
        except Exception as estr:
            self.connection_established = False
            return ('ERROR: Connection to host %s dropped' % self.device)

        response = stdout.read()
        if response == '':
            respone = stderr.read()
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            logging.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
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


class DRAC:
    def __init__(self, environment='agile', **opts):
        from axsess import Password

        self.environment = environment
        self.idrac = Connect(remote_host='idrac')
        if self.idrac.error != '':
            raise AssertionError, "ERROR: failed to communicate with iSensor's IDRAC, %s" % self.idrac.error
        P = Password()
        self.device = 'idrac'
        self.ip = P.get_device(self.device, 'address')
        os.environ['%s_IP' % self.device] = self.ip
        self.ip = self.idrac.ip
        self.mgmtIP = P.get_device('isensor', 'address')
        self.mgmt = None
        os.environ['isensor_IP'] = self.mgmtIP
        self.cmd = self.idrac.cmd

        depots = {'agile': {
        'location': '/local/repos/isensor/development/VERSION/agile/isos',
        'server': 'atl1depot01.internal.secureworkslab.com',
        },
        }
        # self.depot_server_address = depots[environment]['server']
        self.iso_location = depots[self.environment]['location']
        self.depot = None
        P = Password()
        self.imsc = Connect(remote_host='imscweb')
        self.imsc.version = None
        self.version = None


    @keyword()
    def Connect_To_IDRAC(self):
        self.idrac = Connect(remote_host='idrac')
        if self.idrac.error != '':
            raise AssertionError, "ERROR: failed to communicate with iSensor's IDRAC, %s" % self.idrac.error
        self.ip = self.idrac.ip
        self.cmd = self.idrac.cmd
        return ('Connection to DRAC successful')


    @keyword()
    def Reboot_From_IDRAC(self, waittime=120):
        self.cmd('serveraction hardreset')
        timer = time() + 30
        timeout = True
        while timer > time():
            uptime = self.cmd('get System.ServerOS').rstrip('\n').rpartition('ServerPoweredOnTime=')[2]
            if int(uptime) == 0:
                timeout = False
                break;
            sleep(1)
        if timeout == True:
            return ('Unable to cold boot the OS')
        timer = time() + waittime
        timeout = True
        while timer > time():
            uptime = self.cmd('get System.ServerOS').rstrip('\n').rpartition('ServerPoweredOnTime=')[2]
            if int(uptime) > 15:
                timeout = False
                break;
            sleep(1)
        resp = self.cmd('set IDRAC.ServerBoot.BootOnce Enabled')
        resp = self.cmd('set IDRAC.ServerBoot.FirstBootDevice HDD')

        return ('Reboot successful...OS up in %d seconds' % (
        timer - time()) if timeout == False else 'OS failed to come up within %d seconds' % waittime)

    @keyword()
    def Wait_For_OS_Self_Boot(self, waittime=108000):
        initial_uptime = int(self.cmd('get System.ServerOS').rstrip('\n').rpartition('ServerPoweredOnTime=')[2])
        timer = time() + waittime
        timeout = True
        while timer > time():
            uptime = int(self.cmd('get System.ServerOS').rstrip('\n').rpartition('ServerPoweredOnTime=')[2])
            if uptime < initial_uptime:
                timeout = False
                break;

        rstr = 'ERROR: timed out after %ds waiting for installer to reboot' % waitttime if timeout == True else 'Reboot detected after %ds' % (
        timer - time())
        return (rstr)


    @keyword()
    def Get_Share_Status(self):
        k = self.cmd('remoteimage -s')
        if k != None:
            status = k.split('\n')
        else:
            status = ['Unknown']
        return (status)

    def set_first_boot(self):
        # resp = self.cmd('config -g cfgServerInfo -o cfgServerBootOnce 1').split('\n')[0]A
        resp = self.cmd('set IDRAC.ServerBoot.BootOnce Enabled')
        assert resp.find('successfully') > 0, 'ERROR: %s' % resp
        #resp = self.cmd('config -g cfgServerInfo -o cfgServerFirstBootDevice vCD-DVD')[0]
        resp = self.cmd('set IDRAC.ServerBoot.FirstBootDevice vCD-DVD')
        assert resp.find('successfully') > 0, 'ERROR: %s' % resp

        return ('First Boot Device was configured successfully')

    @keyword()
    def Get_Mgmt_Credentials(self):
        from axsess import Password

        P = Password()
        device, user, password, certpath = P.getCredentials(mgmt=self.mgmtIP)
        return (user, password)

    @keyword()
    def Get_Auto_Build_Version(self):
        try:
            testID = os.environ['TestID'].split('.')
        except:
            return (None)
        try:
            tid = ''.join('%s.' % testID[x] for x in range(0, 2))
            tid = tid.rstrip('.')
        except:
            return (None)
        isoxml = etree.parse('%s/iso_inventory.xml' % ISO_PATH)
        testruns = isoxml.xpath('//testrun-id')
        for testrun in testruns:
            if testrun.text == tid:
                return (testrun.getparent().attrib['version'])
        return (None)

    @keyword()
    def Connect_NFS_Share(self, path=None, **opts):
        from axsess import Password
        # location = '172.16.244.36:/var/opt/secureworks/bb_images/isensor-barebone-8.4.0-8.iso'
        version = None
        status = self.Get_Share_Status()
        assert status[0].find('Disabled') >= 0, 'A remote share is already mounted...you must dismount the share first'
        if path == None:
            if 'version' in opts:
                version = opts['version']
                if 'imageType' in opts:
                    path = self.get_ISO_from_depot(opts['imageType'], opts['version'])
                else:
                    path = self.get_ISO_from_depot('ktos', opts['version'])

            elif 'imageType' in opts:
                path = self.get_ISO_from_depot(opts['imageType'])
                version = self.get_latest_auto_version(opts['imageType'])

        self.imsc.version = deepcopy(version)
        assert path != None, 'the share location was not specified'
        nfsip = path.split(':')[0]
        P = Password()
        dev, user, password, cert = P.getCredentials(address=nfsip)
        logging.info('attempting to connect remote nfs share: %s' % path)
        resp = self.cmd('remoteimage -c -u %s -p %s -l %s' % (user, password, path))
        logging.info('response received from IDRAC: %s' % resp)
        status = self.Get_Share_Status()
        timer = time() + 30
        rval = 'ERROR: failed to establish share'
        while timer > time():
            status = self.Get_Share_Status()
            chkstatus = status[0].find('Disabled')
            if chkstatus < 0:
                rval = resp
                break
            sleep(1)
        if not rval.startswith('ERROR'):
            fbresult = self.set_first_boot()

        else:
            fbresult = 'No attempt was made to set first boot to NFS share due to error'
        return (version, '%s for "%s\n%s"' % (rval.rstrip('\n'), path, fbresult))


    @keyword()
    def Disconnect_NFS_Share(self):
        status = self.Get_Share_Status()
        if status[0].find('Disabled') >= 0:
            return ('Share is already disconnected')
        rval = self.cmd('remoteimage -d')
        timer = time() + 30
        while timer > time():
            status = self.Get_Share_Status()
            chkstatus = status[0].find('Disabled')
            if chkstatus >= 0:
                rval = status[0]
                break
        return (rval)

    def get_latest_auto_version(self, image_type):
        import re
        from os.path import basename, dirname

        if self.depot == None:
            self.depot = Connect(remote_host='depot')
        image_list = self.depot.cmd('ls %s/*%s*-*iso' % (
        self.iso_location.replace('VERSION', '*'),
        'auto',
        )
        ).split('\n')
        images = sorted(image_list, None, None, True)
        image = images[0] if len(images) > 0 else None
        if image == None:
            return (None)
        if image_type == 'ktos':
            seek_version = re.findall('.*auto-\d{1,2}\.\d{1,2}.*\.iso', image)
            assert len(seek_version) > 0, 'ERROR: regex failure %s' % image
            image_dir = dirname(seek_version[0])
            image_base = basename(seek_version[0])
            version = re.findall('\d{1,2}\.\d{1,2}.*', image_base)[0].replace('.iso', '')
            image_list = self.depot.cmd('ls %s/*ktos-%s*.iso' % (image_dir, version))
            images = sorted(image_list.split('\n'), None, None, True)
            image = images[0] if len(images) > 0 else None
            return (version if image != None else None)
        image_base = basename(image)
        version = re.findall('\d{1,2}\.\d{1,2}.*', image_base)[0].replace('.iso', '')

        return (version)

    def get_ISO_from_depot(self, image_type=None, version=None, **opts):
        import re

        image_type = 'barebone-internal-auto' if image_type == None or image_type.lower() == 'bb' else image_type.lower()
        if image_type not in ['barebone-auto', 'barebone-internal', 'barebone', 'ktos']:
            image_type = 'barebone-auto'
        if version == None:
            version = self.get_latest_auto_version(image_type)
        major_v = re.findall('\d{1,2}\.\d{1,2}', version)
        major_version = major_v[0] if len(major_v) > 0 else None
        assert major_version != None, 'Invalid version string'
        self.depot = Connect(remote_host='depot')
        image_list = self.depot.cmd('ls %s/*%s*-%s*iso' % (
        self.iso_location.replace('VERSION', major_version),
        image_type,
        version,
        )
        )
        images = image_list.split('\n')
        image = sorted(images, None, None, True)[0]
        if image == '':
            return ('ERROR: image does not exist on the depot server')

        return ('%s:%s' % (self.depot.ip, image.rstrip('\n')))

    @keyword()
    def Test_Run_Abort(self, reason=''):
        pids = []
        pid = os.getppid()
        return (str(pid))

    @keyword()
    def Get_MD5sum(self, version=None, **opts):
        if version != None:
            self.imsc.version = version
        md5sum = self.get_image_md5sum(self.imsc.version)

        return ('%s - %s' % (self.imsc.version, md5sum))


    def get_image_md5sum(self, version):
        if version != None:
            self.imsc.version = version
        logging.info('fetching md5sum from %s' % self.imsc.ip)
        cmdstr = 'ls /secureworks/usr/local/apache/htdocs/iSensor_images/*%s*.md5' % self.imsc.version
        md5sums = self.imsc.cmd('ls /secureworks/usr/local/apache/htdocs/iSensor_images/*%s*.md5' % self.imsc.version)
        logging.info('sent "%s" to imscweb' % cmdstr)
        logging.info('received list of md5sum file(s) for version %s: %s' % (self.imsc.version, str(md5sums)))
        md5sum_list = sorted(md5sums.split('\n'), None, None, True)
        if len(md5sum_list) == 0 or md5sum_list[0] == '':
            logging.info('no md5sum found')
            return (None)

        logging.info('picked most current md5sum file: %s' % md5sum_list[0])
        md5sum = self.imsc.cmd('cat %s' % md5sum_list[0]).split(' ')[0]
        return (md5sum)

    @keyword()
    def Test_SSH_Access(self, environment='agile', **opts):
        from axsess import Password

        P = Password()
        P.get_credentials(address=self.mgmtIP)
        connected_via_primary_credentials = True
        try:
            self.mgmt = mgmt = Connect(remote_host=P.device)
        except Exception as estr:
            logging.debug(estr)
            raise AssertionError, 'Unable to connect to host: %s' % estr
        if mgmt.error != '':
            try:
                device, user, password, cert = P.getCredentials(mgmt=self.mgmtIP)
                self.mgmt = mgmt = Connect(address=self.mgmtIP, remote_host=device, username=user, password=password)
                connected_via_primary_credentials = False
            except Exception as second_attempt:
                logging.debug('second attempt: %s' % second_attempt)
                if mgmt.error.find('Connection timed out') < 0 and mgmt.error.find('does not match') < 0:
                    raise AssertionError, "ERROR: failed to communicate with iSensor's Mgmt port, %s\n%s" % (
                    mgmt.error, second_attempt)
                else:
                    logging.debug(mgmt.error + '\n\t' + str(second_attempt))
                return (mgmt.error)
        test = mgmt.cmd('/secureworks/bin/sw-info.sh')
        if connected_via_primary_credentials == True:
            changepw = mgmt.cmd(r'echo -e "tester\ntester" | passwd root')
        return (test)
