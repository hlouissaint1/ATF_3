import os
import sys
import re
import config
from lxml import etree
from lxml.builder import E
from types import *
from robot.api import logger as logging
from robot.api.deco import keyword
import paramiko
import warnings
from axsess import Password
from copy import deepcopy
import time
from time import time, strftime, gmtime
import tempfile
from atfvars import varImport

global options
CLASS_INIT = None
NOW = lambda: strftime('%4Y-%2m-%2dT%2H:%2M:%2S.%Z', gmtime(time() + 2))
BAD_VERSION_FORMAT = 'Incorrect version formatting'
PARSER = etree.XMLParser(remove_blank_text=True)

LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())

import logging

##########LOGPATH = '/var/www/cgi-bin'
##########DOCROOT = '/var/www/html/htdocs'
LOG = config.LOGPATH + '/ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename=LOG,
                    level=logging.DEBUG)


def testCasePassed():
    return (deviceInfoFile)


def getFieldIntValue(tstr, fieldname):
    rxstr = "\s%s\s\d+\s" % fieldname
    match = re.findall(rxstr, tstr)
    if len(match) == 0:
        return (None)
    value = match[0].lstrip(' ').split(' ')[1]
    return (int(value))


class Connect:
    @varImport()
    def __init__(self, **evars):
        if not 'device' in evars:
            self.__dict__['device'] = 'isensor'
        self.__dict__.update(evars)
        warnings.simplefilter('ignore')
        paramiko.util.log_to_file('/var/www/cgi-bin/logs/paramiko.log')
        device = evars['DUT'] if 'DUT' in evars else evars['device'] if 'device' in evars else 'isensor'
        self.ip = evars['%s_IP' % device]
        if self.ip == None and '%s_host' % device in evars:
            self.ip = evars['%s_host' % device]
        elif self.ip == None:
            raise AssertionError('%s...%s' % (device, str(evars)))
        self.connection_established = False
        try:
            device_name = evars['%s_name' % device]

        except KeyError:
            device_name = self.ip
        self.sftp_chan = None
        assert len(self.ip) > 0, 'No IP address for device %s' % device
        P = Password(evars['TestEnv'], evars['ATF_User'])
        self.device, user, pword, cert = P.getCredentials(address=self.ip)
        assert pword != None, 'encrypted password for device %s @ %s is missing from the ATF configuration' % (
            device, self.ip)
        self.password = pword
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
            if device == 'isensor':
                logging.debug('attempting to add new nost keys from %s to local known hosts at %s' % (
                    self.ip, os.path.expanduser('~/.ssh/known_hosts')))
                keys.add(self.ip, key.get_name(), key)
                keys.save(os.path.expanduser('~/.ssh/known_hosts'))
        except Exception as estr:
            logging.error('unable to insert isertkey for %s\n%s' % (self.ip, str(estr)))

        self.cnx = paramiko.client.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            keypath = evars['keypath'] if 'keypath' in evars else None
            if keypath == None:
                path = 1
                logging.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword)
                logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                path = 2
                logging.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    logging.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except:
                    path = 3
                    logging.debug(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.cnx.connect(self.ip, username=user, password=pword)
                    logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                    self.connection_established = True
        except Exception as error:
            self.error = "Connection failure to device (%s) at %s, user:%s\n%s" % (
                self.device, self.ip, user, str(error) + ',' + pword)
            logging.error(self.error)
            self.connection_established = False
        assert self.connection_established == True, 'Unable to connect to %s @ %s using %s credentials %s\n%s\n%d' % (
            self.device, self.ip, user, pword, str(error), path)
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
            try:
                self.sftp_client = paramiko.sftp_client.SFTPClient
            except Exception as error:
                print(str(error))
                trap
        self.user = user
        self.device = device

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            logging.error(self.error)
            raise AssertionError(self.error)

    def cmd(self, command, **kwords):
        log = logging.debug if not 'logdebug' in kwords or kwords['logdebug'] != True else logging.info

        if 'logsuppress' not in kwords or kwords['logsuppress'] == False:
            log("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)
        except:
            self.reconnect()
            stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)

        response = stdout.read()
        if response == '':
            respone = stderr.read()
        if 'logsuppress' not in kwords or kwords['logsuppress'] == False:
            log("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def sudo(self, command, **flags):
        flist = ''
        if len(flags) > 0:
            for f in list(flags.keys()):
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
            raise AssertionError('ERROR - cannot read source file %s' % source)

        try:
            self.sftp_chan = self.sftp_client.from_transport(self.transport)
            self.sftp_chan.put(source, destination)
        except Exception as error:
            raise AssertionError('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(error)))

    def pullfile(self, destination, source):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        try:
            self.sftp_chan = self.sftp_client.from_transport(self.transport)
            self.sftp_chan.get(source, destination)
        except Exception as error:
            raise AssertionError('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(error)))


# +++++++++++++++++++++++++++++++++++++  class iSensor ++++++++++++++++++++++++++++++++++++++++++++++++++++++

def get_private_key():
    try:
        fxml = etree.parse('%s/admin/%s_servers.xml' % (config.DOCROOT, os.environ['TestEnv'].lower()))
        keynode = fxml.find('atf/private-key')
        if keynode == None:
            return (None)
        keypath = keynode.attrib['name']
        return (keypath)
    except Exception as estr:
        raise AssertionError('Cannot locate private key path: %s' % str(estr))


class iSensor:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.device = evars['device'] = 'isensor'
        self.device_type = evars['device_type'] = 'mgmt'
        self.keypath = evars['keypath'] = get_private_key()
        self.evars = evars
        self.isensor = Connect(**evars)
        self.cmd = self.isensor.cmd
        self.cnx = self.isensor.cnx
        self.pushfile = self.isensor.pushfile
        self.sftp_client = self.isensor.sftp_client
        self.ip = self.isensor.ip
        self.linemark = 1
        self.datemark = ''
        self.procmark = 0
        self.pregex = '.*'
        self.procget = {}
        self.policy = None
        self.versions = {}
        self.uin = self.cmd('cat /var/iSensor/uin').rstrip('\n')
        self.idn = self.cmd('cat /var/iSensor/internal-device-name').rstrip('\n')
        self.mac = \
            self.cmd('ifconfig `get_management_interface` |pcregrep -o "(([[:xdigit:]]){2}:){5}[[:xdigit:]]{2}"').split(
                '\n')[0]
        home_net = self.cmd('/secureworks/bin/sw-info.sh  |grep HOME_NET |pcregrep -o "(\d{1,3}\.){3}\d{1,3}\/\d{1,2}"')
        self.home_net = home_net.rstrip('\n')
        self.prompt = '[%s]#' % self.uin
        self.vprompt = self.uin + '>'
        self.vtags = {'Version': '', 'iVersion': '', 'rVersion': '', 'sVersion': ''}
        for tag in list(self.vtags.keys()):
            vval = self.cmd('cat /var/iSensor/%s' % tag)
            self.vtags[tag] = vval.rstrip('\n')
        rmVersion = self.cmd(
            "export PATH=$PATH:/secureworks/bin/;/secureworks/bin/sw-info.sh |grep -A 3 Policies |grep Ruleset |pcregrep -o '(\d+\.){4}\d+'")
        self.vtags['rmVersion'] = rmVersion.rstrip('\n')

    @keyword
    def Get_iSensor_Version(self, tag, **kword):
        if tag not in self.vtags:
            return ('ERROR: version file "%s" not found' % tag)
        if 'rollback' in kword:
            tokens = self.vtags[tag].split('.')
            rbtokens = kword['rollback'].rstrip('\n').split('.')
            x = 0
            for token in tokens:
                if rbtokens[x] != '0':
                    fint = int(token)
                    tint = fint + int(rbtokens[x])
                    rbtokens[x] = str(tint)
                else:
                    rbtokens[x] = token
                x += 1
            rbver = ''.join('%s.' % s for s in rbtokens)
            return (rbver)

        return (self.vtags[tag])

    @keyword
    def Get_iSensor_Platform_Model(self):
        modelstr = self.cmd('/bin/dmesg |grep PowerEdge |tail -1|pcregrep -o "R\d{3}" |pcregrep -o "\d{3}"')
        return (modelstr.rstrip('\n'))

    @keyword
    def Track_Process(self, procfile, pregex, **kwords):
        atostr = lambda str_array: ''.join('\n%s' % s for s in str_array)
        try:
            f = open(procfile, 'r')
            events = f.read().split('\n')
            f.close()
            self.pregex = re.compile(pregex)
            cur_events = atostr(events)
            cur_procs = re.findall(self.pregex, cur_events)
            self.procmark = len(events)
            return (atostr(cur_procs))

        except IOError:
            return ('ERROR: Process file cannot be found\n')

    @keyword
    def Get_Process(self, procfile, regex, **kwords):
        atostr = lambda str_array: ''.join('\n%s' % s for s in str_array)
        try:
            f = open(procfile, 'r')
            events = f.read().split('\n')
            f.close()
            filtered_events = re.findall(regex, atostr(events))
            if regex not in self.procget:
                self.procget[regex] = 0
            new_count = len(filtered_events) - self.procget[regex]
            self.procget[regex] = len(filtered_events)
            if 'lastonly' in kwords and kwords['lastonly'] == 'True':
                return (new_count, filtered_events[len(filtered_events) - 1])
            else:
                return ([new_count, atostr(filtered_events)])
        except IOError:
            return ('ERROR: Process file cannot be found\n')

    @keyword
    def Mark_End_Of_Log(self, logname, **kwords):
        mark = self.cmd('cat %s |wc -l' % logname)
        self.linemark = int(mark) + 1
        return (self.linemark)

    @keyword
    def Find_Log_Event(self, logname, regex, **kwords):
        endmark = self.cmd('cat %s 2>&1 |wc -l' % logname)
        if int(endmark) < self.linemark - 1:
            return ('WARNING: logfile %s truncated' % logname)
        if 'last' in kwords:
            lastn = kwords['last']
            result = self.cmd(
                'tail %d %s 2>&1 | pcregrep "%s" |tail %d' % (
                    (int(endmark) - self.linemark + 1), logname, regex, lastn))
        result = self.cmd('tail %d %s 2>&1 | pcregrep "%s"' % ((int(endmark) - self.linemark + 1), logname, regex))
        return (result)

    @keyword
    def Check_For_Alerts(self, regex, wtime, alert_dir, **kargs):
        crgx = re.compile(regex, re.MULTILINE)
        waittime = float(wtime.split(' ')[0])
        now = time()
        expire = now + waittime
        logging.debug(
            'Sending cmd: "ls -lta --time-style "+%cs" %s" continuously until alert appears or timeout' % (
                '%', alert_dir))
        while (now < expire):
            alert_list = self.cmd('ls -lta --time-style "+%cs" %s' % ('%', alert_dir), logsuppress=True)
            match = re.findall(crgx, alert_list)
            if len(match) > 0:
                return (str(match))
            now = time()
        return (str(['Timed_Out']))

    @keyword
    def Check_For_Stage_Alerts(self, wtime, **kwargs):
        waittime = float(wtime.split(' ')[0])
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', wtime, '/secureworks/msg/stage/alerts2.*')
        match = eval(matchfrom)
        if 'list' in kwargs and kwargs['list'] == 'no':
            return (str(p[len(p) - 1]))
        p = match[0].split(' ')
        return (str([p[len(p) - 1]]))

    @keyword
    def Check_For_Compound_Alerts(self, waittime, **kwargs):
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', waittime, '/secureworks/msg/compound/alerts2.*')
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', waittime, '/secureworks/msg/compound/alerts2.*')
        match = eval(matchfrom)
        p = match[0].split(' ')
        if 'list' in kwargs and kwargs['list'] == 'no':
            return (str(p[len(p) - 1]))
        return ([p[len(p) - 1]])

    @keyword
    def Check_For_U2_Alerts(self, waittime):
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', waittime, '/secureworks/msg/u2/alerts2.*')
        match = eval(matchfrom)
        p = match[0].split(' ')
        return ([p[len(p) - 1]])

    @keyword
    def Check_For_Alert_Update(self, wtime):
        waittime = float(wtime.split(' ')[0])
        now = time()
        expire = now + waittime
        starttime = None
        while (now < expire):
            alertsfrom = self.Check_For_Alerts('alerts2\.\d+', '1.0', '/secureworks/msg/compound/alerts2.*')
            alerts = eval(alertsfrom)
            if alerts[0] == 'Timed_Out':
                now = time()
                continue;
            alert = self.cmd('ls -al --time-style "+%cs" /secureworks/msg/compound/%s' % ('%', alerts[0]))
            p = alert.split(' ')
            if starttime == None:
                starttime = p[len(p) - 2]
                now = time()
                continue
            if p[len(p) - 2] != starttime:
                return (str([os.path.basename(p[len(p) - 1]).rstrip('\n')]))
            now = time()
        return (str(['Timed_Out', -1]))

    @keyword
    def Alert_Then_Measure_Staging_Interval(self, wtime):
        waittime = float(wtime.split(' ')[0])
        self.cmd('/secureworks/bin/soc-test-alert.sh')
        now = time()
        alerttime = 0.0
        stagetime = 0.0
        expire = now + waittime
        starttime = now
        while now < expire:
            matchfrom = self.Check_For_Stage_Alerts('1.0')
            match = eval(matchfrom)
            if match[0] != 'Timed_Out':
                stagetime = int(time() - starttime) + 1
            matchfrom = self.Check_For_Alerts('alerts2\.\d+', '1.0', '/secureworks/msg/compound/alerts2.*')
            match = eval(matchfrom)
            if match[0] == 'Timed_Out':
                now = time()
                continue
            size = '0'
            for alert in match:
                alertspec = self.cmd('ls -al --time-style "+%cs" /secureworks/msg/compound/%s' % ('%', alert))
                p = alertspec.split(' ')
                size = p[len(p) - 3]
                if size != '0':
                    # print alertspec
                    break
            if size == '0':
                now = time()
                continue
            if stagetime == 0.0:
                stagetime = int(time() - starttime) + 1
            alerttime = int(time() - starttime) + 1
            return (['%d' % stagetime, '%d' % alerttime])
        return (['Timed_Out', -1])

    @keyword
    def Get_Interface_IP_Address(self, iface_spec, **kwords):
        """
        Get the IPv4 addresse(s) of the specified interface/interface group.
            Example:  ${iface}= Get_Interface_IP_Address                tunnels
                Returns 'tun0:xxx.xxx.xxx.xxx,tun1:xxx.xxx.xxx.xxx'
            Example:  ${iface}= Get_Interface_IpAddress         eth0
                Returns 'eth0:xxx.xxx.xxx.xxx'
                    or
                    'eth0: No IPv4 Address'
        """
        iface_group = {
            'tunnels': '^tun\d+',
            'management': 'mgmt\d+',
            'bridges': 'br\d+',
            'ethx': 'eth\d+',
        }
        log = logging.debug
        ip_regex = "(\d{1,3}\.){3}\d{1,3}"
        log('Get_Interface_IP_Address %s' % iface_spec)
        if iface_spec.lower() in iface_group:
            ifaces = self.cmd('/sbin/ifconfig |pcregrep -o "%s"' % iface_group[iface_spec.lower()]).split('\n')
            ipadds = []
            for iface in ifaces:
                if iface == '':
                    ifaces.pop(ifaces.index(iface))
                    continue
                ip = self.cmd('/sbin/ifconfig %s |pcregrep -o "%s"' % (iface, ip_regex)).rstrip('\n')
                if ip == '':
                    ip = 'No IPv4 Address'
                ipadds.append(ip)
        else:
            resp = self.cmd('/sbin/ifconfig |pcregrep -A1 "%s" | pcregrep -o "%s"' % (iface_spec, ip_regex))
            ifaces = [iface_spec]
            if resp == '':
                resp = 'No IPv4 Address'
            ipadds = [resp]
        outstr = ''.join('%s:%s,' % (ifaces[x], ipadds[x]) for x in range(0, len(ifaces)))
        return (outstr.rstrip(','))

    @keyword
    def Monitor_VPN_Tunnel_Interfaces(self, timerstr):
        tscale = {'s': 1.0, 'm': 60.0, 'h': 3600.0, }
        searchint = re.findall("\d+", timerstr)
        if len(searchint) == 0:
            return ("ERROR: Invalid time specified")
        timer = float(searchint[0])
        searchint = re.findall("\D+", timerstr.strip(' '))
        if len(searchint) > 0:
            scale = searchint[0].lstrip(' ')[0]
            if scale in tscale:
                timer *= tscale[scale]
        end_timer = time() + float(timer)
        while time() < end_timer:
            for intfc in ('tun0', 'tun1'):
                resp = self.Get_Interface_IP_Address(intfc)
                if resp == 'No IPv4 Address':
                    return ('ERROR: %s is has no IP address\n' % intfc)
                ifstats = self.cmd('ifconfig %s' % intfc)
                if ifstats.find('UP') < 0 or ifstats.find('RUNNING') < 0:
                    return ('ERROR: %s is down\n%s' % (intfc, ifstats))
            time.sleep(2)
        return ("Interfaces tun0 and tun1 appear to be stable")

    @keyword
    def getNetworkConfig(self, cfg_par):
        logging.info("getNetworkConfig - %s" % cfg_par)

        swcfg = lambda c: self.cmd('/secureworks/bin/swcfg get isensor.networking.management %s' % c.lower())

        if cfg_par.lower() == 'all':
            logging.info("getNetworkConfig sending command: /secureworks/bin/swcfg dump isensor.networking.management")
            resp = self.cmd('/secureworks/bin/swcfg dump isensor.networking.management')
            logging.info("getNetworkConfig resp %s" % resp)
        else:
            logging.info(
                "getNetworkConfig sending command: /secureworks/bin/swcfg get isensor.networking.management %s" % cfg_par.lower())
            resp = swcfg(cfg_par)
            logging.info("getNetworkConfig resp %s" % resp)

        return (resp)

    @keyword
    def SVC(self, service_name, state_spec, waitstr):
        mpx = {'s': 1, 'm': 60, 'h': 3600}
        suffix = waitstr.strip('0123456789')
        wait = waitstr.strip(suffix)
        try:
            unit = suffix.lstrip(' ')[0]
            if unit in mpx:
                multiplier = mpx[unit]
            else:
                multiplier = 1
        except IndexError:
            multiplier = 1
        fwait = float(wait) * multiplier
        service = service_name.lower()
        state = state_spec.lower()
        if not service.startswith('/service/'):
            service = "/service/%s" % service
        if int(wait) > 0:
            self.cmd('/sbin/svc -%s %s' % (state[0], service))
            endwait = time() + fwait + 1.0
            while time() < endwait:
                srv_state = self.cmd('/sbin/svstat %s' % service)
                if state_spec in srv_state and not 'want' in srv_state:
                    break
                time.sleep(1)
            if time() >= endwait and srv_state.find(state) < 0:
                return ("timed out")
        else:
            srv_state = self.cmd('/sbin/svstat %s' % service)

        return (srv_state)

    def Get_Packet_Metrics(self, fieldspec, pktfwd='ipq3'):
        fields = fieldspec.split(',')
        if pktfwd == 'ipq3':
            metrics = {
                'Packets in': ['Packets\sin\s+\:\s+\d+', 0],
                'Packets out': ['Packets\sout\s+\:\s+\d+', 0],
                'Packets dropped': ['Packets\sdropped\s+\:\s+\d+', 0],
                'Number of rings': ['Number\sof\srings\s+\:\s+\d+', 0],
                'Num of public rings': ['Num\sof\spublic rings\s+\:\s+\d+', 0],
                'Max rings': ['Max\srings\s+\:\s+\d+', 0],
                'Packets bypassed': ['Packets\sdropped\s+\:\s+\d+', 0],
                'Cdev major num': ['Cdev\smajor\snum\s+\:\s+\d+', 0],
                'Packets autov': ['Packets\sautov\s+\:\s+\d+', 0],
                'Fsync calls': ['Fsync\scalls\s+\:\s+\d+', 0],
            }
        elif pktfwd == 'dpdk':
            metrics = {
                'Packets in': ['packets_rx\s+\:\s+\d+', 0],
                'Packets out': ['packets_tx\s+\:\s+\d+', 0],
                'Packets autov': ['packets_autov\s+\:\s+\d+', 0],
                'Number of queues': ['num_queues\s+\:\s+\d+', 0],
                'Packets dropped in': ['packets_rx_drop\s+\:\s+\d+', 0],
                'Packets dropped out': ['packets_itx_drop\s+\:\s+\d+', 0],
                'Packets dropped': ['packets_rx_drop\s+\:\s+\d+', 0],
            }
        else:
            raise AssertionError('invalid packet forward specification')

        addplus = ''
        fieldnames = []
        compare_flag = False
        for field in fields:
            equate = field.split(':')
            fieldnames.append(equate[0])
            if len(equate) > 1 and equate[0] in metrics:
                metrics[equate[0]][1] = int(equate[1])
                compare_flag = True
        if pktfwd == 'ipq3':
            pktdata = self.cmd('cat /proc/net/ipq3')
        else:
            pktdata = self.cmd('cat /secureworks/stats/dptd')
        for metric in fieldnames:
            data = re.findall(metrics[metric][0], pktdata)
            if len(data) > 0:
                if compare_flag == False:
                    metrics[metric][1] = int(data[0].split(':')[1])
                    addplus = ''
                else:
                    metrics[metric][1] = int(data[0].split(':')[1]) - metrics[metric][1]
                    addplus = '+'
        rstr = ''
        for field in fieldnames:
            if field in metrics:
                rstr += "%s:%s%d," % (field, addplus, metrics[field][1])
        return (rstr.rstrip(','))

    @keyword
    def Get_IPQ3_Metrics(self, fieldspec):  # for backward compatibility
        return (self.Get_Packet_Metrics(fieldspec, pktfwd='ipq3'))

    @keyword
    def Read_XpdFoo_Compound(self, validation):
        alertlist = []
        rstr = ""
        totalevents = 0
        totalpkts = 0
        packet_len = '0'
        sigID = '0'
        valid = {'AlertFiles': None, 'AlertCount': None, 'PartialPkts': True, 'PktCount': None, 'sig_id': None,
                 'packet_length': None}
        fields = validation.split(',')
        alerts = self.cmd('ls /secureworks/msg/compound/*')
        for alert in alerts.split('\n'):
            if alert == '':
                continue
            stats = self.cmd("stat %s" % alert)
            size = getFieldIntValue(stats, "Size:")
            # rstr += "%s - %s," % (alert, str(size))
            if size > 0:
                events = self.cmd('/secureworks/bin/xpdfoo %s |pcregrep "^\(Event\)" |wc -l' % alert)
                pkts = self.cmd('/secureworks/bin/xpdfoo %s |pcregrep "^Packet" |wc -l' % alert)
                totalpkts += int(pkts)
                totalevents += int(events)
                sigID = self.cmd(
                    '/secureworks/bin/xpdfoo %s |pcregrep -o "sig id:\s\d+\s" |pcregrep -o "\d+" |tail -1' % alert)
                packet_len = self.cmd(
                    '/secureworks/bin/xpdfoo %s |pcregrep -o "packet_length:\s\d+$" |pcregrep -o "\d+" |tail -1' % alert)
                alertlist.append([alert, size, int(events), int(pkts)])
        for field in fields:
            if field not in valid:
                continue
            if field == 'AlertFiles':
                rstr += "AlertFiles:%d," % len(alertlist)
            elif field == 'AlertCount':
                rstr += "AlertCount:%d," % totalevents
            elif field == 'PktCount':
                rstr += "PktCount:%d," % totalpkts
            elif field == 'sig_id':
                rstr += "sig_id:%d," % int(sigID)
            elif field == 'packet_length':
                rstr += "packet_length:%d," % int(packet_len)

            elif field == 'PartialPkts':
                partialpkts = 0
                for alert in alertlist:
                    alert_content = self.cmd('/secureworks/bin/xpdfoo %s' % alert[0])
                    packets = alert_content.split('Packet')
                    packets.pop(0)
                    for packet in packets:
                        pkt_len = getFieldIntValue(packet, "packet_length:")
                        pbytes = re.findall("\[\s*[0-9A-Fa-f]{1,4}\]", packet, flags=re.MULTILINE)
                        bcnt = int(pbytes[len(pbytes) - 1].strip(']').strip('['))
                        oddbyteline = packet[packet.index(pbytes[len(pbytes) - 1]):]
                        oddbyteline = oddbyteline[:oddbyteline.index('\n')]
                        oddbytes = re.findall("([0-9A-Fa-f]{2}){1,16}\s{1}", oddbyteline)
                        bcnt += len(oddbytes)
                        if bcnt != pkt_len:
                            partialpkts += 1
                rstr += 'PartialPkts:%d,' % partialpkts
        return (rstr.rstrip(','))

def get_fqdn():
        import re
        try:
                with open('/etc/hosts', 'r') as hosts:
                        fqdn_parse = re.findall('(a|p|r)(-atf.*net)', hosts.read(), re.MULTILINE)[0]
                        fqdn = fqdn_parse[0] + fqdn_parse[1]
                        logging.info('FQDN is %s' % fqdn)
                        return(fqdn)
        except Exception as estr:
                logging.debug('failed to determine FQDN "%s"...exiting' % str(estr))
        return('')


class Mail:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)

        self.default_to_addresses = self.to_addresses = ['pmankoo@secureworks.com,hlouissaint@secureworks.com']

        self.mailing_list = {}
        self.summary = ''
        self.reports = ''
        #self.report_link = self.REPORTFILE if 'REPORTFILE' in self.__dict__ else ''
        self.log = ''
        #self.uleset_Performance/Ruleset_Performance/logs/Sanity/Pilot/20210413_183847.CTU9.Sanity.html
        self.content = ''
        self.test_config = ''
        self.test_status = 'started up'
	self.fqdn = get_fqdn()

	try:
		self.log_link = 'https://%s/%s' % (self.fqdn, os.environ['LOGFILE'])
	except KeyError:
		self.log_link = 'https://%s/rf_log.html' % ( self.ATF_User)
		self.LOGFILE = os.environ['LOGFILE'] = self.log_link

	try:
		self.report_link = 'https://%s/%s' % (self.fqdn, os.environ['REPORTFILE'])
	except KeyError:
		self.report_link = 'https://%s/rf_report.html' % (self.ATF_User)
		self.REPORTFILE = os.environ['REPORTFILE'] = self.report_link

        if 'LOGFILE' in self.__dict__:
            self.testID = '.%s' % os.path.basename(self.LOGFILE.strip('html'))
	    
        if not 'TestID' in self.__dict__:
            self.TestID = strftime('%04Y%02m%02d.%02H%02M%02S')
        if 'TestEnv' in self.__dict__:
            self.subject = 'Test ID (%s): %s - ' % (self.TestEnv, self.TestID)
        if 'email' not in self.__dict__ or self.email == 'User' or self.email == 'UNDEFINED':
            logging.debug('using default email distro for %s' % self.ATF_User)
            self.email = self.ATF_User
        for resource in ['isensor_IP', 'pan_IP', 'TestEnvironment', 'bpIP', 'bpFirstPort', 'bpSecondPort', 'bpGroup',
                         'TOPOLOGY', 'ione_IP',
                         'ione_Ports', 'ione_Topology', 'targetRuleset', 'TestEnv', 'bps_IP', 'isensor_Hardware',
                         'idrac_IP',
                         'session_user', 'email', 'VarFile']:
            if resource in self.__dict__:
                if self.__dict__[resource] == 'UNASSIGNED':
                    continue
                self.test_config += '\t%s: %s\n' % (resource.replace('_', ' ').upper(), self.__dict__[resource])
            else:
                continue
	try:
	    sxml = etree.parse('%s/admin/%s_servers.xml' % (config.DOCROOT, self.TestEnv.lower()))
	except:
	    logging.debug('servers configuration missing')
	    raise AssertionError('Mail module was imported with missing servers config')
        try:
            logging.debug('email distribution is: %s' % self.email)
        except AttributeError:
            logging.debug('email distribution is undefined')
            raise AssertionError('Mail module was imported without the email distribution defined\n%s' % str(evars))
        try:
            exml = etree.parse('%s/admin/email.xml' % (config.DOCROOT))
        except Exception as estr:
            raise AssertionError('Email file unreadable: %s' % str(estr))
        mailserver = sxml.find('atf/mail-server')
        if mailserver != None and 'url' in mailserver.attrib:
            self.smtp_server = mailserver.attrib['url']
        else:
            self.smtp_server = 'r-atl1mxhost04.corp-dmz.secureworks.net'

        mailclient = sxml.find('atf/mail-client')
        if mailclient != None and 'url' in mailclient.attrib:
            self.from_address = mailclient.attrib['url']
        else:
	    self.from_address = '%c-atf.atf-%s.aws.secureworks.net' % (os.environ['TestEnv'].lower()[1], os.environ['TestEnv'].lower())

        logging.debug('email server URL is: %s, email client is %s' % (self.smtp_server, self.from_address))
        if self.email != 'UNDEFINED':
            if len(self.to_addresses) > 0:
                user = self.to_addresses.pop(0)  # remove the default user (me)
            else:
                user = None
            group = exml.find('group[@name="%s"]' % self.email)
            assert group != None, "Can't find email distro group %s" % self.email
            recipients = group.findall('recipient')
            logging.debug('found %s recipients in distribution list: %s' % (
                len(recipients), self.email))
            for recipient in recipients:
                self.to_addresses.append('%s@%s' % (recipient.attrib['name'], group.attrib['domain']))
            self.email = str(self.to_addresses)
            logging.debug('email distribution list is: %s' % self.to_addresses)

    def mailAttachemnts(self, subject, recipients, content, attachments):
        import smtplib
        from email.utils import COMMASPACE, formatdate
        from email.mime.text import MIMEText
        from email.MIMEMultipart import MIMEMultipart
        from email.MIMEBase import MIMEBase
        from email import encoders

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.from_address
        msg['To'] = recipients
        msg.attach(MIMEText(content))
        for attachment in attachments.split(','):
            if attachment == 'logfile':
                attached_file = self.log_link
            elif attachment == 'reportfile':
                attached_file = self.report_link
            else:
                continue
            with open(attached_file, 'r') as atachfd:
                part = MIMEBase('application', 'html')
                part.set_payload(atachfd.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(attachment))
                msg.attach(part)

        smtpObj = smtplib.SMTP(self.smtp_server)
        smtpObj.helo(self.from_address)
        smtpObj.sendmail(self.from_address, self.to_addresses, msg.as_string())
        smtp.quit()

    @keyword()
    def Mail_Report(self, subject=None, recipients=None, **options):
        import smtplib
        logging.debug('email distro is %s' % self.email)

        if recipients != None:
            for recipient in recipients.split(','):
            	self.to_addresses.append('%s.secureworks.com' % recipient)
        logging.debug(
            'Processing Mail Report keyword...\n\tDistribution:%s\n\tsubject: %s\n\tTo: %s\n\tBody:%s' % (
                self.email, self.subject, self.to_addresses, self.content))
        content = self.content
        self.content = 'Test Configuration:\n%s\n' % self.test_config
        """
        if 'attach' in options:
                self.mailAttachemnts(self.subject, self.to_addresses, self.content, options['attach'])
                return('Message "%s" Sent' % self.subject)
        """
        self.content += content
        body = 'Subject:%s\n\n%s' % (self.subject, self.content)
        try:
            smtpObj = smtplib.SMTP(self.smtp_server)
            smtpObj.helo(self.from_address)
            smtpObj.sendmail(self.from_address, self.to_addresses, body)
            logging.info('Successfully sent mail from %s with subject "%s" to %s' % (
                self.smtp_server, self.subject,
                ''.join('%s;' % recipient for recipient in self.to_addresses),
            ))
            return ('Message "%s" Sent' % self.subject)
        except Exception as merror:
            logging.error(
                'ERROR in attempting to send mail from %s with subject "%s" to %s: %s' %
                (self.smtp_server, self.subject, str(
                    self.to_addresses), str(merror)))
            return ('ERROR sending email from %s with subject %s\n%s\n' % (
                self.smtp_server, str(self.to_addresses), self.subject, str(merror)))

    @keyword()
    def Log_To_Mail(self, content, link=None, **options):
        logging.debug('content: %s\nlink:%s\noptions:%s' % (content, link, str(options)))

	url = 'https://%s' % self.fqdn
        if 'convert_to_link' in options:
            if content.index(DOCROOT) < 0:
                logging.debug('content does not contain DOCROOT')
            else:
                content = content.replace(config.DOCROOT, url)
                logging.debug('converted content to %s' % content)
                link = None
        if link != None:
            if link == 'logfile':
                linker = self.log_link
            elif link == 'reportfile':
                linker = self.report_link
            else:
                linker = None
            if linker != None:
                logging.debug('LINKER: "%s"' % str(linker))
                try:
                    ext = linker.index('html')
                except ValueError:
                    logging.error('"html" file is missing from link %s (%s) ' % (link, str(linker)))
                s = linker[21:len(linker) - 5]
                linkstr = '%s' % (linker)
                content += '\n\t%s\n' % linkstr
                logging.debug('content w/link = %s' % content)
        if 'title' in options:
            indented = '----------'
            for line in content.split('\n'):
                indented += '\n     %s' % line
            self.content += '\n%s:\n%s\n----------\n\n' % (options['title'], indented)
        else:
            self.content += content

    @keyword()
    def Set_Mail_Subject(self, subject, **options):
        self.subject += subject

    @keyword()
    def Update_Config(self, key, value, **options):
        logging.debug('request to update mail configuration string replacing %s value with %s,\ncurrent config:\n%s' % (
            key, value, self.test_config))
        if self.test_config.index(key) >= 0:
            for line in self.test_config.split('\n'):
                if line.startswith(key):
                    self.test_config = self.test_config.replace(line, '%s:%s' % (key, value))
                    logging.debug(
                        'replaced "%s" with "%s:%s"..config now is:\n%s' % (line, key, value, self.test_config))
                    break

    @keyword()
    def Append_Config(self, cfg_csv, **options):
        for cfg in cfg_csv.split(','):
            self.test_config += '\t%s\n' % cfg


# This is here for backward compatibility to the legacy libraries
from scwxDCIMlib import LabManager as __LabManager


class LabManager(__LabManager):
    def get_vars(self):
        return str(self.__dict__)


# This is here for backward compatibility to the legacy libraries
from scwxDCIMlib import PathFinder as __PathFinder


class PathFinder(__PathFinder):
    def get_vars(self):
        return str(self.__dict__)


# This is here for backward compatibility to the legacy libraries
from scwxBPlib2 import BreakingPoint as __BP


class BreakingPoint(__BP):
    def get_vars(self):
        return str(self.__dict__)


class ione:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        logging.debug('TG\n%s' % str(evars))
        self.evars = evars
        self.device = evars['device'] = 'ione'
        self.ione = Connect(**evars)
        self.ip = self.ione.ip
        self.cmd = self.ione.cmd
        self.sudo = self.ione.sudo

    def callRemoteScript(self, scriptname, **kword):
        cmd = "/secureworks/testAutomation/iSensorReputationTest/scripts/" + scriptname
        cmd += ''.join(" %s=%s" % (key, kword[key]) for key in list(kword.keys()))
        logging.debug('Starting remote script %s on device %s (%s)' % (cmd, self.device, self.ip))
        response = self.sudo(cmd, S='')
        logging.debug("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    @keyword()
    def Run_Remote_Script(self, script, **kword):
        self.callRemoteScript(script, **kword)

    @keyword()
    def genIpDnsPkt(self, DnsQname):
        try:
            iface = self.ione_Ports.split(':')[0]
        except Exception as estr:
            raise AssertionError('Invalid iOne ports...check the configuration file:\n%s' % estr)
        response = self.callRemoteScript("genIpDnsPkt.sh", TstAction="SendOnly", TstIface=iface, DnsQname=DnsQname,
                                         DnsSvrIpAddr="172.16.138.76")
        return (response)

    @keyword()
    def Generate_DNS_Packet(self, DnsQname):
        return (self.genIpDnsPkt(DnsQname))

    @keyword()
    def Send_Pcap_File(self, capfilename, intfc1="p1p1", intfc2="p1p2"):
        try:
            intfc1 = self.ione_Ports.split(':')[0]
            intfc2 = self.ione_Ports.split(':')[1]
        except Exception as estr:
            raise AssertionError('Invalid iOne ports...check the configuration file:\n%s' % estr)

        cmd = "/usr/local/bin/tomahawk -i %s -j %s -A0 -r1 -l1 -f /root/pcap/%s 2>&1" % (intfc1, intfc2, capfilename)
        logging.debug('Starting pcap playback \n\t"%s"\n\t... on device %s (%s)' % (cmd, self.device, self.ip))
        response = self.sudo(cmd)
        logging.debug("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)


class ATF:
    @varImport()
    def __init__(self, **evars):
        import socket
        import struct
        import fcntl

        self.__dict__.update(evars)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.eth0 = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', 'eth0'[:15]))[20:24])
        self.eth0 = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', 'ens5'[:15]))[20:24])

    @keyword()
    def Get_ATF_IP_Address(self):
        return (self.eth0)

    @keyword()
    def Publish_Performance_Results(self, filestr='performance_samples.csv', docname='Ruleset Performance History',
                                    **opts):
        from atf_results import Results

        R = Results()
        return (R.processPerformanceSamples(filestr, docname, **opts))

    @keyword()
    def Archive_Performance_Data(self, filestr='performance_metrics.csv', docname='iSensor Release Performance History',
                                 **opts):
        from atf_results import Results
        R = Results()
        return (R.processPerformanceData(filestr, docname, **opts))

    @keyword(tags=['obfuscated'])
    def Get_iSensor_Credentials(self, deviceID):
        logging.debug('Credentials have been obfuscated')
        P = Password()
        self.device, user, pword, cert = P.getCredentials(address=self.isensor_IP)
        return (user, pword)
