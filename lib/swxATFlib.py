import os
import sys
import re
from lxml import etree
from lxml.builder import E
from types import *
from robot.api import logger as logging
from robot.api.deco import keyword
import paramiko
import warnings
from axsess import Password
from copy import deepcopy
from time import time, sleep, strftime, gmtime
import tempfile
from atfvars import varImport


global options
CLASS_INIT = None
NOW = lambda: strftime('%4Y-%2m-%2dT%2H:%2M:%2S.%Z', gmtime(time() + 2))
BAD_VERSION_FORMAT = 'Incorrect version formatting'
PARSER = etree.XMLParser(remove_blank_text=True)
DOCROOT = '/var/www/html/htdocs'
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())

import logging

LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
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
            raise AssertionError, '%s...%s' % (device, str(evars))
        self.connection_established = False
        try:
            device_name = evars['%s_name' % device]
	    
        except KeyError:
            device_name = self.ip
        self.sftp_chan = None
        assert len(self.ip) > 0, 'No IP address for device %s' % device
        P = Password(evars['TestEnv'], evars['ATF_User'])
	self.device, user, pword, cert = P.getCredentials(address=self.ip)
        assert pword != None, 'encrypted password for device %s @ %s is missing from the ATF configuration' % (device, self.ip)
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
	    	path=1
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
	assert self.connection_established == True, 'Unable to connect to %s @ %s using %s credentials %s\n%s\n%d' % (self.device, self.ip, user, pword, str(error), path )
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
            try:
                self.sftp_client = paramiko.sftp_client.SFTPClient
            except Exception as error:
                print str(error)
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


# +++++++++++++++++++++++++++++++++++++  class iSensor ++++++++++++++++++++++++++++++++++++++++++++++++++++++


class iSensor:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.device = evars['device'] = 'isensor'
	self.device_type = evars['device_type'] = 'mgmt'
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
	self.vtags = { 'Version' : '', 'iVersion' : '', 'rVersion' : '', 'sVersion' : ''}
	for tag in self.vtags.keys():
		vval = self.cmd('cat /var/iSensor/%s' % tag)
		self.vtags[tag] = vval.rstrip('\n')
	rmVersion = self.cmd("export PATH=$PATH:/secureworks/bin/;/secureworks/bin/sw-info.sh |grep -A 3 Policies |grep Ruleset |pcregrep -o '(\d+\.){4}\d+'")
	self.vtags['rmVersion'] = rmVersion.rstrip('\n')



    @keyword
    def Get_iSensor_Version(self, tag, **kword):
        if not self.vtags.has_key(tag):
            return ('ERROR: version file "%s" not found' % tag)
        if kword.has_key('rollback'):
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
    def Initialize_Policy(self, instance, policy):
        self.policy.instance = instance
        self.policy.name = policy
        rval = self.cmd('/secureworks/bin/swcfg %s removepolicy %s 2>&1' % (instance, policy))


    @keyword
    def Set_Policy(self, element, value):
        setattr(self.policy, element, value)
        rval = self.cmd(
            '/secureworks/bin/swcfg %s set %s %s %s 2>&1' % (self.policy.instance, self.policy.name, element, value))
        self.policy.error += rval
        return rval


    @keyword
    def Apply_And_Verify_Policy(self):
        estr = ''
        rval = self.policy.error
        rval += self.cmd('/secureworks/bin/swcfg %s apply %s 2>&1' % (self.policy.instance, self.policy.name))
        sleep(1)
        dump = self.cmd('/secureworks/bin/swcfg %s dump %s 2>&1' % (self.policy.instance, self.policy.name))
        dumplines = dump.split('\n')
        for line in dumplines:

            equate = line.split('=\"')
            if equate[0] == '':
                continue
            try:
                x = self.policy.ignore.index(equate[0])
                continue
            except ValueError:
                pass
            setval = getattr(self.policy, equate[0])
            if setval.strip('\"') != equate[1].strip('\"'):
                estr += 'ERROR: %s %s.%s "%s" != "%s"\n' % (
                    self.policy.instance, self.policy.name, equate[0], equate[1].strip('\"'), setval.strip('\"'))
        rval += estr
        return rval


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
            if not self.procget.has_key(regex):
                self.procget[regex] = 0
            new_count = len(filtered_events) - self.procget[regex]
            self.procget[regex] = len(filtered_events)
            if kwords.has_key('lastonly') and kwords['lastonly'] == 'True':
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
        if kwords.has_key('last'):
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
        if kwargs.has_key('list') and kwargs['list'] == 'no':
            return (str(p[len(p) - 1]))
        p = match[0].split(' ')
        return (str([p[len(p) - 1]]))


    @keyword
    def Check_For_Compound_Alerts(self, waittime, **kwargs):
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', waittime, '/secureworks/msg/compound/alerts2.*')
        matchfrom = self.Check_For_Alerts('alerts2\.\d+', waittime, '/secureworks/msg/compound/alerts2.*')
        match = eval(matchfrom)
        p = match[0].split(' ')
        if kwargs.has_key('list') and kwargs['list'] == 'no':
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
        if iface_group.has_key(iface_spec.lower()):
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
            if tscale.has_key(scale):
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
            sleep(2)
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
            if mpx.has_key(unit):
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
                sleep(1)
            if time() >= endwait and srv_state.find(state) < 0:
                return ("timed out")
        else:
            srv_state = self.cmd('/sbin/svstat %s' % service)

        return (srv_state)


    @keyword
    def Get_IPQ3_Metrics(self, fieldspec):
        fields = fieldspec.split(',')
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
        addplus = ''
        fieldnames = []
        compare_flag = False
        for field in fields:
            equate = field.split(':')
            fieldnames.append(equate[0])
            if len(equate) > 1 and metrics.has_key(equate[0]):
                metrics[equate[0]][1] = int(equate[1])
                compare_flag = True

        ipq3data = self.cmd('cat /proc/net/ipq3')
        for metric in fieldnames:
            data = re.findall(metrics[metric][0], ipq3data)
            if len(data) > 0:
                if compare_flag == False:
                    metrics[metric][1] = int(data[0].split(':')[1])
                    addplus = ''
                else:
                    metrics[metric][1] = int(data[0].split(':')[1]) - metrics[metric][1]
                    addplus = '+'
        rstr = ''
        for field in fieldnames:
            if metrics.has_key(field):
                rstr += "%s:%s%d," % (field, addplus, metrics[field][1])
        return (rstr.rstrip(','))


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
            if not valid.has_key(field):
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


class Mail:
    @varImport() 
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.smtp_server = 'atl1mxhost01.internal.secureworkslab.net'

        self.from_address = 'atl101804@internal.secureworkslab.net'
        self.to_addresses = []
        if 'ATF_User' in self.__dict__:
            if self.ATF_User != 'admin' and not self.ATF_User.startswith('Auto'):
                self.to_addresses.append('%s@secureworks.com' % self.ATF_User)
            else:
                self.to_addresses.append('%s@secureworks.com' % 'gowen')
	elif os.environ['USER'] != 'root':
		self.ATF_User = os.environ['USER']
		self.to_addresses.append('%s@secureworks.com' % os.environ['USER'])
	else:
		self.ATF_User = None
	    
        self.mailing_list = {}
        self.summary = ''
        self.reports = ''
        self.report_link = self.REPORTFILE if 'REPORTFILE' in self.__dict__ else ''
        self.log = ''
        self.log_link = self.LOGFILE if 'LOGFILE' in self.__dict__ else ''
        self.content = ''
        self.test_config = ''
        self.test_status = 'started up'
        if 'LOGFILE' in self.__dict__:
            self.testID = '.%s' % os.path.basename(self.LOGFILE.strip('html'))
        if not 'TestID' in self.__dict__:
            self.TestID = strftime('%04Y%02m%02d.%02H%02M%02S')
        if 'TestEnv' in self.__dict__:
            self.subject = 'Test ID (%s): %s - ' % (self.TestEnv, self.TestID)
        if 'email' not in self.__dict__:
	    self.email = 'User'
        for resource in ['isensor_IP', 'pan_IP', 'TestEnvironment', 'bpIP', 'bpFirstPort', 'bpSecondPort', 'bpGroup', 'TOPOLOGY', 'ione_IP',
                         'ione_Ports', 'ione_Topology', 'targetRuleset', 'TestEnv', 'bps_IP', 'isensor_Hardware', 'idrac_IP',
			'session_user', 'email', 'VarFile' ]:
            if resource in self.__dict__:
                if self.__dict__[resource] == 'UNASSIGNED':
                    continue
                self.test_config += '\t%s: %s\n' % (resource.replace('_',' ').upper(),self.__dict__[resource])
            else:
		continue
	
        try:
            logging.debug('swxATFlib:__init__ - email distribution is: %s' % self.email)
        except AttributeError:
            logging.debug('swxATFlib:__init__ - email distribution is undefined')
	    raise AssertionError, 'Mail module was imported without the email distribution defined\n%s' % str(evars)
        if self.email != 'User':
            if len(self.to_addresses) > 0:
                user = self.to_addresses.pop(0)
            else:
                user = None
            try:
                exml = etree.parse('%s/%s/email.xml' % (DOCROOT, self.ATF_User))
            except Exception as estr:
                raise AssertionError, 'Email file unreadable: %s' % str(estr)
            group = exml.find('group[@name="%s"]' % self.email)
	    assert group != None, "Can't find email distro group %s" % self.email
            recipients = group.findall('recipient')
            logging.debug('swxATFlib:__init__ - found %s recipients in distribution list: %s' % (
            len(recipients), self.email))
            for recipient in recipients:
                self.to_addresses.append('%s@%s' % (recipient.attrib['name'], group.attrib['domain']))
            self.email = str(self.to_addresses)
            logging.debug('swxATFlib:__init__ - email distribution list is: %s' % self.to_addresses)


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
        smtpObj.helo("x-atl1ngpcsau02")
        smtpObj.sendmail(self.from_address, self.to_addresses, msg.as_string())
        smtp.quit()


    @keyword()
    def Mail_Report(self, subject=None, recipients=None, **options):
        import smtplib

        if recipients != None:
            for recipient in recipients.split(','):
                self.to_addresses.append('%s.secureworks.com' % recipient)
        logging.debug(
            'swxATFlib:Mail_Report - Processing Mail Report keyword...\n\tDistribution:%s\n\tsubject: %s\n\tTo: %s\n\tBody:%s' % (
                self.email, self.subject, self.to_addresses, self.content))
        content = self.content
        self.content = 'Test Configuration:\n\t%s\n' % self.test_config
        """
        if 'attach' in options:
                self.mailAttachemnts(self.subject, self.to_addresses, self.content, options['attach'])
                return('Message "%s" Sent' % self.subject)
        """
        self.content += content
        body = 'Subject:%s\n\n%s' % (self.subject, self.content)
        try:
            smtpObj = smtplib.SMTP(self.smtp_server)
            smtpObj.helo("agile-ATF.mss-fo")
            smtpObj.sendmail(self.from_address, self.to_addresses, body)
            logging.info('swxATFlib:Mail_Report - Successfully sent mail with subject "%s" to %s' % (
                self.subject,
                ''.join('%s;' % recipient for recipient in self.to_addresses),
            ))
            return ('Message "%s" Sent' % self.subject)
        except Exception as merror:
            logging.error('swxATFlib:Mail_Report - ERROR in attempting to send mail with subject "%s" to %s: %s' % (
                self.subject,
                str(self.to_addresses),
                str(merror)
            ))
            return ('swxATFlib:Mail_Report - ERROR sending email to %s with subject %s\n%s\n' % (
            str(self.to_addresses), self.subject, str(merror)))


    @keyword()
    def Log_To_Mail(self, content, link=None, **options):
        if link != None:
            if link == 'logfile':
                linker = self.log_link
            elif link == 'reportfile':
                linker = self.report_link
            else:
                linker = None
            if linker != None:
		try:
	                ext = linker.index('html')
		except ValueError:
			logging.error('"html" file is missing from link %s (%s) ' % (link, str(linker)))
                s = linker[21:len(linker) - 5]
                linkstr = '%s/%s.html' % ('https://agile-ATF.mss-fo.secureworkslab.net', s)
                content += '\n\t%s\n' % linkstr
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
from scwxBPlib import BreakingPoint as __BP
class BreakingPoint(__BP):
	def get_vars(self):
		return str(self.__dict__)



class Traffic_Generator:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
	logging.debug('TG\n%s' % str(evars))
        self.evars = evars

    def callRemoteScript(self, scriptname, **kword):
        cmd = "/secureworks/testAutomation/iSensorReputationTest/scripts/" + scriptname
        cmd += ''.join(" %s=%s" % (key, kword[key]) for key in kword.keys())
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
		iface = self.ionePorts.split(':')[0]
	except Exception as estr:
		raise AssertionError, 'Invalid iOne ports...check the configuration file:\n%s' % estr
        response = self.callRemoteScript("genIpDnsPkt.sh", TstAction="SendOnly", TstIface=iface, DnsQname=DnsQname,
                                        DnsSvrIpAddr="172.16.138.76")
        return (response)

    @keyword()
    def Generate_DNS_Packet(self, DnsQname):
        return(self.genIpDnsPkt(DnsQname))

    @keyword()
    def Send_Pcap_File(self, capfilename, intfc1="p1p1", intfc2="p1p2"):
	try:
		intfc1 = self.ionePorts.split(':')[0]
		intfc2 = self.ionePorts.split(':')[1]
	except Exception as estr:
		raise AssertionError, 'Invalid iOne ports...check the configuration file:\n%s' % estr

        cmd = "/usr/local/bin/tomahawk -i %s -j %s -A0 -r1 -l1 -f /root/pcap/%s 2>&1" % (intfc1, intfc2, capfilename)
        logging.debug('Starting pcap playback \n\t"%s"\n\t... on device %s (%s)' % (cmd, self.device, self.ip))
        response = self.sudo(cmd)
        logging.debug("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)

class ione(Traffic_Generator):
    @varImport()
    def __init__(self, **evars):
	logging.debug('iONE\n%s' % str(evars))
	assert 'ione_Topology' in os.environ and os.environ['ione_Topology'] != "UNASSIGNED", 'No ione topology defined\n%s' % evars
	self.device = evars['device'] = 'ione'
	self.ione = Connect(**evars)
	self.ip = self.ione.ip
	self.cmd = self.ione.cmd
	self.sudo = self.ione.sudo
	
class itwo(Traffic_Generator):
    @varImport()
    def __init__(self, **evars):
	evars['device'] = 'itwo'
	self.itwo = Connect(self.TestEnv,self.ATF_User,**evars)
	self.ip = self.itwo.ip
	self.cmd = self.itwo.cmd
	self.sudo = self.itwo.sudo
	

class ATF:
    @varImport()
    def __init__(self, **evars):
	import socket
	import struct
	import fcntl
  	self.__dict__.update(evars)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	self.eth0 = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', 'eth0'[:15]))[20:24])
	

    @keyword()
    def Get_ATF_IP_Address(self):
   	return(self.eth0)


    @keyword()
    def Publish_Performance_Results(self):
	from atf_results import Results
  	R = Results('Ruleset_Performance')
	R.processPerformanceSamples()

    @keyword(tags=['obfuscated'])
    def Get_iSensor_Credentials(self, deviceID):
	logging.debug('Credentials have been obfuscated')
	P = Password()
	self.device, user, pword, cert = P.getCredentials(address=self.isensor_IP)
	return(user, pword)

	
	
	

