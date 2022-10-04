#! /usr/bin/python
# Author G. Owen, gowen@secureworks.com

import os
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from time import time, strftime, mktime, strptime, sleep, gmtime, localtime
from enum import Enum
from robot.api.deco import keyword
from json import JSONDecoder, JSONEncoder, dumps
from pprint import pprint
from atfvars import varImport
import logging
import re
import paramiko
from paramiko_expect import SSHClientInteraction
import warnings
from tempfile import mkstemp
from lxml import etree
from lxml.builder import E
from copy import deepcopy

ATF_CERT = "/etc/pki/tls/certs/prodATF_REST_client.crt"
ATF_CERT_KEY = '/etc/pki/tls/certs/rest_plain_key.pem'
CERT_BUNDLE = '/etc/pki/tls/certs/p-atl100955.mss-fo.secureworks.net.crt'

SAMPLES_PER_PAGE = 20
PAGE_LIST_SIZE = 11

PROMPT = '.*[#\$\>\:] '
SESSION_TIMEOUT = 1800
MAX_REFRESH_COUNT = 3

NSX_LOGPATH = '/var/www/cgi-bin/lib'
DOCROOT = '/var/www/html/htdocs'
MODULE = 'scwxNSXlib.py'
NSX_LOG = 'nsx.log'

logging.basicConfig(
    format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    filename='%s/%s' % (NSX_LOGPATH, NSX_LOG),
    filemode='w',
    level=logging.DEBUG)

NSXLOG = logging.getLogger('nsx_regression')
rhandler = logging.FileHandler('%s/%s' % (NSX_LOGPATH, NSX_LOG))
formatter = logging.Formatter('%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s')
rhandler.setFormatter(formatter)
NSXLOG.addHandler(rhandler)
NSXLOG.setLevel(logging.DEBUG)
NSXLOG.debug('Initialized logging')


class VulnDB:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.url = 'https://%s/CANDIDATE_RELEASE_ID?apikey=%s' % (
            self.vlndb_IP, self.vlndb_Password)
        self.latest_url = 'https://%s/latest.tgz?enhanced_metadata=true&apikey=%s' % (
            self.vlndb_IP, self.vlndb_Password)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.Session()
        self.session.trust_env = False
        self.error = 'Unknown'
        self.Added = []
        self.Changed = []
        self.Removed = []
        self.previous_rs_version = None
        self.this_rs_version = None
        self.tar = None
        self.tarfile_name = None
        self.rs_files = {
            'variables.yaml': lambda c: c,
            'release_number.txt': lambda c: c.rstrip('\n'),
            'notification_text': lambda c: c,
            'previous_release_number.txt': lambda c: c.rstrip('\n'),
            'sw.rules.md5': lambda c: c,
            'sw_rules_added.txt': lambda c: self.parse_rs_diffs(c.split('\n')),
            'sw_rules_removed.txt': lambda c: self.parse_rs_diffs(c.split('\n')),
            'rules/sw.rules': lambda c: c,

        }

        headers = {}
        NSXLOG.info('ATF Sandbox: %s, Environment: %s' % (self.ATF_User, self.TestEnv))

    def parse_rs_diffs(self, content):
        regexes = {
            'Added': '(?<=^NEW)(.*)',
            'Changed': '(?<=^CHANGED)(.*)',
            'Removed': '(?<=^REMOVED)(.*)',
        }
        rval = ''
        for regex in regexes:

            for s in content:
                rs = s.split(';')[0]
                if len(re.findall("NEW|CHANGED|REMOVED", rs)) == 0:
                    continue
                try:
                    parsed = re.findall('(?<=msg:).*', re.findall(regexes[regex], rs, re.MULTILINE)[0])
                    if len(parsed) == 0:
                        parsed = re.findall('(?<=sid:).*', re.findall(regexes[regex], rs, re.MULTILINE)[0])
                    if len(parsed) != 0:
                        self.__dict__[regex].append(parsed[0])
                except Exception as estr:
                    continue
            rval += '%s:\n' % regex + ''.join('\t%s\n' % e for e in self.__dict__[regex])
        return rval.replace('[', '').replace(']', '')

    def read_rs_file(self, tarfile_name, filename=None):
        import tarfile
        content = None
        self.tar = tar = tarfile.open(tarfile_name, 'r:gz')
        for tar_file in tar:
            if tar_file.name == filename or filename is None:
                extracted = tar.extract(tar_file.name, '/tmp')
                content = None
                with open('/tmp/%s' % filename, 'r') as f:
                    content = self.rs_files[filename](f.read())
                os.unlink('/tmp/%s' % tar_file.name)
                if filename is not None:
                    break

        return content

    @keyword
    def Get_Suricata_Ruleset_Diffs(self, version):
        if not self.tarfile_name:
            tarfile = self.fetch_suricata_ruleset(version)
        diffs = self.read_rs_file(self.tarfile_name, 'sw_rules_removed.txt')
        diffs = self.read_rs_file(self.tarfile_name, 'sw_rules_added.txt')
        header = 'Differences between version %s and %s\n\n' % (self.previous_rs_version, self.this_rs_version)
        return header + diffs.replace('\"', '')

    @keyword
    def Download_Suricata_Ruleset(self, version=None):
        assert version is not None, 'ERROR: No version was specified for download'
        if version != self.this_rs_version:
            tarfile = self.fetch_suricata_ruleset(version)
        notify = self.read_rs_file(self.tarfile_name, 'notification_text')
        verify = self.Verify_Suricata_Ruleset_MD5_Sum()
        if verify.find('ERROR') >= 0:
            return (verify)
        return 'Suricata Ruleset version "%s" downloaded successfully (%s)...\n\n%s\n' % (version, verify, notify)

    @keyword
    def Get_Latest_Suricata_RS_Version(self):
        NSXLOG.debug('fetching ruleset from %s' % self.latest_url.split('?')[0])
        raw = self.session.get(self.latest_url, verify=False)
        NSXLOG.debug('status code: %s' % raw.status_code)
        NSXLOG.debug('Response headers: \n%s' % ''.join('\t%s:%s\n' % (k, raw.headers[k]) for k in raw.headers.keys()))
        filename = raw.headers['content-disposition'].split('=')[1]
        with open('/tmp/%s' % filename, 'wb') as f:
            f.write(raw.content)
        self.tarfile_name = '/tmp/%s' % filename
        latest = self.this_rs_version = self.read_rs_file(self.tarfile_name, 'release_number.txt')
        previous = self.previous_rs_version = self.read_rs_file(self.tarfile_name, 'previous_release_number.txt')
        verify = self.Verify_Suricata_Ruleset_MD5_Sum()
        if verify.find('ERROR') >= 0:
            return verify
        return latest, previous

    def fetch_suricata_ruleset(self, version=''):
        url = self.url.replace('CANDIDATE_RELEASE_ID', version)
        NSXLOG.debug('fetching ruleset from %s' % url.split('?')[0])
        raw = self.session.get(url, verify=False)
        NSXLOG.debug('Response headers: \n%s' % ''.join('\t%s:%s\n' % (k, raw.headers[k]) for k in raw.headers.keys()))
        if raw.status_code != 200:
            self.error = 'ERROR %d: fetching CTU ruleset: %s' % (raw.status_code, raw.reason)
            NSXLOG.error(self.error)
            return None, None

        filename = raw.headers['content-disposition'].split('=')[1]
        with open('/tmp/%s' % filename, 'wb') as f:
            f.write(raw.content)
        self.tarfile_name = '/tmp/%s' % filename
        self.previous_rs_version = self.read_rs_file(self.tarfile_name, 'previous_release_number.txt')
        self.this_rs_version = self.read_rs_file(self.tarfile_name, 'release_number.txt')
        assert self.this_rs_version == version, 'Incorrect version was downloaded'
        return self.tarfile_name

    @keyword
    def Verify_Suricata_Ruleset_MD5_Sum(self):
        from hashlib import md5
        assert self.tarfile_name != None, 'ERROR: Suricata ruleset has not yet been downloaded'
        md5sum_should = self.read_rs_file(self.tarfile_name, 'sw.rules.md5').split(' ')[0]

        rules = self.read_rs_file(self.tarfile_name, 'rules/sw.rules')
        md5sum_is = md5(rules).hexdigest()
        del rules
        assert md5sum_should == md5sum_is, 'ERROR, MD5sum mismatch, IS: %s, SHOULD BE: %s' % (md5sum_is, md5sum_should)

        return 'MD5sum "%s" matches' % md5sum_is


OPTION_TRUE = lambda kw, o: True if o in kw and kw[o] == True else False


class nsxtAPI(object):
    class NSXKeyword_Error(RuntimeError):
        ROBOT_CONTINUE_ON_FAILURE = True

    def __call__(self, pFunction):

        def nsxt_api_call(self, uri, data=None, **opts):

            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            url = '%s/%s' % (self.nsxt_Url, uri)
            try:
                resp = pFunction(self, url, data)
                assert str(resp.status_code).startswith('2'), 'ERROR: API %s failed to %s... (code %d)\n%s\n' % (
                    pFunction.__name__, url, resp.status_code, resp.json()["error_message"])
            except Exception as estr:
                return (str(estr))
            if OPTION_TRUE(opts, 'return_raw'):
                return resp.text
            D = JSONDecoder()
            try:
                djson = D.decode(resp.text)
            except ValueError:
                return resp.text
            if len(opts) == 0:
                return djson

            rlist = {}
            if 'keys' in opts:
                for key in opts['keys'].replace(' ', '').split(','):
                    if key in djson.keys():
                        rlist[key] = djson[key]
                    else:
                        rlist[key] = '"%s" not found' % key

            return rlist

        return nsxt_api_call


NSX_POLICY = lambda u: 'policy/api/v1/%s' % u
NSX_BASE = lambda u: 'api/v1/%s' % u
NSX_NODE = lambda u: 'api/v1/node/%s' % u


class NSX:
    class NSXKeyword_Error(RuntimeError):
        ROBOT_CONTINUE_ON_FAILURE = True

    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.timestamp = 0.0
        self.elapsed = 0.0
        self.cnx = self.cmd = None
        self.hostname = self.nsxt_Url.replace('https://', '')
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.trust_env = False
        self.extract_data = lambda d, s: re.findall('(?<=%s: )\S+' % d, s)[0]
        self.group_id = None
        self.cpu_used_time = 0

    @nsxtAPI()
    def POST(self, url, data=None, **opts):
        resp = self.session.post(url, data=data, auth=(self.nsxt_User, self.nsxt_Password), verify=False)
        return resp

    @nsxtAPI()
    def PUT(self, url, data=None, **opts):
        resp = self.session.put(url, data=data, auth=(self.nsxt_User, self.nsxt_Password), verify=False)
        return resp

    @nsxtAPI()
    def GET(self, url, data=None, **opts):
        resp = self.session.get(url, auth=(self.nsxt_User, self.nsxt_Password), verify=False)
        return resp

    # k = N.GET(NSX_BASE('global-configs'))
    # k = N.GET(NSX_BASE('node/logs/nsx-audit.log'))
    # D.datetime.isoformat(D.datetime.fromtimestamp(T.time()))

    @keyword
    def Get_NSX_Interface_Info(self, get_iface=None):
        ifaces = {}
        iface_data = self.GET(NSX_NODE('network/interfaces'))
        for iface_glob in iface_data['results']:
            iface = iface_glob['interface_id']
            ifaces[iface] = {}
            ifaces[iface]['link_status'] = iface_glob['link_status']
            ifaces[iface]['physical_address'] = iface_glob['physical_address']
            ifaces[iface]['IP'] = iface_glob['ip_addresses'][0]['ip_address']
            ifaces[iface]['mtu'] = iface_glob['mtu']
        rstr = ''
        for iface in ifaces:
            if get_iface is not None and iface != get_iface:
                continue
            rstr += '%s:\n\tIP: %s\n\tphysical_address: %s\n\tMTU: %s\n\tlink_status: %s\n\n' % (
                iface,
                ifaces[iface]['IP'],
                ifaces[iface]['physical_address'],
                ifaces[iface]['mtu'],
                ifaces[iface]['link_status'],
            )
        if rstr == '':
            return ('ERROR: interface "%s" is not among installed interfaces (%s)' % (
                get_iface, ''.join('%s,' % iface for iface in ifaces.keys()).rstrip(',')))
        return rstr

    @keyword
    def Get_NSX_Versions(self, ):
        versions = self.GET(NSX_NODE('version'))
        NSXLOG.debug('versions = "%s"' % versions)
        return versions
        # return (''.join('%s: %s\n' % (key, versions[key]) for key in versions.keys()))

    @keyword
    def Get_NSX_Log(self, get_log=None, timestamp=None, span=None):
        from datetime import datetime
        if get_log != None:
            timestamp = time() - 300.0 if timestamp == None else float(timestamp)
            span = 300.0 if span == None else float(span)
            starttime = datetime.isoformat(datetime.fromtimestamp(timestamp)).split('.')[0]
            endtime = datetime.isoformat(datetime.fromtimestamp(timestamp + span)).split('.')[0]

            log_contents = self.GET(NSX_NODE('logs/%s/data' % get_log)).replace(self.hostname, '')
            logstartx = log_contents.find(starttime)
            adjust = 0.0
            while logstartx < 0:
                timestamp -= 10.0
                starttime = datetime.isoformat(datetime.fromtimestamp(timestamp)).split('.')[0]
                adjust += 10.0
                if adjust > span:
                    return 'ERROR: log events not found at time %s' % str(timestamp)
                logstartx = log_contents.find(starttime)

            logendx = log_contents.find(endtime)

            if logendx < 0:
                logslice = log_contents[logstartx:]
            else:
                logslice = log_contents[logstartx:logendx]
            return logslice

        log_list = self.GET(NSX_NODE('logs'))
        log_names = []
        for logx in log_list['results']:
            if logx['log_name'].endswith('.gz'):
                continue
            log_names.append(logx['log_name'])
        return ''.join('%s\n' % log for log in log_names)

    @keyword
    def Get_NSX_Time(self, **opts):
        self.cnx = nsx = Connect(self.nsxt_IP)
        self.cmd = nsx.cmd
        try:
            datestr = nsx.cmd('get clock').rstrip('\n')
            tx = datestr.split('.')
            last_time = self.timestamp
            self.timestamp = mktime(strptime(tx[0], '%a %b %d %Y UTC %H:%M:%S'))
            ms = float(tx[1]) / 1000
            self.timestamp += ms
            if 'return_elapsed' in opts:
                self.elapsed = self.timestamp - float(opts['return_elapsed'])
        except Exception as estr:
            nsx.cnx.close()
            raise AssertionError('ERROR: Unable to fetch time from NSX Host:\n\t%s' % str(estr))
        nsx.cnx.close()
        if 'return_elapsed' in opts:
            return datestr, self.timestamp, self.elapsed
        else:
            return datestr, self.timestamp

    @keyword
    def Get_NSX_Uptime(self, **opts):
        self.cnx = nsx = Connect(self.nsxt_IP)
        self.cmd = nsx.cmd
        try:
            uptime = nsx.cmd('get uptime').rstrip('\n')
        except Exception as estr:
            nsx.cnx.close()
            raise AssertionError('ERROR: Unable to fetch uptime from NSX Host:\n\t%s' % str(estr))
        nsx.cnx.close()
        return uptime

    @keyword
    def Get_NSX_Interface_Stats(self, iface=None, return_metric=None, **opts):
        assert iface is not None, 'ERROR: interface ID was not specified'
        self.cnx = nsx = Connect(self.nsxt_IP)
        self.cmd = nsx.cmd
        try:
            stats = nsx.cmd('get interfaces')
        except Exception as estr:
            raise AssertionError('ERROR: unable to retrieve interface stats: %s', str(estr))
        data = {metric: self.extract_data(metric, stats) for metric in [
            'Interface',
            'RX packets',
            'TX packets',
            'RX bytes',
            'TX bytes',
            'RX errors',
            'TX errors',
            'RX dropped',
            'TX dropped',
            'TX collisions',
        ]
                }
        if return_metric:
            if return_metric == 'Interface':
                return data[return_metric]
            else:
                return int(data[return_metric])
        else:
            rstr = '%s: %s\n\t' % ('Interface', data.pop('Interface'))
            rstr += ''.join('%s: %s\n\t' % (key, data[key]) for key in data.keys())
            return rstr

        ######################### admin vsish commands to ESX ######################################

    def get_nsx_idps_group_id(self, **opts):
        esx = Connect(self.esx_IP)
        cmdstr = 'vsish -e set /sched/groupPathNameToID host vim vmvisor nsx-idps'
        grp_id_str = esx.cmd(cmdstr)
        grp_id_extracted = re.search('\d+', grp_id_str)
        assert grp_id_extracted is not None, 'ERROR:failed to extract NSX group ID via vsish: %s' % cmdstr
        self.group_id = grp_id_extracted.group()
        return esx

    @keyword()
    def Get_NSX_Memory_Usage(self, **opts):
        esx = self.get_nsx_idps_group_id()
        cmdstr = 'memstats -r group-stats -s name:max:consumed -u mb -g %s' % self.group_id
        memstr = esx.cmd(cmdstr)
        memstat_extracted = re.findall('(?<=nsx-idps)\s+(\d+)\s+(\d+)', memstr, re.MULTILINE)
        assert len(memstat_extracted) > 0, 'ERROR: failed to retrieve nxst-idps memory stats'
        maxmem, consumed = memstat_extracted[0]
        esx.cnx.close()
        NSXLOG.debug('max: %s, consumed: %s' % (maxmem, consumed))
        if 'limit' in opts and opts['limit'] is not None:
            limitv = float(opts['limit'].replace('%c' % 0x25, ''))
            pcnt = (100 * float(consumed)) / float(maxmem)
            if pcnt > limitv:
                return (
                    maxmem, consumed, 'FAILED: memory consumption (%5.2f%c of max) is greater than limit of %5.2f%c' % (
                        pcnt, 0x25, limitv, 0x25))
            else:
                return (
                    maxmem, consumed, 'PASSED: memory consumption (%5.2f%c of max) is within the limit of %5.2f%c' % (
                        pcnt, 0x25, limitv, 0x25))
        return maxmem, consumed, 'No limit provided'

    def parse_cpu_stats(self, cpu_str, field, anchor=None):
        fields = lambda s, f: re.findall('(^.*)(?<=%s:)(\d+)' % f, s, re.MULTILINE)
        if anchor is None:
            fval = fields(cpu_str, field)
        else:
            px = cpu_str.find(anchor)
            pe = cpu_str[px:].find('}')
            fval = fields(cpu_str[px:px + pe], field)
        rfields = {}
        for f in fval:
            fname = f[0].lstrip().rstrip(':')
            if fname in rfields:
                rfields[fname + '*'] = f[1]
            else:
                rfields[fname] = f[1]

        return rfields

    @keyword()
    def Get_NSX_CPU_Usage(self, metric='used-time', **opts):
        esx = self.get_nsx_idps_group_id()
        cmdstr = 'vsish -e get /sched/groups/%s/stats/cpuStatsDir/cpuStats' % self.group_id
        cpu_str = esx.cmd(cmdstr)
        esx.cnx.close()
        if 'return_raw' in opts and opts['return_raw'] == True:
            return cpu_str
        if 'anchor' in opts:
            rstr = self.parse_cpu_stats(cpu_str, metric, opts['anchor'])
        else:
            rstr = self.parse_cpu_stats(cpu_str, metric)
        if metric == 'used-time':
            if self.cpu_used_time == 0:
                self.cpu_used_time = int(rstr[metric])
                return self.cpu_used_time, 0
            else:
                delta = int(rstr[metric]) - self.cpu_used_time
                self.cpu_used_time = int(rstr[metric])
                return self.cpu_used_time, delta

        return ''.join('%s = %s' % (k, rstr[k]) for k in rstr)

    def get_vswitch_info(self, **opts):
        esx = Connect(self.esx_IP)
        cmdstr = 'nsxdp-cli vswitch instance list'
        instance_list = esx.cmd(cmdstr)
        if 'return_raw' in opts and opts['return_raw'] == True:
            esx.cnx.close()
            return instance_list
        vnics = {}
        vswitch = re.findall('DvsPortset-\d+\s\((\S+)\)', instance_list, re.MULTILINE)
        DVPortID = re.findall('^.*eth\d\s+\d+\s+(\S+)', instance_list, re.MULTILINE)
        vmnics = re.findall('^\s+(vmnic\d+)', instance_list, re.MULTILINE)
        for vnic in [0, 1]:
            vnics['eth%d' % (vnic + 1)] = {'vswitch': vswitch[vnic], 'DVPortID': DVPortID[vnic], 'vmnics': vmnics[vnic]}
        for vnic in vnics.keys():
            cmdstr = 'nsxdp-cli vswitch l2sec get --dvport %s -dvs %s\n' % (
                vnics[vnic]['DVPortID'], vnics[vnic]['vswitch'])
            vnics[vnic]['state'] = esx.cmd(cmdstr)
            cmdstr = 'esxcfg-nics -l |grep %s' % vnics[vnic]['vmnics']
            esxcfgstr = esx.cmd(cmdstr)
            vnics[vnic]['state'] += '\n%s' % esxcfgstr
        esx.cnx.close()
        NSXLOG.debug(str(vnics))
        return vnics

    def configure_ip_forwarding(self):
        bridge = Connect(self.bridge_IP)
        rstr = ''
        cmdstr = 'sysctl net.ipv4.ip_forward'
        ip_forwarding_str = bridge.cmd(cmdstr)
        ip_forwarding = re.findall('(?<=\=\s)\d+', ip_forwarding_str)
        if len(ip_forwarding) == 0 or ip_forwarding[0] != '1':
            ip_forwarding_str = bridge.cmd(cmdstr + '=1')
            ip_forwarding = re.findall('(?<=\=\s)\d+', ip_forwarding_str)
            if len(ip_forwarding) == 0 or ip_forwarding[0] != '1':
                rstr += '\nERROR: failed to set ip forwarding on NSX bridge VM'
            else:
                rstr += '\nSuccessfully configured NSX bridge VM ip forwarding'
        else:
            rstr += '\nNSX bridge VM is already configured for ip forwarding'
        bridge.cnx.close()

        return rstr

    @keyword()
    def Get_VMNIC_Link_State(self):
        vnics = self.get_vswitch_info()
        state = ""
        for vnic in vnics.keys():
            slst = re.findall('^vmnic\d+.*$', vnics[vnic]['state'], re.MULTILINE)
            if len(slst) > 0:
                state += '%s\n' % slst[0]
        return state

    @keyword()
    def Configure_NSX_Bridge_VM(self):
        vnics = self.get_vswitch_info()
        esx = Connect(self.esx_IP)
        rstr = ''
        attempt = []
        for vnic in vnics.keys():
            if 'deny' in vnics[vnic]['state']:
                cmdstr = 'nsxdp-cli vswitch l2sec set --dvport %s -dvs %s --mac-change --forge-src --promisc' % (
                    vnics[vnic]['DVPortID'], vnics[vnic]['vswitch'])
                configure = esx.cmd(cmdstr)
                attempt.append(vnic)
            else:
                rstr += '\n"%s" is already configured' % vnic

        del vnics
        vnics = self.get_vswitch_info()
        for vnic in vnics.keys():
            if 'deny' in vnics[vnic]['state']:
                rstr += '\nERROR: failed to configure NSX bridge VM "%s"' % vnic
            elif vnic in attempt:
                rstr += 'Successfully configured NSX bridge VM "%s"' % vnic
        esx.cnx.close()
        rstr += self.configure_ip_forwarding()

        return rstr

    def Publish_Performance_Results(self,
                                    filestr='performance_samples.csv',
                                    docname='NSX-T/Suricata Ruleset Performance History',
                                    **opts):
        from atf_results import NSXResults

        R = NSXResults()
        rlink = R.processPerformanceSamples(
            '%s/Ruleset_Performance/Ruleset_Performance/history/NSX-T/Pilot/%s' % (DOCROOT, filestr), docname, **opts)
        return rlink.replace(DOCROOT, '')


class Connect:
    def __init__(self, address):
        import paramiko
        import warnings
        from axsess import Password

        paramiko.util.log_to_file('/var/www/cgi-bin/logs/paramiko.log')
        warnings.simplefilter('ignore')
        env = os.environ['TestEnv']
        atf_user = os.environ['ATF_User']
        P = Password(env, atf_user)
        device, user, password, keypath = P.getCredentials(address=address)
        assert device != None, "address '%s' is not in user %s's %s configuration" % (address, atf_user, env)
        self.ip = address
        self.password = pword = password
        self.user = user
        self.error = ''
        try:
            from paramiko.transport import Transport
            from paramiko.hostkeys import HostKeys

            keys = HostKeys()
            keys.load(os.path.expanduser('~/.ssh/known_hosts'))

            NSXLOG.debug('creating transport session for %s' % self.ip)
            T = Transport((self.ip, 22))
            NSXLOG.debug('starting transport client for %s' % self.ip)
            T.start_client()
            key = T.get_remote_server_key()
        except Exception as estr:
            NSXLOG.error('unable to insert isert host key for %s\n%s' % (self.ip, str(estr)))
            raise AssertionError('Trap %s' % estr)

        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if keypath is None:
                NSXLOG.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword, look_for_keys=False, allow_agent=False)
                NSXLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                NSXLOG.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    NSXLOG.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except:
                    NSXLOG.debug(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.cnx.connect(self.ip, username=user, password=pword)
                    NSXLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                    self.connection_established = True
        except Exception as error:
            self.error = "Connection failure to device at %s, user:%s\n%s" % (
                self.ip, user, str(error) + ',' + pword)
            NSXLOG.error(self.error)
            self.connection_established = False
        if self.connection_established:
            self.transport = self.cnx.get_transport()
        self.user = user
        self.device = device
        self.BUF_SIZE = 65535
        self.rxc = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def cmd(self, command, **kwords):
        if not self.connection_established:
            NSXLOG.error('Connection error...cannot execute remote command')
            return 'Connection Error'
        # self.cnx = paramiko.SSHClient()

        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            NSXLOG.debug("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)
        except Exception as estr:
            NSXLOG.debug('Error connecting to NSX: "%s"' % str(estr))
            self.error = ''
            self.reconnect()
            if self.error != '':
                NSXLOG.error('Error connecting to NSX: %s' % self.error)
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)

        response = stdout.read()
        if response == '':
            response = stderr.read()
        NSXLOG.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return response

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            NSXLOG.debug('reconnecting to host %s' % self.ip)
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            NSXLOG.error(self.error)
            raise AssertionError(self.error)
        NSXLOG.debug('re-connection successful')

    def sudo(self, command, **flags):
        if not self.connection_established:
            NSXLOG.error('Connection error...cannot execute remote sudo')
            return 'Connection Error'
        # self.cnx = paramiko.SSHClient()
        flist = ''
        if len(flags) > 0:
            for f in flags.keys():
                flist += " \-%s %s" % (f, flags[f])

        response = ''
        error = ''
        NSXLOG.info('Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
        stdin, stdout, stderr = self.cnx.exec_command("sudo -S %s 2>&1" % command)
        stdin.write("%s\n" % self.password)
        stdin.flush()
        while True:
            resp = stdout.read()
            error += stderr.read()
            if not resp:
                break
            response += resp
        if error != '':
            response += '\nERROR:\n%s\n' % error
            NSXLOG.error('ERROR in response to sudo command: %s' % "sudo -S %s 2>&1" % command)
        NSXLOG.info("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return response.replace('Password: ', '')

    def pushfile(self, source, destination):
        import scpclient as SCP
        from hashlib import md5

        if not self.connection_established:
            NSXLOG.error('Connection error...cannot upload file')
            return 'Connection Error'
        try:
            destination_path = os.path.basename(destination)
            NSXLOG.info('uploading file %s from ATF to %s:%s' % (source, self.ip, destination))
            W = SCP.Write(self.transport, os.path.dirname(destination))
            W.send_file(source, destination_path)
            SCP.closing(W)
            C = Connect(self.ip)
            NSXLOG.debug('moving %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            resp = C.sudo('mv %s/%s %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            NSXLOG.debug('moved %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            NSXLOG.debug('comparing MD5 sums between source and destination files after upload')
            md5sum = C.cmd('md5sum %s' % destination).split(' ')[0]
            C.cnx.close()
            with open(source, 'r') as sfile:
                smd5sum = md5(sfile.read())
            assert md5sum == smd5sum.hexdigest(), 'MD5 sums do not match between source and destination files'
            return 'Success: MD5 sums of the source and destination files match: % s\n' % md5sum
        except Exception as estr:
            NSXLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return 'ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr))

    def pullfile(self, destination, source):
        import scpclient as SCP
        from hashlib import md5
        import traceback

        if not self.connection_established:
            NSXLOG.error('Connection error...cannot upload file')
            return 'Connection Error'

        try:
            source_path = os.path.basename(source)

            NSXLOG.info('downloading file %s from %s:%s to ATF' % (source, self.ip, source))
            R = SCP.Read(self.transport, os.path.dirname(source))
            resp = R.receive_file(destination, True, None, source_path)
        except Exception as estr:
            tb = traceback.extract_stack()
            pprint(tb)
            NSXLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return 'ERROR - failed to copy %s from %s (%s)' % (source, destination, str(estr))

        return resp


def launch_request_json(options, ):
    E = JSONEncoder()
    json = {
        'testrun': {
            'environment': options.TestEnv,
            # 'identification' : options.tag,
            'user': options.Session_User,
            'target-ruleset': options.ruleset_version,
            'test-group': options.group,
            'test-suites': [],
            'configuration-profile': {},
            'abort-test': False,
            'testrun-id': ''
        }
    }

    #    for tests in options.tests.split(','):
    for tests in options.tests:
        suite, test = tests.split(':')

        if suite == '*':
            json['testrun']['test-suites'] = []
            break
        if test == '*':
            json['testrun']['test-suites'].append({'suite': {'name': suite, 'tests': []}})
            continue
        suite_exists = False
        for ste in json['testrun']['test-suites']:
            if ste['suite']['name'] == suite:
                ste['suite']['tests'].append(test)
                suite_exists = True
                break
        if not suite_exists:
            json['testrun']['test-suites'].append({'suite': {'name': suite, 'tests': [test]}})

    if options.config is None:

        json['testrun']['configuration-profile'] = {'name': '%s.%s' % (options.user, 'last.testrun')}
    else:
        json['testrun']['configuration-profile'] = {'name': options.config}
    config = json['testrun']['configuration-profile']
    try:
        with open('%s.cfg' % config['name'], 'r') as cfg:
            config = eval(cfg.read())
    except Exception as error:
        config = {}
    if not 'bps' in config:
        config['bps'] = {}

    if options.bps_IP is not None:
        config['bps']['address'] = options.bps_IP
    pair1 = options.bps_Firstport
    pair2 = options.bps_Secondport
    config['bps']['first-port'] = '%s,1,1' % pair1
    config['bps']['second-port'] = '%s,1,1' % pair2
    config['bps']['topology'] = options.bps_Topology
    config['bps']['group'] = options.bps_Group
    """
    config['ione'] = {'address' : options.ioneIP, 'ports' : options.ionePorts}
    if options.ioneTopo != None:
        config['ione']['topology'] = options.ioneTopo
    """
    config['dcim'] = {'address': options.dcim_IP, 'name': options.dcim_Name}
    if options.nsxt_IP is not None:
        config['nsxt'] = {"address": options.nsxt_IP}
    config['email'] = options.Session_User
    config['name'] = options.Session_User + '_' + options.TestEnv
    json['testrun']['configuration-profile'] = deepcopy(config)
    with open('%s.cfg' % config['name'], 'w') as cfg:
        cfg.write(str(json['testrun']['configuration-profile']))

    rval = E.encode(json)
    NSXLOG.debug('launching...%s' % str(rval))
    return rval


def launch_nsx_test(json):
    REQUESTS_TIMEOUT_SECONDS = 20
    headers = {'User-Agent': 'ATF NSX Trigger', 'Content-Type': 'application/json', 'Accept': 'application/json'}
    D = JSONDecoder()
    NSXLOG.info('Requesting test launch')
    try:
        djson = D.decode(json)
        NSXLOG.debug('outgoing JSON is good:')
        NSXLOG.debug(dumps(djson, sort_keys=True, indent=4, separators=(',', ':')))
    except Exception as error:
        NSXLOG.error(str(error))
        NSXLOG.error(str(json))
        NSXLOG.error('outgoing JSON is malformed')
        exit(1)
    atf = etree.parse('%s/framework.xml' % DOCROOT).find('atf')
    url = atf.find('url').text.replace('/admin/', ':8443/launch')
    NSXLOG.debug('%s' % url)

    request_file = 'last_launch.request' if 'testrun' in djson else 'last_status.request'
    with open(request_file, 'w') as resp:
        resp.write(str(djson))
    response_file = 'last_launch.response'
    with open(response_file, 'w') as outfd:
        body = dumps(json)
        try:
            NSXLOG.debug('requesting...%s using certs: %s,%s,%s' % (url, ATF_CERT, ATF_CERT_KEY, CERT_BUNDLE))
            rval = requests.post(url=url, data=json, cert=(ATF_CERT, ATF_CERT_KEY), verify=CERT_BUNDLE, headers=headers,
                                 timeout=REQUESTS_TIMEOUT_SECONDS)
        except requests.exceptions.SSLError as estr:
            NSXLOG.error('SSL exception error encountered %s' % str(estr))
            raise AssertionError(str(estr))
        except Exception as estr:
            NSXLOG.error('Unknown error encountered during request:\n %s' % str(estr))
            raise AssertionError(str(estr))
        NSXLOG.debug('rval: \nStat code: %d\nText: %s' % (rval.status_code, rval.text))
        outfd.write("Response from ATF:\nStat code: %d\nText: %s" % (rval.status_code, rval.text))
    with open(response_file, 'r') as response:
        rjson = rval.text
        try:
            djson = D.decode(rjson)
            NSXLOG.info('Response is well-formed JSON:')
        except:
            estr = 'Received malformed JSON from server'
            NSXLOG.error(estr)
            NSXLOG.error(str(rjson))
            return None, estr
    response_type = djson.keys()[0]
    try:
        if 'testrun-id' in djson[djson.keys()[0]]:
            NSXLOG.debug('parsing "testrun-id"')
            tid = djson[djson.keys()[0]]['testrun-id']
        else:
            NSXLOG.debug('No testrun-id found')
            tid = None
        return tid, dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':'))
    except Exception as error:
        NSXLOG.error(str(error))
        return (
            None, 'ERROR: %s\n%s' % (str(error), dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':'))))


if __name__ == "__main__":
    import sys

    environment, user = (sys.argv[1], sys.argv[2])
    V = VulnDB(environment, user)

    # check to see if a test is already running on for this user
    try:
        sessionxml = etree.parse('%s/%s/sessions.xml' % (DOCROOT, user))
    except Exception as estr:
        sys.stderr.write('session file not found for user %s\n' % user)
        NSXLOG.error('session file not found for user %s' % user)
        exit(1)
    session = sessionxml.find('session')
    if session.attrib['running'] == 'yes':
        sys.stderr.write('NSX test is already in progress\n')
        NSXLOG.error('NSX test is already in progress')
        exit(2)
    # check to see if the 10G resource is in use
    try:
        locks = etree.parse('%s/locks.xml' % DOCROOT)
    except:
        sys.stderr.write('lock file is in use\n')
        NSXLOG.error('lock file is in use\n')
        exit(4)
    all_locks = locks.findall('lock')
    for lock in all_locks:
        if lock.attrib['bps'] == V.bps_IP:
            topo_in_lock = lock.attrib['topo']
            topo_in_config = V.bps_Topology.split(',')
            for bps_pair in topo_in_config:
                for bps_port in bps_pair.split(':'):
                    if bps_port in topo_in_lock:
                        sys.stderr.write('Breaking Point %s is in use\n' % bps_port)
                        NSXLOG.debug('Breaking Point %s is in use' % bps_port)
                        exit(3)
    latest = V.Get_Latest_Suricata_RS_Version()
    ruleset = session.find('nsxt/target-ruleset')
    last_version = ruleset.attrib['version']
    if len(sys.argv) > 3:
        version = sys.argv[3]
        forced_test = True
    else:
        version = latest
        forced_test = False
    if last_version != latest or forced_test is True:
        V.__dict__['tests'] = ['Ruleset_Performance:NSX-T']
        V.__dict__['group'] = 'Ruleset Performance'
        V.__dict__['config'] = {'name', 'This is a test'}
        V.__dict__['ruleset_version'] = version
        json = launch_request_json(V)

        D = JSONDecoder()
        djson = D.decode(json)
        NSXLOG.debug(dumps(djson, sort_keys=True, indent=4, separators=(',', ':')))
        resp = launch_nsx_test(json)

        NSXLOG.debug('Response for launch of test ID "%s" is \n%s' % (resp[0], resp[1]))
    else:
        NSXLOG.debug('Version %s has already been tested' % version)
    exit(0)
