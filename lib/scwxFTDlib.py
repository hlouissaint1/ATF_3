#! /usr/bin/python
# Author G. Owen, gowen@secureworks.com
# Updated by Himmler Louissaint TLN-11931
import os
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from time import time, strftime, mktime, strptime, sleep, localtime
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

SAMPLES_PER_PAGE = 20
PAGE_LIST_SIZE = 11

PROMPT = '.*[#\$\>\:] '
SESSION_TIMEOUT = 1800
MAX_REFRESH_COUNT = 3

FTD_LOGPATH = '/var/www/cgi-bin/lib/logs'
DOCROOT = '/var/www/html/htdocs'
MODULE = 'scwxFTDlib.py'
FTD_LOG = 'ftd.log'

logging.basicConfig(
    format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    filename='%s/%s' % (FTD_LOGPATH, FTD_LOG),
    filemode='w',
    level=logging.DEBUG)

FTDLOG = logging.getLogger('ftd_regression')
rhandler = logging.FileHandler('%s/%s' % (FTD_LOGPATH, FTD_LOG))
formatter = logging.Formatter('%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s')
rhandler.setFormatter(formatter)
FTDLOG.addHandler(rhandler)
FTDLOG.setLevel(logging.DEBUG)
FTDLOG.debug('Initialized logging')

###########################################################################################################################################################################

class VulnDB:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.url = 'https://%s/latest_vrt_release.txt?apikey=%s&release_number=CANDIDATE_RELEASE_ID' % (
            self.vlndb_IP, self.vlndb_Password)
        self.diff_pars = 'engine_name=Snort&engine_version=2.9.9.0&policy=VRT&first_release_number=FIRST&second_release_number=SECOND'
        self.diff_url = 'https://%s/pcs_release_diff.xml?apikey=%s&%s' % (
            self.vlndb_IP, self.vlndb_Password, self.diff_pars)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.Session()
        self.session.trust_env = False
        self.error = 'Unknown'
        self.added = []
        self.changed = []
        self.deleted = []

        headers = {}

    def fetch_vrt_ruleset(self, version=''):
        url = self.url.replace('CANDIDATE_RELEASE_ID', version)
        raw = self.session.get(url, verify=False)
        if raw.status_code != 200:
            self.error = 'ERROR %d: fetching CTU ruleset: %s' % (raw.status_code, raw.reason)
            return (None, None)
        filename = raw.headers['content-disposition'].split('=')[1]
        if version == '':
            current_version = re.findall('(?<=vrt_release_)(\d+)_.*', filename)[0]
            return (current_version)
        outfd, outfn = mkstemp(prefix="_.", suffix=filename)
        with open(outfn, 'w') as f:
            f.write(raw.text)
        return (filename, outfn)

    def fetch_ctu_ruleset_diffs(self, first, second, **opts):
        url = self.diff_url.replace('FIRST', first).replace('SECOND', second)
        raw = self.session.get(url, verify=False)
        if raw.status_code != 200:
            self.error = 'ERROR %d: fetching CTU ruleset: %s' % (raw.status_code, raw.reason)
            return (None, None)
        xml = etree.fromstring(str(raw.text))
        if 'return_xml' in opts and opts['return_xml'] == True:
            return (xml)
        if 'return_raw' in opts and opts['return_raw'] == True:
            return (raw.text)

        self.added = xml.xpath('//signature[@diff="added"]')
        self.deleted = xml.xpath('//signature[@diff="deleted"]')
        self.changed = xml.xpath('//signature[@diff="changed"]')
        rstr = '\nAdded %d rule(s):\n' % len(self.added)
        rstr += ''.join('\tswid:%s vid:%s gid:%s - %s\n' % (
            x.attrib['swid'],
            x.attrib['vid'],
            x.attrib['gid'],
            x.attrib['msg']) for x in self.added)
        rstr += '\nDeleted %d rule(s):\n' % len(self.deleted)
        rstr += ''.join('\tswid:%s vid:%s gid:%s - %s\n' % (
            x.attrib['swid'],
            x.attrib['vid'],
            x.attrib['gid'],
            x.attrib['msg']) for x in self.deleted)
        rstr += '\nChanged %d rule(s):\n' % len(self.changed)
        rstr += ''.join('\tswid:%s vid:%s gid:%s - %s\n' % (
            x.attrib['swid'],
            x.attrib['vid'],
            x.attrib['gid'],
            x.attrib['msg']) for x in self.changed)
        return (rstr)


#######################################################################################################################################################################################

class fmcCall(object):
    def __call__(self, pFunction):

        def fmc_api_call(self, object_URL, data=None, obj_uuid=None, **opts):
            if time() - self.refresh_timer >= SESSION_TIMEOUT:
                FTDLOG.debug('requesting session token from FMC')
                if self.refresh_count >= MAX_REFRESH_COUNT:  # request a new token
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    url = '%s/auth/generatetoken' % self.platform_uri
                    resp = self.session.post(url, auth=(self.fmc_User.upper(), self.fmc_Password), verify=False)
                    FTDLOG.debug('resp=: %s\n%s\n' % (str(resp.headers), resp.text))

                    if resp.status_code != 204:
                        FTDLOG.error('failed to retrieve session token from FMC @ %s: %d\n%s' % (
                            self.fmc_IP, resp.status_code, resp.test))
                        raise AssertionError, 'failed to retrieve session token from FMC @ %s: %d\n%s' % (
                            self.fmc_IP, resp.status_code, resp.test)
		    self.__dict__.update({'%s' % S.lower() : resp.headers[S] for S in resp.headers.keys()} ) 
                    self.headers['X-auth-access-token'] = self.__dict__['x-auth-access-token']
                    self.headers['Domain_UUID'] = self.domain_uuid
                    self.refresh_count = 0
                    self.refresh_timer = time()

                else:  # refresh the existing token
                    self.headers['X-auth-refresh-token'] = self.__dict__['x-auth-refresh-token']
                    self.headers['X-auth-access-token'] = self.__dict__['x-auth-access-token']
                    url = '%s/auth/refreshtoken' % self.platform_uri
                    resp = self.session.post(url, headers=self.headers, verify=False)
                    FTDLOG.debug('resp=: %s\n%s\n' % (str(resp.headers), resp.text))

                    self.__dict__.update(resp.headers)
                    if 'ERROR' in resp:
                        FTDLOG.error('ERROR refreshing access token: %s' % resp)
                        return (resp)
                    self.refresh_count += 1
                    self.headers.pop('X-auth-refresh-token')
                    self.refresh_timer = time()
            FTDLOG.debug('successfully retrieve session token from FMC')
            if 'link' in opts and opts['link'] == True:
                url = object_URL
            elif 'platform' in opts and opts['platform'] == True:
                url = '%s/%s' % (self.platform_uri, object_URL)

            else:
                url = '%s/domain/%s/%s' % (self.config_uri, self.domain_uuid, object_URL)
            FTDLOG.debug('data field is:\n%s', str(data))

            if 'link' in opts and opts['link'] == True:
                url = object_URL
            elif 'platform' in opts and opts['platform'] == True:
                url = '%s/%s' % (self.platform_uri, object_URL)
            else:
                url = '%s/domain/%s/%s' % (self.config_uri, self.domain_uuid, object_URL)
            FTDLOG.debug('data field is:\n%s', str(data))
            if 'test' in opts:
                print
                dumps(data)
                return (data)
            rval = pFunction(self, url, data, **opts)
            try:
                response = self.json.decode(rval.text)
                self.response = deepcopy(response)
            except Exception as estr:
                return ('ERROR return from API:\n%s\%s' % (str(estr), rval.text))
            FTDLOG.debug('received response:\n%s' % response)
            return (response)

        return (fmc_api_call)

#######################################################################################################################################################################################

def non_fatal_error(rtext):
    match = re.findall('^Non-Fatal error:.*$', rtext, re.MULTILINE)
    if len(match) > 0:
        FTDLOG.debug('FMC reported a non-fatal error:\n%s' % rtext)
        eresp = ''
        for m in match:
            eresp += m
        return ('WARNING: \n %s' % eresp)
    return (None)

#######################################################################################################################################################################################

class fmc_sudo(object):
    def __call__(self, pFunction):

        def fmc_sudo_call(self, **opts):
            if not 'fmc_IP' in self.__dict__ or self.fmc_IP == None:
                return ('ERROR: the FMC device address was not supplied')
            fmc_expect = paramiko.SSHClient()
            fmc_expect.load_system_host_keys()
            fmc_expect.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            fmc_expect.connect(hostname=self.fmc_IP, username=self.fmc_User, password=self.fmc_Password)
            try:
                interact = SSHClientInteraction(fmc_expect, timeout=1800, display=True)
                interact.expect(PROMPT)
            except Exception as estr:
                return ('ERROR: unable to establish a dialog with FMC @ %s:\n\t%s' % (self.fmc_IP, estr))
            try:
                rval = pFunction(self, interact, **opts)
            except Exception as estr:
                return (
                        'ERROR: the command sent to FMC @ %s resulted in an exception:\nexception=%s' % (
                    self.fmc_IP, estr))

            fmc_expect.close()
            return (rval)

        return (fmc_sudo_call)

#######################################################################################################################################################################################

class ignite_sudo(object):
    def __call__(self, pFunction):

        def ignite_sudo_call(self, **opts):
            if not 'ignite_IP' in self.__dict__ or self.ignite_IP == None:
                return ('ERROR: the FMC device address was not supplied')
            ignite_expect = paramiko.SSHClient()
            ignite_expect.load_system_host_keys()
            ignite_expect.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ignite_expect.connect(hostname=self.ignite_IP, username=self.ignite_User, password=self.ignite_Password)
            try:
                interact = SSHClientInteraction(ignite_expect, timeout=1800, display=True)
                interact.expect(PROMPT)
            except Exception as estr:
                return ('ERROR: unable to establish a dialog with Cisco Ignite @ %s:\n\t%s' % (self.ignite_IP, estr))
            try:
                rval = pFunction(self, interact, **opts)
            except Exception as estr:
                return (
                        'ERROR: the command sent to FMC @ %s resulted in an exception:\nexception=%s' % (
                    self.ignite_IP, estr))

            ignite_expect.close()
            return (rval)

        return (ignite_sudo_call)

#######################################################################################################################################################################################

class ftdExpert(object):
    def __call__(self, pFunction):
        def ftd_expert_call(self, **opts):
            warnings.simplefilter('ignore')
            if not 'ftd_IP' in self.__dict__ or self.ftd_IP == None:
                return ('ERROR: the FTD device address was not supplied')
            ftd = paramiko.SSHClient()
            ftd.load_system_host_keys()
            ftd.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ftd.connect(hostname=self.ftd_IP, username=self.ftd_User, password=self.ftd_Password)
            try:
                interact = SSHClientInteraction(ftd, timeout=1800, display=False)
                interact.expect(PROMPT)
                interact.send('expert\n')
                interact.expect(PROMPT)
            except Exception as estr:
                return ('ERROR: unable to establish a dialog with FTD @ %s:\n\t%s' % (self.ftd_IP, estr))
            try:
                rval = pFunction(self, interact, **opts)
            except Exception as estr:
                return ('ERROR: the command sent to %s resulted in an exception:\nexception=%s' % (self.ftd_IP, estr))

            ftd.close()
            return (rval)

        return (ftd_expert_call)

#######################################################################################################################################################################################

class ftdShell(object):
    def __call__(self, pFunction):
        def ftd_shell_call(self, command=None, **opts):
            if not 'ftd_IP' in self.__dict__ or self.ftd_IP == None:
                return ('ERROR: the FTD device address was not supplied')
            ftd = paramiko.SSHClient()
            ftd.load_system_host_keys()
            ftd.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ftd.connect(hostname=self.ftd_IP, username=self.ftd_User, password=self.ftd_Password)
            try:
                interact = SSHClientInteraction(ftd, timeout=30, display=False)
                interact.expect(PROMPT)
            except Exception as estr:
                return ('ERROR: unable to establish a dialog with FTD @ %s:\n\t%s' % (self.ftd_IP, estr))
            try:
                rval = pFunction(self, interact, command, **opts)
            except Exception as estr:
                return ('ERROR: the command sent to %s resulted in an exception:\nexception=%s' % (self.ftd_IP, estr))
            ftd.close()
            return (rval)

        return (ftd_shell_call)

#######################################################################################################################################################################################

class FTD():
    @keyword()
    def Get_Interface_List(self, **opts):
        resp = self.ftd_command('show interface')
        if 'return_raw' in opts and opts['return_raw'] == True:
            return (resp)
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FTD device at %s' % self.ftd_IP)
        interfaces = re.findall('^Interface\s\S+', resp, re.MULTILINE)
        if 'return_as_list' in opts and opts['return_as_list'] == True:
            return (map(lambda s: s.replace('Interface ', ''), interfaces))
        return (''.join('%s\n' % iface.replace('Interface ', '') for iface in interfaces))

    @keyword()
    def Get_Interface_Stats(self, interfaces=None, **opts):
        if interfaces == None:
            interface_list = self.Get_Interface_List(return_as_list=True, exclude_mgmt_iface=True)
        else:
            interface_list = interfaces.split(',')
        interface_stats = {}
        rval = ''
        for interface in interface_list:
            resp = self.ftd_command('show interface %s' % interface)
            if 'return_raw' in opts:
                return (resp)
            state = re.findall('^.*is.*(up|down)', resp)[0]
            """
                if state != 'up':
                    interface_stats[interface] = {'state': state}
                    continue
            """
            try:
                interface_stats[interface] = {
                    'state': re.findall('^.*is.*(up|down)', resp)[0],
                    'pkts_in': re.findall('\d+(?=\spackets\sinput)', resp)[0],
                    'pkts_out': re.findall('\d+(?=\spackets\soutput)', resp)[0],
                    'pkts_dropped': re.findall('\d+(?=\spackets\sdropped)', resp)[0],
                }
                if interfaces != None:
                    for metric in interface_stats[interface]:
                        if 'return_%s' % metric in opts:
                            return (interface_stats[interface][metric])
                rval += '\n%s' % interface
                rval += ''.join('\n\t%s=%s' % (stat.replace('_', ' '), interface_stats[interface][stat]) for stat in
                                interface_stats[interface])

            except Exception as estr:
                return ('ERROR: could not retrieve statistics for interface %s on %s:\n\%s\n%s' % (
                    interface, self.ftd_IP, str(estr), resp))
            failed = ''
            for stat in interface_stats[interface]:
                limit_str = 'limit_%s' % stat
                if limit_str in opts and int(interface_stats[interface][stat]) > int(opts[limit_str]):
                    failed += '\n%s FAILED: "%s" exceeded allowed limit of %s' % (interface, stat, opts[limit_str])
            if failed != '':
                rval += '%s\n' % failed
        self.interface_stats.update(interface_stats)
        if 'return_as_dict' in opts and opts['return_as_dict'] == True:
            return (interface_stats)
        return (rval)

    @keyword()
    def Get_Traffic(self, interfaces=None, **opts):
        resp = self.ftd_command('show traffic')
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FTD device at %s' % self.ftd_IP)
        rval = ''
        if interfaces == None:
            ilist = re.findall('^\S*(?=\:$)', resp, re.MULTILINE)
            interface_list = ilist
        else:
            interface_list = interfaces.split(',')
        for interface in interface_list:
            ix = resp.find(interface)
            ilines = resp[ix:].split('\n', 13)
            garbage = ilines.pop(13)
            rval += ''.join('%s\n' % value for value in ilines)

        return (rval)

    @keyword()
    def Get_Snort_Metrics(self, **opts):
        resp = self.ftd_command('show snort statistics')

        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FTD device at %s' % self.ftd_IP)
        if 'return_raw' in opts and opts['return_raw'] == True:
            return (resp)

        regex1 = re.compile('((Passed|Blocked|Injected) Packets)(\s+)(\d+)$', re.MULTILINE)
        regex2 = re.compile('((Packets bypassed\s\(Snort Down\))(\s+)(\d+)$)', re.MULTILINE)
        regex3 = re.compile('((Packets bypassed\s\(Snort Busy\))(\s+)(\d+)$)', re.MULTILINE)
        metrics_list = {
            'Passed Packets': regex1,
            'Blocked Packets': regex1,
            'Injected Packets': regex1,
            'Packets (Snort Down)': regex2,
            'Packets (Snort Busy)': regex3,
        }
        for metric in metrics_list:
            mx = re.findall(metrics_list[metric], resp)
            try:
                metrics_list[metric] = int(mx[0][3])
            except:
                return (resp)
        self.snort_metrics = metrics_list
        if 'limit' in opts:
            benign_packets = metrics_list.pop('Passed Packets')
            if benign_packets == 0:
                return ('FAILED: No traffic detected through snort engine\n')
            failed = 'FAILED: {0} count of {1}  exceeds the specified limit of {2}'
            passed = 'PASSED: {0} count of {1}  was within the specified limit of {2}'

            limit = int(opts['limit'])
            results = map(
                lambda m: failed.format(m, metrics_list[m], limit) if metrics_list[m] > limit else passed.format(m,
                                                                                                                 metrics_list[
                                                                                                                     m],
                                                                                                                 limit),
                list(metrics_list))
            return (''.join('%s\n' % result for result in results))
        return (resp)

    def Verify_No_Dropped_Packets(self):
        rval = self.Get_Snort_Metrics(self.ftd_IP)
        rval += '\n' + self.Get_Snort_Metrics(self.ftd_IP, limit='0')
        if not 'FAILED' in rval:
            rval += '\nAll packet counters PASSED\n'
        return (rval)

    @ftdShell()
    def ftd_command(self, dialog, command, **opts):
        assert command != None, 'Missing command'
        dialog.send(command)
        dialog.expect(PROMPT)
        data = dialog.current_output_clean.strip('\n')
        return (data)

    @ftdExpert()
    def get_ctu_local_rules_from_ftd(self, dialog, **opts):
        framework = etree.parse('%s/framework.xml' % DOCROOT)
        atfurl = framework.find('atf/url')
        assert atfurl != None and atfurl.text != '', 'ERROR: the ATF framework config file is missing'
        atf_host = atfurl.text.replace('/admin/', '').replace('https://', '')
        cmd = 'ls /var/sf/detection_engines/*/intrusion/*/local.rules |tail -1'
        dialog.send(cmd)
        dialog.expect(PROMPT)
        rules_file = dialog.current_output_clean.strip('\n')
        print
        'RULES FILE:', rules_file
        fd, atf_tmp_file = mkstemp(prefix='ftd', suffix='.rules')
        print
        'TMP:', atf_tmp_file
        print
        'CONNECTION OK'
        cmd = 'scp -i ~/.ssh/sshkey_for_atf %s gowen@%s:%s/rules.%s' % (rules_file, atf_host, DOCROOT, self.ftd_IP)
        print
        'CMD:', cmd
        dialog.send(cmd)
        dialog.expect(PROMPT)
        resp = dialog.current_output_clean
        print
        'COMMAND RESPONSE:', resp
        rules = {}
        with open(atf_tmp_file, 'r') as f:
            for line in f.readlines():
                if line[0] == '#':
                    continue
                vids = re.findall('(?<=VID)\d+', line)
                if len(vids) == 0:
                    continue
                vid = vids[0]
                gids = re.findall('(?<=gid:)\d+', line)
                if len(gids) == 0:
                    continue
                gid = gids[0]
                sids = re.findall('(?<=sid:)\d+', line)
                if len(sids) == 0:
                    continue
                sid = sids[0]
                swids = re.findall('(?<=msg:\")\d+', line)
                if len(swids) == 0:
                    continue
                swid = swids[0]
                rules[swid] = {'vid': vid, 'sid': sid, 'gid': gid, 'rule': line}

        os.unlink(atf_tmp_file)
        with open('%s.parsed' % atf_tmp_file, 'w') as f:
            f.write(str(rules))

        return (rules)

    @ftdExpert()
    def fetch_rs_version_on_device(self, dialog, **opts):
        dialog.send('ls /var/sf/detection_engines/*/intrusion/*/local.rules')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        if not raw.find('No such file or directory') < 0:
            err = 'ERROR: no local rules file found on FTD device'
            FTDLOG.error(err)
            return (err)
        cmd = 'pcregrep -o  "(?<=ruleset-release\s)\d+" /var/sf/detection_engines/*/intrusion/*/local.rules |sort |uniq |tail -1\n'
        dialog.send(cmd)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        resp = re.findall('^\d+$', raw, re.MULTILINE)
        if len(resp) > 0:
            return resp[0]
        return ('0')

    @ftdExpert()
    def get_ftd_name(self, dialog, **opts):
        dialog.send('hostname\n')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        resp = raw.split('\n')[1]
        return (resp)

    @ftdExpert()
    def get_memory_data(self, dialog, **opts):
        cmd = 'cat /proc/meminfo\n'
        percent = lambda t, v: 100.0 * (float(v) / float(t))
        dialog.send(cmd)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        data = re.findall('(MemTotal|MemFree):\s+(\d+)\s(\w+)', raw)
        assert len(data) > 1, 'ERROR: unable to retrieve memory usage'
        freepcnt = percent(data[0][1], data[1][1])
        usedpcnt = 100.0 - freepcnt
        used = str(int(data[0][1]) - int(data[1][1]))
        if 'limit' in opts and opts['limit'] != None:
            if usedpcnt <= float(opts['limit']):
                result = 'PASSED: memory usage is within acceptable limit of %s%c' % (opts['limit'], 0x25)
            else:
                result = 'FAILED: memory usage exceeds acceptable limit of %s%c' % (opts['limit'], 0x25)
        else:
            result = ''
        rval = '%s:\t%s\n%s:\t%s (%0.2f%c)\nMemUsed:\t%s (%0.2f%c)\n%s\n' % (
            data[0][0], data[0][1],
            data[1][0], data[1][1],
            freepcnt, 0x25,
            used,
            usedpcnt, 0x25,
            result)

        return (rval)

    @ftdExpert()
    def pmtool_cmd(self, dialog, **opts):
        assert 'command' in opts, 'ERROR: No command to give pmtool'
        cmd = 'sudo pmtool %s' % opts['command']
        FTDLOG.debug(cmd)
        dialog.send(cmd)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw)

    @keyword()
    def Restart_Snort(self):
        FTDLOG.debug('Restarting Snort')
        rsp = self.pmtool_cmd(command='restartbytype snort')
        sleep(30)
        return (rsp)

    @ftdExpert()
    def tail_log(self, dialog, **opts):
        assert 'log' in opts, 'ERROR: cannot tail if the log is not specified'
        if 'length' in opts:
            length = opts['length']
        else:
            length = '100'
        if 'mark' in opts:
            cmd = 'sudo grep -A %s "%s" %s' % (length, opts['mark'], opts['log'])
        else:
            cmd = 'sudo tail -n %s %s' % (length, opts['log'])
        dialog.send(cmd)
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw)

    @ftdExpert()
    def fetch_last_top_heading(self, dialog, **opts):
        cmd = 'sudo pcregrep "^top.*$" /var/log/top.log |tail -1'
        dialog.send(cmd)
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw.strip('\n'))

    @ftdExpert()
    def fetch_ftd_time(self, dialog, **opts):
        cmd = 'date'
        dialog.send(cmd)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (str(raw))

    @keyword()
    def Get_Last_Top_Info(self, ):
        top_hdr = self.fetch_last_top_heading()
        top_info = self.tail_log(mark=top_hdr, log='/var/log/top.log', length='4')
        return (top_info)
        self.memory = {}
        tmem = re.findall('(?<=Mem\:)(\s+\d+\S*\s\w+.*)', top_info)
        for m in tmem[0].split(','):
            metric = m.lstrip().split(' ')
            self.memory[metric[1]] = metric[0]
        self.swap = {}
        tswap = re.findall('(?<=Swap\:)(\s+\d+\S*\s\w+.*)', top_info)
        for m in tmem[0].split(','):
            metric = m.lstrip().split(' ')
            self.swap[metric[1]] = metric[0]
        tcpu = re.findall('(?<=Cpu\(s\):)(\s+\d+\.\d\S+.*)', top_info)
        self.cpu = {}
        for m in tcpu[0].split(','):
            metric = m.lstrip().split('%c' % 0x25)
            self.cpu[metric[1]] = metric[0]
        self.load_avg = re.findall('(?<=average\:)(\s+\d+\.\d+\S.*)', top_info)[0].split(',')

        return (top_info)

    @ftdExpert()
    def check_ruleset_diff(self, diffs, rs_version):

        for added in diffs.xpath('signature[@diff="added"]'):
            swid = added.attrib['swid']
            regex = re.compile('')

    @keyword()
    def Verify_FTD_Ruleset_Diffs(self, first, second):
        ftd_ruleset = self.get_ctu_local_rules_from_ftd()
        is_same = lambda f, s, v: (f[s]['gid'] == v.attrib['gid']) and (f[s]['vid'] == v.attrib['vid']) and (
                int(f[s]['sid']) == 1700000 + int(s))
        vlndb = VulnDB(self.TestEnv, self.ATF_User)
        diffs = vlndb.fetch_ctu_ruleset_diffs(first, second, return_xml=True)
        rval = ''
        # varify that the added rules are on the FTD
        for added in diffs.xpath('signature[@diff="added"]'):
            swid = added.attrib['swid']
            exists = False

            if (swid in ftd_ruleset) and (is_same(ftd_ruleset, swid, added) == True):
                exists = True
            if exists != True:
                rval += 'ERROR: added ruleset could not be found on the FTD: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, added.attrib[s]) for s in added.attrib)
            else:
                rval += 'PASSED: added ruleset was found on the FTD: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, added.attrib[s]) for s in added.attrib)
        for removed in diffs.xpath('signature[@diff="removed"]'):
            swid = removed.attrib['swid']
            exists = False
            if (swid in ftd_ruleset) and (is_same(ftd_ruleset, swid, removed) == True):
                exists = True
            if exists == True:
                rval += 'ERROR: removed ruleset is still on FTD: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, removed.attrib[s]) for s in removed.attrib)
            else:
                rval += 'PASSED: removed ruleset was not found on FTD: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, removed.attrib[s]) for s in removed.attrib)

        for changed in diffs.xpath('signature[@diff="changed"]'):
            swid = changed.attrib['swid']
            exists = False
            if (swid in ftd_ruleset) and (is_same(ftd_ruleset, swid, changed) == True):
                exists = True
            if exists != True:
                rval += 'ERROR: changed ruleset could not be found on the FTD: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, changed.attrib[s]) for s in changed.attrib)
            else:
                rval += 'PASSED: changed ruleset was found on the FTD: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, changed.attrib[s]) for s in changed.attrib)

        return (rval)

    @keyword()
    def Verify_FTD_CTU_Ruleset_Version(self, version=None, waittime='300'):
        from time import sleep

        resp = self.fetch_rs_version_on_device()
        if 'ERROR' in resp:
            return (resp)
        rval = ''
        if version != None:
            timeout = int(waittime) + int(time())
            while time() < timeout:
                resp = self.fetch_rs_version_on_device()
                if 'ERROR' in resp:
                    return (resp)
                if int(resp) != int(version):
                    rval = 'FAILED: the FTD device @ %s is at version "%d" installed...not version "%d"' % (
                        self.ftd_IP, int(resp), int(version)
                    )
                else:
                    rval = 'PASSED: the FTD device @ %s is running ruleset version "%d"' % (self.ftd_IP, int(resp))
                    break
                sleep(30)
        else:
            rval = '%d' % int(resp)

        return (rval)

    @keyword()
    def Get_FTD_CTU_Ruleset_Version(self):
        return (self.Verify_FTD_CTU_Ruleset_Version())

    @keyword()
    def Get_CPU_Utilization(self, limit='100.0'):
        resp = self.ftd_command('show cpu usage')
        print
        resp
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FTD device at %s' % self.ftd_IP)
        assert 'CPU utilization' in resp, 'ERROR-failed to fetch CPU utilization from FTD device @ %s' % self.ftd_IP
        return (self.check_ftd_cpu_usage(resp, limit))

    def check_ftd_cpu_usage(self, resp, limit_str):
        try:
            limit = float(limit_str.replace('%', ''))
        except:
            return ('ERROR: specified limit is neither an interger or a float')
        vals = re.findall('(\d+(\.\d+)*)(?=\%)', resp)
        usage = [('%s.%s' % (i[0], i[1] if i[1] != '' else '0')) for i in vals]
        limit_check = map(lambda x: 'FAIL' if float(x) > limit else 'PASS', usage)
        results = ['5s', '1m', '5m']
        rval = 'FAILED' if limit_check.count('FAIL') > 0 else 'PASSED'
        rval += ' (limit = %3.1f%c):' % (limit, 0x25)
        rval += ''.join(
            '%s=%3.1f%c (%s),' % (result, float(usage.pop(0)), 0x25, limit_check.pop(0)) for result in results)
        return (rval.rstrip(','))

    @keyword()
    def Get_FTD_CPU_Core_Utilization(self, limit='100.0', core=''):
        resp = self.ftd_command('show cpu')
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FTD device at %s' % self.ftd_IP)
        if core == '':
            rval = self.check_ftd_cpu_usage(resp, limit)
            return (rval)
        cores = re.findall('^Core\s\d+.*$', resp, re.MULTILINE)
        rval = ''
        for core in cores:
            corestr = re.findall('Core \d+', core)[0]
            rval += '%s-%s\n' % (corestr, self.check_ftd_cpu_usage(core, limit))
        return (rval)


    def get_columns(self, col_hdrs, extract, usr=0, sys=0, return_dict=False, **opts):
        if usr != 0:
            extract += ''.join(',usr[%d]' % c for c in range(0, usr))
        if sys != 0:
            extract += ''.join(',sys[%d]' % c for c in range(0, sys))
        headers = col_hdrs.lstrip('#').split(',')

        col_indices = []
        col_dict = {}
        for column in extract.split(','):
            try:
                col_x = 1 + headers.index(column)
                col_dict[column] = col_x
                col_indices.append(col_x)
            except:
                continue
        if len(col_indices) == 0:
            return
        col_indices = sorted(col_indices)
        col_hdr_list = map(lambda x: headers[x - 1], col_indices)
        for col in range(0, len(col_hdr_list)):
            col_dict[col_hdr_list[col]] = col
        span = col_indices[0]
        rval = '%d' % col_indices[0]

        for x in range(1, len(col_indices)):
            if col_indices[x] == span + 1:
                if rval.endswith('-'):
                    continue
                else:
                    rval += '-'
                span = col_indices[x]
            else:
                if rval.endswith('-'):
                    rval += '%d,%d' % (span, col_indices[x])
                else:
                    rval += ',%d' % col_indices[x]
                span = col_indices[x]
        if return_dict == True:
            return (rval.rstrip('-'), col_dict)
        else:
            return (rval.rstrip('-'))

    def get_stats(self, dialog, columns, **opts):
        end_time = float(opts['end_time'])
        start_time = float(opts['start_time'])
        FTDLOG.debug('start time= %s, end time= %s, columns= "%s"' % (start_time, end_time, columns))
        if 'wait_for_boundary' in opts:
            wait_for_boundary = opts['wait_for_boundary']
        else:
            wait_for_boundary = True
        if wait_for_boundary == True:
            boundary = (end_time - (end_time % 300)) + 300
            current_time = self.Get_FTD_Time(return_epoch=True)
            FTDLOG.debug('time boundary= %s, current_time= %s' % (boundary, current_time))
            while current_time < boundary:
                current_time = self.Get_FTD_Time(return_epoch=True)
                sleep(1)
        mark = start_time - (start_time % 300)
        FTDLOG.debug('time mark= %d' % int(mark))
        dialog.send('sudo su -')
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        dialog.send('/usr/local/sf/bin/de_info.pl\n')
        dialog.expect(PROMPT)
        uuids = dialog.current_output_clean.strip('\n')
        uuid = re.findall('DE UUID\s+\:\s(\S+)', uuids, re.MULTILINE)[0]

        try:
            cmd = 'cat /var/sf/detection_engines/%s*/instance-*/now | grep -v "####" |head -1' % uuid
            FTDLOG.debug('sending command: %s' % cmd)
            dialog.send(cmd)
            dialog.expect(PROMPT)
            resp = dialog.current_output_clean
            FTDLOG.debug('response was: %s' % resp)
        except Exception as estr:
            FTDLOG.debug('erred response was: %s' % estr)
            return (estr)
        column_headers = re.findall('^#\S+', resp, re.MULTILINE)
        assert len(column_headers) > 0, 'unable to fetch column headers'
        headers = column_headers[0]
        extract = columns.split(',')
        cpucol = self.get_columns(headers, 'iCPUs')
        cmd = 'cat /var/sf/detection_engines/%s*/instance-*/now | grep -v "####" |cut -s -d "," -f %s |grep -v "#" |tail -1' % (
            uuid, cpucol)
        FTDLOG.debug('sending command: %s' % cmd)
        dialog.send(cmd)
        dialog.expect(PROMPT)
        resp = re.findall('(?<=tail\s\-1)\d+', dialog.current_output.replace('\n', ''), re.MULTILINE)
        ncpus = resp[0]
        if 'usr' in extract:
            usr = int(ncpus)
            extract.pop(extract.index('usr'))
        else:
            usr = 0
        if 'sys' in extract:
            sys = int(ncpus)
            extract.pop(extract.index('sys'))
        else:
            sys = 0
        ext = ''.join('%s,' % s for s in extract)
        columns, hdr_dict = self.get_columns(headers, ''.join('%s,' % s for s in extract).rstrip(','), usr, sys, True)

        cmd = 'cat /var/sf/detection_engines/%s*/instance-*/now | grep -v "####" |cut -s -d "," -f %s |grep -v "#" |tail -48' % (
            uuid, columns)
        FTDLOG.debug('sending expert command to FTD at %s: \n%s\n' % (self.ftd_IP, cmd))
        dialog.send(cmd)
        dialog.expect(PROMPT)
        resp = re.findall('^\d{10,12}.*', dialog.current_output_clean, re.MULTILINE)

        # resp = dialog.current_output_clean.split('\n')
        FTDLOG.debug('response was:\n%s...\n' % str(resp)[0:1000])

        return (resp, hdr_dict)

    @keyword()
    def Get_FTD_CPU_Stats(self, start_time=None, end_time=None, usr_limitstr='100.0', sys_limitstr='100.0', **opts):
        import traceback
        from math import floor, ceil

        cstats = ''
        if end_time == None or end_time == 'None':
            end_time = start_time
            start_time = str(float(end_time) - 300.0)
            FTDLOG.debug('no end time supplied...using start= %s, end= %s' % (start_time, end_time))
        try:
            cstats = self.get_cpu_stats(start_time=start_time, end_time=end_time, **opts)
            FTDLOG.debug('fetched CPU stats: \n%s' % str(cstats))
        except Exception as estr:
            tb = traceback.extract_stack()
            FTDLOG.error('FATAL ERROR fetching cpu metrics: %s\n%s' % (estr, tb))
            cstats = 'FATAL ERROR fetching cpu metrics: %s\n%s' % estr
        usr_limit = float(usr_limitstr)
        sys_limit = float(sys_limitstr)
        header = '\n      '
        result_val = ''
        if len(cstats) == 0:
            return (
                'ERROR:No stats were returned for the period specified...did you mean to set the "include_idle_periods" flag?')
        periods = sorted(cstats)

        headers = []
        cpus = []
        print_group = 0
        sub_header = ''
        rval = ''
        FTDLOG.debug('cstats type= %s' % type(cstats))
        for cpu in sorted(cstats[periods[0]], lambda x, y: int(x.replace('cpu', '')) - int(y.replace('cpu', ''))):
            cpun = int(cpu.replace('cpu', ''))
            rval += '%17s' % cpu
            try:
                cpus[print_group].append(cpu)
            except IndexError:
                cpus.append([])
                headers.append('')
                cpus[print_group].append(cpu)
            if (1 + cpun) % 4 == 0:
                headers[print_group] = '\n      ' + rval + '\n%-9s' % '5m period' + (4 * ('%9s%8s' % ('usr', 'sys')))
                rval = ''
                headers[print_group] += sub_header
                print_group += 1
        rval = ''
        for print_group in range(0, len(cpus)):
            results = {}
            result_val = ''
            rval += headers[print_group]
            for period in periods:
                fperiod = float(period)
                rval += '\n%s    ' % strftime('%0H:%0M:%0S', localtime(fperiod))
                for cpu in cpus[print_group]:
                    rval += '| %05.2f   %05.2f |' % (
                        float(cstats[period][cpu]['usr']), float(cstats[period][cpu]['sys']))
                    if float(cstats[period][cpu]['usr']) > usr_limit and float(cstats[period][cpu]['usr']) < 100.10:
                        tval = strftime('%0H:%0M:%0S', localtime(fperiod))
                        result_val += '\nPeriod %s FAILED: a usage value for "usr" on one or more CPUs exceeded the specified limit of %4.2f' % (
                            tval, usr_limit)
                    if float(cstats[period][cpu]['sys']) > sys_limit and float(cstats[period][cpu]['sys']) < 100.10:
                        tval = strftime('%0H:%0M:%0S', localtime(fperiod))
                        if not tval in results:
                            results[tval] = True
                            result_val += '\nPeriod %s FAILED: a usage value for "sys" on one or more CPUs exceeded the specified limit of %4.2f' % (
                                tval, sys_limit)
            locpu = cpus[print_group][0].replace('cpu', '')
            hicpu = cpus[print_group][len(cpus[print_group]) - 1].replace('cpu', '')

            if result_val == '':
                result_val = '\nCPU%s - CPU%s values for "usr" were below the limit of %4.2f and all values for "sys" were below the limit of %4.2f' % (
                    locpu, hicpu, usr_limit, sys_limit)
            rval += ('\n' + result_val + '\n')
        return (rval)

    @ftdExpert()
    def get_cpu_stats(self, dialog, **opts):
        assert 'end_time' in opts, 'illegal call to get_stats...no end time'
        assert 'start_time' in opts, 'illegal call to get_stats...no start time'
        start_time = float(opts['start_time'])
        end_time = float(opts['end_time'])
        if 'include_idle_periods' in opts:
            include_idle_periods = opts['include_idle_periods']
        else:
            include_idle_periods = False
        mark = start_time - (start_time % 300)
        FTDLOG.debug('fetching cpu stats from %s to %s (mark= %s)' % (opts['start_time'], opts['end_time'], str(mark)))
        resp, headers = self.get_stats(dialog, 'time,iCPUs,pkt_stats.pkts_recv,usr,sys', **opts)
        if resp[0].startswith('cat'):
            resp.remove(resp[0])
        rval = ''
        periods = {}
        FTDLOG.debug('headers: %s' % str(headers))
        FTDLOG.debug('first line: %s' % resp[0])
        nCPUs = resp[0].split(',')[headers['iCPUs']]
        FTDLOG.debug('Number of cpus= %s' % nCPUs)
        cpus = {}
        for x in range(0, int(nCPUs)):
            cpus['cpu%d' % x] = []
        cpus = sorted(cpus, lambda x, y: int(x.replace('cpu', '')) - int(y.replace('cpu', '')))
        FTDLOG.debug('cpus: %s' % str(cpus))
        for period in resp:
            # FTDLOG.debug('period: %s', period)
            valid = re.match('\d+,\d', period)
            if not valid:
                continue
            field = period.split(',')
            ptime = int(field[headers['time']])
            if ptime < mark - 300:  # only use the periods bracketed by the stat and end times
                continue
            if ptime > end_time + 300:
                continue

            pkts_rcvd = int(field[headers['pkt_stats.pkts_recv'] - 1])
            FTDLOG.debug('pkts_rcvd %s, index %d' % (pkts_rcvd, headers['pkt_stats.pkts_recv'] - 1))

            if pkts_rcvd == '0' and include_idle_periods == False:  # filter out the periods with no traffic
                continue

            periods[ptime] = {}

            for cpustr in cpus:
                cpu = int(cpustr.replace('cpu', ''))
                periods[ptime]['cpu%d' % cpu] = {'usr': field[headers['usr[%d]' % cpu] - 1],
                                                 'sys': field[headers['sys[%d]' % cpu] - 1]}
        return (periods)

    #############################################################################################

    @keyword()
    def Get_FTD_Memory_Usage(self, limit='100.0'):
        raw = self.get_memory_data(limit=limit)
        return (raw)

    @keyword()
    def Get_FTD_Time(self, **opts):
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        datestr = self.fetch_ftd_time()
        FTDLOG.info('retrieved timedate: %s from device' % datestr)
        dre = re.match('.*(\w{3})\s+(\d+)\s+(\d{2})\:(\d{2})\:(\d{2})\s+\w+\s+(\d{4}).*', datestr.strip('\n')).groups()
        tu = map(lambda s: int(s) if s not in months else int(months.index(s)) + 1, dre)
        epoch = mktime((tu[5], tu[0], tu[1], tu[2], tu[3], tu[4], 0, 0, 0))
        if 'return_epoch' in opts:
            return (epoch)
        if 'return_elapsed' in opts:
            return (datestr.rstrip('\n'), epoch, epoch - float(opts['return_elapsed']))
        return (datestr.rstrip('\n'), epoch)

    @keyword()
    def Get_FTD_Model(self):
        resp = self.ftd_command('show model')
        return (resp.rstrip())

    def Get_FTD_Info(self):
        resp = self.ftd_command('show version')
        return (resp)

    def Get_SRU_Version(self, **opts):
        info = self.Get_FTD_Info()
        if 'return_raw' in opts:
            return (info)

        sru_version = re.findall('(Rules update version\s+:\s)(\S+)', info, re.MULTILINE)[0][1]
        vdb_version = re.findall('(VDB version\s+:\s)(\S+)', info, re.MULTILINE)[0][1]
        return ('%s (VDB %s)' % (sru_version, vdb_version))

    @keyword()
    def Publish_Performance_Results(self, results_file='firepower_performance_samples.csv', **opts):
	from atf_results import VRT_Results
        R = VRT_Results('Ruleset_Performance')
        return (R.processPerformanceSamples(results_file))

        
#######################################################################################################################################################################################

class FMC(FTD):
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.session = requests.Session()
        self.session.trust_env = False

        self.headers = {'Content-Type': 'application/json'}
        self.platform_uri = 'https://%s/api/fmc_platform/v1' % self.fmc_IP
        self.config_uri = 'https://%s/api/fmc_config/v1' % self.fmc_IP
        self.refresh_count = MAX_REFRESH_COUNT + 1  # to force a new token request upon creating the instance
        self.refresh_timer = 0.0
        self.json = JSONDecoder()
        self.policies = {'intrusion': {}, 'access': {}}
        self.policyTypes = ['access', 'file', 'intrusion']
        self.devices = {}
        self.ftd = None
        self.policy_names = {'balanced': 'atf_perf_bal', 'security': 'atf_perf_sec', 'connectivity': 'atf_perf_con'}
        self.deploy_cmd = lambda p, n, f: 'bin/oink.sh --policy ari-%s --access %s --deploy --file tmp/%s' % (p, n, f)
        self.deploy_policy = lambda p: 'bin/oink.sh --access %s --deploy --debug' % p
        self.upload_files = {}
        self.expect_buf = []
        self.interface_stats = {}
        FTDLOG.debug('created FMC instance for host @ %s' % self.fmc_IP)

    def capture_expect_output(self, xstr):
        self.expect_buf += xstr
        full = re.findall('^#+$', xstr)
        if len(full) > 3:
            raise AssertionError, 'TRAP'

    @fmc_sudo()
    def purge_ctu_rulesets(self, dialog, **opts):
        self.dialog = dialog
        cmd = 'sudo -S /var/sf/bin/delete_rules.pl --prune -n local'
        dialog.send(cmd)
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect('', timeout=10, output_callback=lambda s: self.capture_expect_output(s), default_match_prefix='')

        dialg.send('\n')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean

        return (raw)

    @fmc_sudo()
    def fmc_oink(self, dialog, **opts):
        assert 'command' in opts, 'ERROR: nothing oinkable'
        self.dialog = dialog
        dialog.send('sudo su -p')
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect(PROMPT)
        dialog.send('cd /var/sf/bin/oink-0.11')
        dialog.expect(PROMPT)
        print
        'SENT:\nbin/oink.sh %s\n' % opts['command']
        dialog.send('bin/oink.sh %s\n' % opts['command'])
        dialog.expect(PROMPT)

        raw = dialog.current_output_clean
        return (raw)



    @fmc_sudo()
    def fmc_fat(self, dialog, **opts):
        FTDLOG.debug('Invoking FMC FAT utility: %s' % ''.join('%s - %s,' % (s, opts[s]) for s in opts))
        assert 'command' in opts, 'ERROR: nothing to do'
        self.dialog = dialog
        dialog.send('sudo su -p')
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect(PROMPT)
        dialog.send(opts['command'])
        dialog.expect(PROMPT)
        FTDLOG.debug('cd /var/sf/bin/fat\n')
        dialog.send('cd /var/sf/bin/fat\n')
        dialog.expect(PROMPT)
        FTDLOG.debug('/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.send('/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.expect(PROMPT)

        raw = dialog.current_output_clean
        FTDLOG.debug('Response: %s' % raw)
        return (raw)

    @fmcCall()
    def fmcGET(self, url, data=None, **opts):
        if 'parameters' in opts:
            parameters = opts['parameters']
        else:
            parameters = {}
        FTDLOG.info('sent GET request to FMC: %s' % url)
        raw = self.session.get(url, headers=self.headers, verify=False, params=parameters)
        return (raw)

    @fmcCall()
    def fmcPUT(self, url, put_data=None, **opts):
        self.request_body = put_data
        FTDLOG.info('sent PUT request to FMC: %s with headers:\n%s, data:\n%s' % (url, self.headers, dumps(put_data)))
        raw = self.session.put(url, data=dumps(put_data), headers=self.headers, verify=False)
        return (raw)

    @fmcCall()
    def fmcPOST(self, url, post_data=None, **opts):
        self.request_body = post_data
        FTDLOG.info('sent POST request to FMC: %s\nPOST data:\n%s' % (url, dumps(post_data)))
        with open('ftdpost.txt', 'w') as f:
            f.write(dumps(post_data))

        raw = self.session.post(url, headers=self.headers, data=dumps(post_data), verify=False)
        return (raw)

    @keyword()
    def Get_Interface_Device(self, deviceName=None, **opts):
        if len(self.devices) == 0:
            rval = self.Get_Device_Records()
        if deviceName != None:
            assert deviceName in self.device, 'ERROR: specified device is not managed by the FMC'
        rval = ''
        for device_name in self.devices:
            device = self.devices[device_name]
            if deviceName != None and device.Name.find(deviceName) < 0:
                continue
            rval += '\nDevice: %s (%s)\n' % (device.Name, device.Hostname)
            FTDLOG.debug('fetching info on device: %s' % device_name)
            intstats = self.fmcGET('devices/devicerecords/%s/etherchannelinterfaces' % device.Id)
            intstats = self.fmcGET('object/urls')

        return (rval)

    @keyword()
    def Get_Policy_Assignments(self, **opts):
        assignments = self.fmcGET('assignment/policyassignments', parameters={'expanded': 'True'})
        if len(self.policies['access']) < 2:
            self.Get_Access_Policies()
        # if len(self.policies['intrusion']) < 2:
        # self.Get_Intrusion_Policies()

        rval = 'No policy found for FTD device @ %s' % self.ftd_IP
        if len(self.devices) == 0:
            self.Get_Device_Records()
        for item in assignments['items']:
            policy = Policy(self.fmcGET('policy/accesspolicies/%s' % item['id']))
            details = self.fmcGET('assignment/policyassignments/%s' % policy.Id)
            policy.json = details
            self.policies['access'][policy.Name] = policy
            for device in details['targets']:
                if device['name'] in self.devices:
                    self.devices[device['name']].__dict__['Policy'] = policy
                if device['name'] == self.ftd.Name:
                    self.ftd.Policy = policy
                    rval = policy.Name
        return (str(rval))

    @keyword()
    def Set_Policy_Assignment(self, new_policy_name=None, policy_type='access'):

        J = JSONEncoder()
        assert new_policy_name != None, 'ERROR: the policy name to which the FTD is to be assigned was not specified'
        if len(self.policies[policy_type]) < 2:
            self.Get_Policies(policy_type)
        assert new_policy_name in self.policies[
            policy_type], 'ERROR: the specified policy name "%s" is invalid' % policy_type
        old_policy_assignment = self.ftd.Policy.json
        try:
            targets = old_policy_assignment['targets'].pop(0)
        except:
            raise AssertionError, 'ERROR: no target in %s' % old_policy_assignment
        new_policy = self.policies[policy_type][new_policy_name]
        fwpolicy = self.fmcGET('policy/intrusionpolicies/%s' % new_policy.Id)
        new_policy.json = {
            'type': 'PolicyAssignment',
            'id': new_policy.Id,
            'name': new_policy.Name,
            'policy': {
                'type': new_policy.Type,
                'name': new_policy.Name,
                'id': new_policy.Id,
            },
            'targets': [
                {
                    'id': self.ftd.Id,
                    'type': self.ftd.Type,
                    'name': self.ftd.Name
                }
            ]
        }
        send_json = J.encode(new_policy.json)
        FTDLOG.debug('sending policy assignment request:\n%s' % send_json)
        resp = self.fmcPOST('assignment/policyassignments', new_policy.json)
        assert 'ERROR' not in resp, '%s\n\n%s' % (new_policy.json, resp)

        return (resp)

    @keyword()
    def Deploy_Policy_To_FTD(self, wait='1200.0'):
        sleep(120)
        return ('This keyword is deprecated with implementation of FAT utility')
        version = ''
        try:
            waittime = int(wait)
        except:
            FTDLOG.error('Invalid wait time specified')
            waittime = 300.0
        if not self.ftd:
            self.Get_Device_Records()
        deployable = self.fmcGET('deployment/deployabledevices', parameters={'expanded': 'True'})
        self.deployable = deployable
        is_deployable = False
        policy_to_deploy = self.Get_Policy_Assignments()
        if 'item' in deployable:

            for item in deployable['items']:
                if item['device']['name'] != self.ftd.Name:
                    continue
                if item['canBeDeployed'] != True:
                    break
                is_deployable = True
                version = item['version']
        if is_deployable == False:
            FTDLOG.info('Firepower device "%s" is not in a state to deploy policy "%s"...deploying anyway' % (
                self.ftd.Name, policy_to_deploy))
        post_data = {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": [self.ftd.Id]
        }
        resp = self.fmcPOST('deployment/deploymentrequests', post_data)
        timed_out = True
        job_status = ''
        if 'metadata' in resp and 'task' in resp['metadata'] and 'id' in resp['metadata']['task']:
            taskID = resp['metadata']['task']['id']
            timer = time() + waittime
            FTDLOG.info('Deployment started, Task ID = %s. Waiting %d seconds to complete' % (taskID, int(waittime)))
            while time() < timer:
                job_status = self.Get_Job_Status(taskID)
                FTDLOG.debug('job status: %s' % job_status['message'].replace(self.ftd.Id, self.ftd.Model))
                if job_status['message'].find('Deploying') >= 0 or job_status['message'].find(
                        'PARTIALLY_SUCCEEDED') >= 0:
                    FTDLOG.debug(job_status['message'].replace(self.ftd.Id, self.ftd.Model))
                    sleep(5)
                    continue
                if job_status['message'].find('SSP_SUCCEEDED') >= 0:
                    FTDLOG.debug(job_status['message'].replace(self.ftd.Id, self.ftd.Model))
                    sleep(5)
                    continue

                if job_status['message'].find('FAILED') >= 0:
                    return ('ERROR: %s' % job_status['message'].replace(self.ftd.Id, self.ftd.Model))
                timed_out = False
                break
            if timed_out == True:
                return ('ERROR: timed out after %d seconds waiting for policy to deploy' % int(timer))
            return (job_status['message'].replace(self.ftd.Id, self.ftd.Model))

        return (resp)

    @keyword()
    def Get_Device_Records(self, device_name=None, **opts):
        if device_name == None:
            device_name = self.ftd_IP
        FTDLOG.debug('fetching device records')
        raw = self.fmcGET('devices/devicerecords')
        count = raw['paging']['count']
        if 'return_raw' in opts and opts['return_raw'] == True:
            return (count, raw)
        rval = '\n%d devices found' % count
        for item in raw['items']:
            draw = self.fmcGET(item['links']['self'], link=True)
            device = Device(draw)
            self.devices[item['name']] = device
            if device_name == item['name'] or device_name == device.Hostname:
                self.ftd = device
                device = Device(draw)
                if 'return_model' in opts:
                    return (device.Model)
                if 'return_health' in opts:
                    return (device.Healthstatus)
                rval = '\nName: %s\nHostname: %s\nModel: %s (%s-%s)\nID:%s\nHealth: %s\n' % (
                    device.Name,
                    device.Hostname,
                    device.Model, device.Modeltype, device.Modelnumber,
                    device.Id,
                    device.Healthstatus,
                )
            else:
                rval += '\nName:\t%s\n\tType: %s\n\tLinks: %s\n' % (item['name'], item['type'], item['links'])
        return (rval)

    @keyword()
    def Get_Job_Status(self, jobid=None, **opts):
        FTDLOG.debug('fetching job status for job %s' % jobid)

        raw = self.fmcGET('job/taskstatuses/%s' % jobid)
        return (raw)

    @keyword()
    def Get_System_Info(self):
        sysinfo = self.fmcGET('info/serverversion', platform=True)
        rval = ''
        for info in sysinfo['items']:
            for item in info:
                if 'sru' in item.lower():
                    rval += '%s:%s\n' % (item, info[item])
                else:
                    rval += '%s:%s\n' % (item.capitalize(), info[item])
        return (rval)

    @keyword()
    def Get_Policies(self, policy_type=None):
        get_policies = lambda p: self.Get_Access_Policies() if p == 'access' else self.Get_Intrusion_Policies()
        assert policy_type != None and policy_type in self.policies, 'ERROR: required policy type is missing or invalid'
        return (get_policies(policy_type))

    @keyword()
    def Get_Access_Policies(self):

        policies = self.fmcGET('policy/accesspolicies')
        for item in policies['items']:
            meta = self.fmcGET('policy/accesspolicies/%s' % item['id'])
            self.policies['access'][item['name']] = Policy(meta)
        return (self.policies['access'])

    @keyword()
    def Get_Intrusion_Policies(self):
        fmc_pmap = {
            'balanced': 'Balanced Security and Connectivity',
            'security': 'Security Over Connectivity',
            'connectivity': 'Connectivity Over Security',
            'atf_perf_bal': 'atf_perf_bal'
        }
        policies = self.fmcGET('policy/intrusionpolicies')
        for item in policies['items']:
            meta = self.fmcGET('policy/intrusionpolicies/%s' % item['id'])
            self.policies['intrusion'][item['name']] = Policy(meta)
        return (self.policies['intrusion'])

    """
    def Get_Policy_Assignment( self, policyName=None, **opts):
        policy_name = ''
        fetched = self.Get_Policy_Assignments(policyName)
        print fetched
        pdata = 'nada'
        #assert 'No policy' not in fetched, 'No policy assignments found containing "%s"' % policyName
        for policy_name in self.policies:
            policy = self.policies[policy_name]
            if policyName != None and  policyName not in policy.Name:
                continue
            for ptype in policyTypes:
                pdata = self.fmcGET('policy/%spolicies/%s/%srules' % (ptype, policy.Id, ptype))
                #pdata = self.fmcGET('policy/%spolicies/%s/%srules' % (ptype, device_id, ptype))
                #pdata = self.fmcGET('policy/%spolicies/%s' % (ptype, policy.Id))
                if 'error' in pdata:
                    continue
        return(pdata)
    """


    @keyword()
    def Upload_File_To_FMC(self, source=None, destination=None):
        assert source != None, 'source file was not specified'
        if destination == None:
            clean_filename = re.findall('.*(vrt_release_.*\.txt)', source)
            destination = 'tmp/%s' % clean_filename[0]
        C = Connect(self.fmc_IP)
        FTDLOG.info('copying %s on ATF to %s on FMC' % (source, destination))
        resp = C.pushfile(source, destination)
        if 'ERROR' in resp:
            return (resp)
        nfe = non_fatal_error(resp)
        return (destination, resp if not nfe else nfe)

    @keyword()
    def Install_SRU_Rulesets(self, sru_ruleset_shell_script):
        FTDLOG.debug('running SRU ruleset installation script "%s"' % sru_ruleset_shell_script)
        C = Connect(self.fmc_IP)
        resp = C.sudo('bash %s' % sru_ruleset_shell_script)
        nfe = non_fatal_error(resp)
        return (resp if not nfe else nfe)

    @keyword()
    def Install_CTU_Ruleset(self, ctu_ruleset_file=None, policy_type='ari-balanced', access_policy=None):
        assert ctu_ruleset_file != None, 'ERROR: the CTU ruleset file name was not specified'
        FTDLOG.debug('installing CTU ruleset: policy=%s, access=%s, ctu_ruleset_file=%s' % (
            policy_type, access_policy, ctu_ruleset_file))
        try:
            ctu_ruleset = re.findall('.*(vrt_release_.*\.txt)', ctu_ruleset_file)[0]
        except Exception as estr:
            raise AssertionError, 'ERROR: invalid ruleset filename "%s" :\n%s' % (ctu_ruleset_file, str(estr))
        C = Connect(self.fmc_IP)
        check_ruleset_location = C.sudo('ls tmp/%s' % ctu_ruleset.strip())
        assert 'No such file or directory' not in check_ruleset_location, 'ERROR: CTU ruleset %s has not been uploaded to the FMC' % ctu_ruleset
        cmd = 'cp /var/tmp/%s /var/sf/bin/fat/rulesin.txt\n' % (ctu_ruleset.strip())
        resp = self.fmc_fat(command=cmd)
        successes = re.findall('(SUCCESS)', resp, re.MULTILINE)
        assert len(successes) == 2, 'ERROR: installation of CTU rulesets failed to complete: %s' % resp
        FTDLOG.debug('CTU ruleset installation Complete:\n%s' % resp)
        return (resp)

    @keyword()
    def OLD_Install_CTU_Ruleset(self, ctu_ruleset_file=None, policy_type='ari-balanced', access_policy=None):
        assert ctu_ruleset_file != None, 'ERROR: the CTU ruleset file name was not specified'
        assert access_policy != None, 'ERROR: the access policy name was not specified'
        FTDLOG.debug('installing CTU ruleset: policy=%s, access=%s, ctu_ruleset_file=%s' % (
            policy_type, access_policy, ctu_ruleset_file))
        try:
            ctu_ruleset = re.findall('.*(vrt_release_.*\.txt)', ctu_ruleset_file)[0]
        except Exception as estr:
            raise AssertionError, 'ERROR: invalid ruleset filename "%s" :\n%s' % (ctu_ruleset_file, str(estr))
        C = Connect(self.fmc_IP)
        check_ruleset_location = C.sudo('ls ~/tmp/%s' % ctu_ruleset.strip())
        assert 'No such file or directory' not in check_ruleset_location, 'ERROR: CTU ruleset %s has not been uploaded to the FMC' % ctu_ruleset
        cmd = '--policy %s --access %s --deploy --file /var/tmp/%s' % (policy_type, access_policy, ctu_ruleset.strip())
        resp = self.fmc_oink(command=cmd)
        assert 'Completed ARI Tool Run' in resp, 'ERROR: installation of CTU rulesets failed to complete'
        FTDLOG.debug('CTU ruleset installation Complete:\n%s' % resp)
        nfe = non_fatal_error(resp)
        if 'ARI failed' in resp:
            resp = 'ERROR: %s' % resp
        if nfe != None:
            resp = 'WARNING: %s' % resp

        return (resp)

    @keyword()
    def Download_CTU_Ruleset(self, version):
        FTDLOG.debug('attempting to download CTU ruleset version %s' % version)
        V = VulnDB()
        vrt_ruleset, tmp_vrt_rulset = V.fetch_vrt_ruleset(version)
        if vrt_ruleset == None:
            return ('ERROR: downloading CTU rulesets:\n%s' % V.error)
        FTDLOG.info('downloaded CTU Rulesets %s and stored in temporary file %s' % (vrt_ruleset, tmp_vrt_rulset))
        return (tmp_vrt_rulset)

    @keyword()
    def Get_Released_CTU_Ruleset_Version(self):
        V = VulnDB()
        rs_version = V.fetch_vrt_ruleset()
        return (rs_version)

    @keyword()
    def Download_CTU_Ruleset_Diffs(self, first=None, second=None):
        assert first != None, 'ERROR: at least one version must be supplied'
        if second == None or int(second) <= int(first):
            second = str(int(first, 10))
            first = str(int(first, 10) - 1)
        vlndb = VulnDB(self.TestEnv, self.ATF_User)
        diffs = vlndb.fetch_ctu_ruleset_diffs(first, second)
        return ('Ruleset differences between %s and %s\n%s' % (first, second, diffs))


#######################################################################################################################################################################################

class igniteCall(object):
    def __call__(self, pFunction):
        def ignite_api_call(self, obj_URL, headers, data=None, **opts):
            FTDLOG.debug('requesting session token from FMC')
            # request a new token
            token_headers = {'accept': 'application/json', 'password': self.ignite_Password, 'username': self.ignite_User}
            token_url = '%s/ignite/token' % self.platform_uri
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            resp = self.session.post(token_url, headers=token_headers, verify=False)
            FTDLOG.debug('resp=: %s\n%s\n' % (str(resp.headers), resp.text))
            if resp.status_code != 200:
                FTDLOG.error('failed to retrieve session token from Ignite @ %s: %d\n%s' % (
                      self.ignite_IP, resp.status_code, resp.text))
                raise AssertionError, 'failed to retrieve session token from Ignite @ %s: %d\n%s' % (
                      self.ignite_IP, resp.status_code, resp.text)
            self.__dict__.update({'%s' % S.lower() : resp.headers[S] for S in resp.headers.keys()} )
            if 'ERROR' in resp:
                FTDLOG.error('ERROR refreshing access token: %s' % resp)
                return (resp)
            self.token = resp.content
            FTDLOG.debug('Successfully retrieve session token from Cisco Ignite')
            url = self.platform_uri + obj_URL
            token = {'token': '%s' % self.token}
            headers.update(token)
            resp = pFunction(self, url, headers, data, **opts)
#            try:
#                response = self.json.decode(resp.text)
#                self.response = deepcopy(response)
#            except Exception as estr:
#                return ('ERROR return from API:\n%s\%s' % (str(estr), resp.text))
            response = resp
            FTDLOG.debug('received response:\n%s' % response)
            return (response)

        return (ignite_api_call)

#######################################################################################################################################################################################

class Ignite():
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.session = requests.Session()
        self.session.trust_env = False
        self.headers = {}
        self.platform_uri = 'https://%s:8443/api' % self.ignite_IP
        self.refresh_count = MAX_REFRESH_COUNT + 1  # to force a new token request upon creating the instance
        self.refresh_timer = 0.0
        self.json = JSONDecoder()
        self.policies = {'intrusion': {}, 'access': {}}
        self.policyTypes = ['access', 'file', 'intrusion']
        self.devices = {}
        self.token = None
        self.ftd = None
        self.policy_names = {'balanced': 'atf_perf_bal', 'security': 'atf_perf_sec', 'connectivity': 'atf_perf_con'}
        self.deploy_cmd = lambda p, n, f: 'bin/oink.sh --policy ari-%s --access %s --deploy --file tmp/%s' % (p, n, f)
        self.deploy_policy = lambda p: 'bin/oink.sh --access %s --deploy --debug' % p
        self.upload_files = {}
        self.expect_buf = []
        self.interface_stats = {}
        FTDLOG.debug('created Ignite instance for host @ %s' % self.ignite_IP)

    @keyword()
    def Upload_File_To_Ignite(self, source=None, destination=None):
        assert source != None, 'source file was not specified'
        if destination == None:
            clean_filename = re.findall('.*(vrt_release_.*\.txt)', source)
            destination = '/tmp/%s' % clean_filename[0]
        C = Connect(self.ignite_IP)
        FTDLOG.info('copying %s on ATF to %s on Ignite' % (source, destination))
        resp = C.pushfile(source, destination)
        if 'ERROR' in resp:
            return (resp)
        nfe = non_fatal_error(resp)
        return (destination, resp if not nfe else nfe)
    
    @ignite_sudo()
    def fmc_ignite(self, dialog, **opts):
        FTDLOG.debug('Invoking Cisco Ignite automation tool: %s' % ''.join('%s - %s,' % (s, opts[s]) for s in opts))
        assert 'command' in opts, 'ERROR: nothing to do'
        self.dialog = dialog
        dialog.send('sudo su -p')
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect(PROMPT)
        dialog.send(opts['command'])
        dialog.expect(PROMPT)
        FTDLOG.debug('cd /var/sf/bin/fat\n')
        dialog.send('cd /var/sf/bin/fat\n')
        dialog.expect(PROMPT)
        FTDLOG.debug('/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.send('/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.expect(PROMPT)

        raw = dialog.current_output_clean
        FTDLOG.debug('Response: %s' % raw)
        return (raw)    

    @igniteCall()
    def igniteGET(self, url, headers=None, get_data=None, **opts):
        if 'parameters' in opts:
            parameters = opts['parameters']
        else:
            parameters = {}
        FTDLOG.info('sent GET request to Ignite: %s' % url)
        raw = self.session.get(url, headers=headers, data=get_data, verify=False, params=parameters)
        return (raw)

    @igniteCall()
    def ignitePUT(self, url, headers=None, put_data=None, **opts):
        self.request_body = put_data
        FTDLOG.info('sent PUT request to Ignite: %s with headers:\n%s, data:\n%s' % (url, self.headers, dumps(put_data)))
        raw = self.session.put(url, data=put_data, headers=headers, verify=False)
        return (raw)

    @igniteCall()
    def ignitePOST(self, url, headers=None, post_data=None, **opts):
        self.request_body = post_data
        FTDLOG.info('sent POST request to Ignite: %s\nPOST data:\n%s' % (url, dumps(post_data)))
        with open('ftdpost.txt', 'w') as f:
            f.write(dumps(post_data))
        raw = self.session.post(url, headers=headers, data=post_data, verify=False)
        return (raw)


    @keyword()
    def Import_CTU_Ruleset_On_Ignite(self, ctu_ruleset_file=None, policy_type='ari-balanced', parent_policy='ATFlab_Performance_with_CTU_bal'):
        assert ctu_ruleset_file != None, 'ERROR: the CTU ruleset file name was not specified'
        FTDLOG.debug('installing CTU ruleset to FMC %s: policy=%s, ctu_ruleset_file=%s' % (
            self.fmc_IP, policy_type, ctu_ruleset_file))
        url = '/snort/import'
        headers = {
            'autosid':  'true',
            'autorev':  'false',
            'delete':   'true',
            'layer':    'ARI Layer',
            'maximum':  '2000000',
            'minimum':  '1000000',
            'policy':   policy_type,
            'hostname': self.fmc_IP,
            'password': self.fmc_Password,
            'parents': parent_policy,
            'username': self.ignite_User,
            'Content-Type': 'application/octet-stream',   
        }
        data = open(ctu_ruleset_file, 'rb').read()
        resp = self.ignitePOST(url, headers=headers, data=data)
        if "ERROR" in resp:
            return (resp)
        FTDLOG.debug('CTU ruleset import successfully completed:\n%s' % resp)
        return (resp)
    
    
    @keyword()
    def Deploy_Policy_To_FTD_Device(self):
        url = '/policy/deploy'
        headers = {
            'accept': 'application/json',
            'devices': self.ftd_Device,
            'blocking': 'false',
            'hostname': self.fmc_IP,
            'password': self.fmc_Password,
            'policies': self.fmc_Access_control_policy,
            'username': self.fmc_User,
        }
        resp = self.igniteGET(url, headers)
        if "ERROR" in resp:
            return (resp)
        FTDLOG.debug('CTU ruleset installation successfully completed on device %s:\n%s' % (self.fmc_IP, resp))
        return (resp)



#######################################################################################################################################################################################

class Policy:
    def __init__(self, policy):
        for item in policy:
            self.__dict__[item.capitalize()] = policy[item]
        self.__dict__['json'] = policy

#######################################################################################################################################################################################

class Device:
    def __init__(self, data):
        for item in data:
            self.__dict__[item.capitalize()] = data[item]
        self.__dict__['Policy'] = None

#######################################################################################################################################################################################

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

            FTDLOG.debug('creating transport session for %s' % self.ip)
            T = Transport((self.ip, 22))
            FTDLOG.debug('starting transport client for %s' % self.ip)
            T.start_client()
            key = T.get_remote_server_key()
        except Exception as estr:
            FTDLOG.error('unable to insert isert host key for %s\n%s' % (self.ip, str(estr)))
            raise AssertionError, 'Trap %s' % estr

        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if keypath == None:
                FTDLOG.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword, look_for_keys=False, allow_agent=False)
                FTDLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                FTDLOG.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    FTDLOG.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except Exception as estr:
                    print
                    str(estr)
                    FTDLOG.debug(
                        'failed authentication with shared key (%s)...attempting connection to %s using password' % (
                            str(estr), self.ip))
                    try:
                        self.cnx.connect(self.ip, username=user, password=pword)
                        FTDLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                        self.connection_established = True
                    except Exception as estr:
                        print(estr)
                        FTDLOG.error('Connection via password failed: %s' % str(estr))
        except Exception as error:
            print
            str(error)
            self.error = "Connection failure to device at %s, user:%s\n%s" % (
                self.ip, user, str(error))
            FTDLOG.error(self.error)
            self.connection_established = False
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
        self.user = user
        self.device = device
        self.BUF_SIZE = 65535
        self.rxc = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def cmd(self, command, **kwords):
        if self.connection_established == False:
            FTDLOG.error('Connection error...cannot execute remote command')
            return ('Connection Error')

        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            FTDLOG.debug("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)
        except Exception as estr:
            FTDLOG.debug('Error connecting to FMS: "%s"' % str(estr))
            self.error = ''
            self.reconnect()
            if self.error != '':
                FTDLOG.error('Error connecting to FMS: %s' % self.error)
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)

        response = stdout.read()
        if response == '':
            response = stderr.read()
        FTDLOG.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            FTDLOG.debug('reconnecting to host %s' % self.ip)
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            FTDLOG.error(self.error)
            raise AssertionError, self.error
        FTDLOG.debug('re-connection successful')

    def sudo(self, command, **flags):
        if self.connection_established == False:
            FTDLOG.error('Connection error...cannot execute remote sudo')
            return ('Connection Error')
        flist = ''
        if len(flags) > 0:
            for f in flags.keys():
                flist += " \-%s %s" % (f, flags[f])

        response = ''
        error = ''
        FTDLOG.info('Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
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
            FTDLOG.error('ERROR in response to sudo command: %s' % "sudo -S %s 2>&1" % command)
        FTDLOG.info("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response.replace('Password: ', ''))

    def pushfile(self, source, destination):
        import scpclient as SCP
        from hashlib import md5

        if self.connection_established == False:
            FTDLOG.error('Connection error...cannot upload file')
            return ('Connection Error')
        try:
            destination_path = os.path.basename(destination)
            FTDLOG.info('uploading file %s from ATF to %s:%s' % (source, self.ip, destination))
            W = SCP.Write(self.transport, os.path.dirname(destination))
            W.send_file(source, destination_path)
            SCP.closing(W)
            FTDLOG.debug('Connecting to Ignite with IP %s' % (self.ip))
            C = Connect(self.ip)
            FTDLOG.debug('moving %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            resp = C.sudo('mv %s/%s %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            FTDLOG.debug('moved %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            FTDLOG.debug('comparing MD5 sums between source and destination files after upload')
            md5sum = C.cmd('md5sum %s' % destination).split(' ')[0]
            C.cnx.close()
            with open(source, 'r') as sfile:
                smd5sum = md5(sfile.read())
            assert md5sum == smd5sum.hexdigest(), 'MD5 sums do not match between source and destination files'
            return ('Success: MD5 sums of the source and destination files match: % s\n' % md5sum)
        except Exception as estr:
            FTDLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return ('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))

    def pullfile(self, destination, source):
        import scpclient as SCP
        from hashlib import md5
        import traceback

        if self.connection_established == False:
            FTDLOG.error('Connection error...cannot upload file')
            return ('Connection Error')

        try:
            source_path = os.path.basename(source)
            print
            'source="%s"' % source
            print
            'destination="%s"' % destination
            FTDLOG.info('downloading file %s from %s:%s to ATF' % (source, self.ip, source))
            R = SCP.Read(self.transport, os.path.dirname(source))
            resp = R.receive_file(destination, True, None, source_path)
        except Exception as estr:
            tb = traceback.extract_stack()
            pprint(tb)
            FTDLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return ('ERROR - failed to copy %s from %s (%s)' % (source, destination, str(estr)))

        return (resp)
