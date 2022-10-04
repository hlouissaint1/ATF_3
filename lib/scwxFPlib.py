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

SAMPLES_PER_PAGE = 20
PAGE_LIST_SIZE = 11

PROMPT = '.*[#\$\>\:] '
SESSION_TIMEOUT = 1800
MAX_REFRESH_COUNT = 3

FP_LOGPATH = '/var/www/cgi-bin/lib/logs'
DOCROOT = '/var/www/html/htdocs'
MODULE = 'scwxFPlib.py'
FP_LOG = 'fp.log'

logging.basicConfig(
    format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    filename='%s/%s' % (FP_LOGPATH, FP_LOG),
    filemode='w',
    level=logging.DEBUG)

FPLOG = logging.getLogger('fp_regression')
rhandler = logging.FileHandler('%s/%s' % (FP_LOGPATH, FP_LOG))
formatter = logging.Formatter('%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s')
rhandler.setFormatter(formatter)
FPLOG.addHandler(rhandler)
FPLOG.setLevel(logging.DEBUG)
FPLOG.debug('Initialized logging')


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


class fmcCall(object):
    def __call__(self, pFunction):

        def fmc_api_call(self, object_URL, data=None, obj_uuid=None, **opts):
            if time() - self.refresh_timer >= SESSION_TIMEOUT:
                FPLOG.debug('requesting session token from FMC')
                if self.refresh_count >= MAX_REFRESH_COUNT:  # request a new token
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    url = '%s/auth/generatetoken' % self.platform_uri
                    resp = self.session.post(url, auth=(self.fmc_User.upper(), self.fmc_Password), verify=False)
                    if resp.status_code != 204:
                        FPLOG.error('failed to retrieve session token from FMC @ %s: %d\n%s' % (
                            self.fmc_IP, resp.status_code, resp.text))
                        raise AssertionError, 'failed to retrieve session token from FMC @ %s: %d\n%s' % (
                            self.fmc_IP, resp.status_code, resp.text)
                    self.__dict__.update({'%s' % S.lower(): resp.headers[S] for S in resp.headers.keys()})
                    self.headers['X-auth-access-token'] = self.__dict__['x-auth-access-token']
                    self.headers['Domain_UUID'] = self.domain_uuid
                    self.refresh_count = 0
                    self.refresh_timer = time()

                else:  # refresh the existing token
                    self.headers['X-auth-refresh-token'] = self.__dict__['x-auth-refresh-token']
                    self.headers['X-auth-access-token'] = self.__dict__['x-auth-access-token']
                    url = '%s/auth/refreshtoken' % self.platform_uri
                    resp = self.session.post(url, headers=self.headers, verify=False)
                    self.__dict__.update(resp.headers)
                    if 'ERROR' in resp:
                        FPLOG.error('ERROR refreshing access token: %s' % resp)
                        return (resp)
                    self.refresh_count += 1
                    self.headers.pop('X-auth-refresh-token')
                    self.refresh_timer = time()
            FPLOG.debug('successfully retrieve session token from FMC')
            if 'link' in opts and opts['link'] == True:
                url = object_URL
            elif 'platform' in opts and opts['platform'] == True:
                url = '%s/%s' % (self.platform_uri, object_URL)

            else:
                url = '%s/domain/%s/%s' % (self.config_uri, self.domain_uuid, object_URL)
            FPLOG.debug('data field is:\n%s', str(data))
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
            FPLOG.debug('received response:\n%s' % response)
            return (response)

        return (fmc_api_call)


def non_fatal_error(rtext):
    match = re.findall('^Non-Fatal error:.*$', rtext, re.MULTILINE)
    if len(match) > 0:
        FPLOG.debug('FMC reported a non-fatal error:\n%s' % rtext)
        eresp = ''
        for m in match:
            eresp += m
        return ('WARNING: \n %s' % eresp)
    return (None)


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
            if True:  # try:
                rval = pFunction(self, interact, **opts)
            fmc_expect.close()
            return (rval)

        return (fmc_sudo_call)


class fpExpert(object):
    def __call__(self, pFunction):
        def fp_expert_call(self, **opts):
            warnings.simplefilter('ignore')
            if not 'ftd_IP' in self.__dict__ or self.ftd_IP == None:
                return ('ERROR: the FP device address was not supplied')
            fp = paramiko.SSHClient()
            fp.load_system_host_keys()
            fp.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            fp.connect(hostname=self.ftd_IP, username=self.ftd_User, password=self.ftd_Password)
            try:
                interact = SSHClientInteraction(fp, timeout=1800, display=True)
                interact.expect(PROMPT)
                interact.send('expert\n')
                interact.expect(PROMPT)
            except Exception as estr:
                fp.close()
                return ('ERROR: unable to establish a dialog with FP @ %s:\n\t%s' % (self.ftd_IP, estr))
            try:
                rval = pFunction(self, interact, **opts)
            except Exception as estr:
                fp.close()
                return ('ERROR: the command sent to %s resulted in an exception:\nexception=%s' % (self.ftd_IP, estr))

            fp.close()
            return (rval)

        return (fp_expert_call)


class fpShell(object):
    def __call__(self, pFunction):
        def fp_shell_call(self, command=None, **opts):
            if not 'ftd_IP' in self.__dict__ or self.ftd_IP == None:
                return ('ERROR: the FP device address was not supplied')
            fp = paramiko.SSHClient()
            fp.load_system_host_keys()
            fp.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            fp.connect(hostname=self.ftd_IP, username=self.ftd_User, password=self.ftd_Password)
            try:
                interact = SSHClientInteraction(fp, timeout=30, display=False)
                interact.expect(PROMPT)
            except Exception as estr:
                return ('ERROR: unable to establish a dialog with FP @ %s:\n\t%s' % (self.ftd_IP, estr))
            if command.startswith('show '):
                interact.send('show\n')
                interact.expect(PROMPT)
                command = command.replace('show ', '')
            try:
                rval = pFunction(self, interact, command, **opts)
            except Exception as estr:
                return ('ERROR: the command sent to %s resulted in an exception:\nexception=%s' % (self.ftd_IP, estr))
            fp.close()
            return (rval)

        return (fp_shell_call)


class FirePower():
    @keyword()
    def Get_Interface_List(self, **opts):
        resp = self.fp_command('show traffic-statistics')
        ilist = re.findall('^Name.*\:\s(\S+)', resp, re.MULTILINE)
        return (ilist)

    @keyword()
    def Get_Interface_Stats(self, interfaces=None, **opts):
        if interfaces == None:
            interface_list = self.Get_Interface_List(return_as_list=True, exclude_mgmt_iface=True)
        else:
            interface_list = interfaces.split(',')
        interface_stats = {}
        rval = ''
        for interface in interface_list:
            resp = self.fp_command('show interfaces %s' % interface)
            if 'return_raw' in opts:
                return (resp)
            try:
                interface_stats[interface] = {
                    'pkts_in': re.findall('^RX Packets.*\:\s(\d+)', resp, re.MULTILINE)[0],
                    'pkts_out': re.findall('^TX Packets.*\:\s(\d+)', resp, re.MULTILINE)[0],
                    'in_pkts_dropped': re.findall('^RX Drops.*\:\s(\d+)', resp, re.MULTILINE)[0],
                    'out_pkts_dropped': re.findall('^TX Drops.*\:\s(\d+)', resp, re.MULTILINE)[0],
                }
                interface_stats[interface]['pkts_dropped'] = str(
                    int(interface_stats[interface]['in_pkts_dropped']) + int(
                        interface_stats[interface]['out_pkts_dropped']))
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
                    failed += '\n%s FAILED: "%s" exceeded allowed limit of %s' % (
                        interface, stat.replace('_', ' '), opts[limit_str])
            if failed != '':
                rval += '%s\n' % failed
        self.interface_stats.update(interface_stats)
        if 'return_as_dict' in opts and opts['return_as_dict'] == True:
            return (interface_stats)
        return (rval)

    @keyword()
    def Get_Traffic(self, interfaces=None, **opts):
        resp = self.fp_command('show traffic-statistics')
        if 'return_raw' in opts:
            return (resp)
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FP device at %s' % self.ftd_IP)
        rval = ''
        if interfaces == None:
            ilist = re.findall('^Name.*\:\s(\S+)', resp, re.MULTILINE)
            interface_list = ilist
        else:
            interface_list = interfaces.split(',')
        for interface in interface_list:
            resp = self.fp_command('show traffic-statistics %s' % interface)
            ilines = resp.split('\n', 13)
            # garbage = ilines.pop(13)
            rval += ''.join('%s\n' % value for value in ilines)

        return (rval)

    def Verify_No_Dropped_Packets(self):
        rval = self.get_perfmon_stats()
        counts = map(lambda x: re.findall('\d+', x), rval.split('\n'))
        recv = map(lambda s: 'PASSED' if int(s) != 0 else 'FAILED', counts[0])
        drop = map(lambda s: 'PASSED' if int(s) == 0 else 'FAILED', counts[1])

        if 'PASSED' in recv and not 'FAILED' in drop:
            rval += '\nAll packet counters PASSED\n'
        else:
            if not 'PASSED' in recv:
                rval += 'FAILED: No packets were received\n'
            if 'FAILED' in drop:
                rval += 'FAILED: packets were dropped'
        return (rval)

    @fpShell()
    def fp_command(self, dialog, command, **opts):
        assert command != None, 'Missing command'
        dialog.send(command)
        dialog.expect(PROMPT)
        data = dialog.current_output_clean.strip('\n')
        return (data)

    @fpExpert()
    def get_perfmon_stats(self, dialog, **opts):
        dialog.send('sudo su -')
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        dialog.send('/usr/local/sf/bin/de_info.pl\n')
        dialog.expect(PROMPT)
        uuids = dialog.current_output_clean.strip('\n')
        uuid = re.findall('DE UUID\s+\:\s(\S+)', uuids, re.MULTILINE)[0]
        cmd = 'cat /var/sf/detection_engines/%s*/instance-*/now | perfstats -q | pcregrep -o "^\s+Pkts (Recv|Drop).*(?<=\:)((\s+\d+){3})"' % uuid
        dialog.send(cmd)
        dialog.expect(PROMPT)
        resp = dialog.current_output_clean.strip('\n').split('\n')
        data = ''.join('%s\n' % s.strip(' ') if s.startswith('  ') else '' for s in resp)
        return (data)

    @fpExpert()
    def find_rule_on_device(self, dialog, **opts):
        # assert 'swid' in opts, 'Missing "swid" value'
        # assert 'rulesfile' in opts, 'Missing rulefile location'
        last_line = lambda s: s.split('\n')[len(s.split('\n')) - 1]
        getsid = lambda f, s: 'cat %s |pcregrep -o "(?<=sid:)(%s)"' % (f, s)
        getswid = lambda f, sw: 'cat %s |pcregrep -o "%s(?=\sVID)"' % (f, sw)
        dialog.send('sudo su -')
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        gobble = dialog.current_output_clean.strip('\n')
        dialog.send('ls /var/sf/detection_engines/*/intrusion/*/local.rules |tail -1')
        dialog.expect(PROMPT)
        rulesfile = last_line(dialog.current_output_clean.strip('\n'))
        dialog.current_output_clean = ''
        dialog.send(getsid(rulesfile, '17' + opts['swid']))
        dialog.expect(PROMPT)
        sid = dialog.current_output_clean.strip('\n')
        FPLOG.debug('SID="%s"' % sid)
        dialog.current_output_clean = ''
        dialog.send(getswid(rulesfile, opts['swid']))
        dialog.expect(PROMPT)
        swid = dialog.current_output_clean.strip('\n')
        FPLOG.debug('SWID="%s"' % swid)
        dialog.current_output_clean = ''
        print
        getswid(rulesfile, opts['swid'])
        print
        getsid(rulesfile, '17' + opts['swid'])
        found = map(lambda s: False if s == '' else True, [sid, swid])
        expected = map(lambda s: False if s == '' else True, opts['expect'])
        if found == expected:
            return (True, found)
        else:
            return (False, found)

    @fpExpert()
    def get_ctu_local_rules_from_fp(self, dialog, **opts):
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
        fd, atf_tmp_file = mkstemp(prefix='fp', suffix='.rules')
        print
        'TMP:', atf_tmp_file
        fp = Connect(self.ftd_IP)
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

    @fpExpert()
    def fetch_rs_version_on_device(self, dialog, **opts):
        dialog.send('ls /var/sf/detection_engines/*/intrusion/*/local.rules')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        if not raw.find('No such file or directory') < 0:
            err = 'ERROR: no local rules file found on FP device'
            FPLOG.error(err)
            return (err)
        cmd = 'cat `ls /var/sf/detection_engines/*/intrusion/*/local.rules |tail -1` |pcregrep -o  "(?<=ruleset-release\s)\d+" |sort |uniq |tail -1'
        timeout = 500 + time()
        while timeout > time():
            dialog.send(cmd)
            dialog.expect(PROMPT)
            raw = dialog.current_output_clean
            resp = re.findall('^\d+$', raw, re.MULTILINE)
            if len(resp) > 0:
                if 'expect_version' in opts:
                    if int(resp[0]) != int(opts['expect_version']):
                        sleep(30)
                        continue
                return resp[0]
            sleep(30)
        return ('0')

    @fpExpert()
    def get_fp_name(self, dialog, **opts):
        dialog.send('hostname\n')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        resp = raw.split('\n')[1]
        return (resp)

    @fpExpert()
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

    @fpExpert()
    def pmtool_cmd(self, dialog, **opts):
        assert 'command' in opts, 'ERROR: No command to give pmtool'
        cmd = 'sudo pmtool %s' % opts['command']
        FPLOG.debug(cmd)
        dialog.send(cmd)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw)

    @keyword()
    def Restart_Snort(self):
        FPLOG.debug('Restarting Snort')
        rsp = self.pmtool_cmd(command='restartbytype snort')
        sleep(30)
        return (rsp)

    @fpExpert()
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

    @fpExpert()
    def fetch_last_top_heading(self, dialog, **opts):
        cmd = 'sudo pcregrep "^top.*$" /var/log/top.log |tail -1'
        dialog.send(cmd)
        dialog.expect('Password\:.*')
        dialog.send('%s\n' % self.ftd_Password)
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw.strip('\n'))

    @fpExpert()
    def fetch_fp_time(self, dialog, **opts):
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

    @keyword()
    def Verify_FP_Ruleset_Diffs(self, first, second):
        if int(first) == 0:
            return ('PASSED: no ruleset on device to compare with')

        vlndb = VulnDB(self.TestEnv, self.ATF_User)
        diffs = vlndb.fetch_ctu_ruleset_diffs(first, second, return_xml=True)
        rval = ''
        # varify that the added rules are on the FP
        for added in diffs.xpath('signature[@diff="added"]'):
            swid = added.attrib['swid']
            result, found = find_rule_on_device(swid=swid, expect=[True, True])
            if result == False:
                rval += 'ERROR: added ruleset could not be found on the FP: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, added.attrib[s]) for s in added.attrib)
            else:
                rval += 'PASSED: added ruleset was found on the FP: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, added.attrib[s]) for s in added.attrib)
        for removed in diffs.xpath('signature[@diff="removed"]'):
            swid = removed.attrib['swid']
            result, found = find_rule_on_device(swid=swid, expect=[False, False])
            if result == False:
                rval += 'ERROR: removed ruleset is still on FP: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, removed.attrib[s]) for s in removed.attrib)
            else:
                rval += 'PASSED: removed ruleset was not found on FP: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, removed.attrib[s]) for s in removed.attrib)

        for changed in diffs.xpath('signature[@diff="changed"]'):
            swid = changed.attrib['swid']
            result, found = find_rule_on_device(swid=swid, expect=[True, True])
            if result == False:
                rval += 'ERROR: changed ruleset could not be found on the FP: signature - %s\n' % ''.join(
                    '%s:%s ' % (s, changed.attrib[s]) for s in changed.attrib)
            else:
                rval += 'PASSED: changed ruleset was found on the FP: signature = %s\n' % ''.join(
                    '%s:%s ' % (s, changed.attrib[s]) for s in changed.attrib)

        return (rval)

    @keyword()
    def Verify_FP_CTU_Ruleset_Version(self, version=None, waittime='500'):
        from time import sleep

        cmd = 'pcregrep -o  "(?<=ruleset-release\s)\d+" /var/sf/detection_engines/*/intrusion/*/local.rules |sort |uniq |tail -1\n'
        resp = self.fetch_rs_version_on_device()
        if 'ERROR' in resp:
            return (resp)
        if version != None:
            resp = self.fetch_rs_version_on_device(expect_version=version)
            if 'ERROR' in resp:
                return (resp)
            if int(resp) != int(version):
                rval = 'FAILED: the FP device @ %s is at version "%d" installed...not version "%d"' % (
                    self.ftd_IP, int(resp), int(version)
                )
            else:
                rval = 'PASSED: the FP device @ %s is running ruleset version "%d"' % (self.ftd_IP, int(resp))
        else:
            rval = '%d' % int(resp)

        return (rval)

    @keyword()
    def Get_FP_CTU_Ruleset_Version(self):
        return (self.Verify_FP_CTU_Ruleset_Version())

    @keyword()
    def Get_FP_CPU_Core_Utilization(self, limitstr='100.0'):
        limit = limitstr.strip('%')
        resp = self.fp_command('show cpu usage')
        if 'Connection Error' in resp:
            return ('ERROR: unable to communicate with FP device at %s' % self.ftd_IP)
        return (self.check_fp_cpu_usage(resp, limit))

    #########################################################

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
        strip_cmd = lambda r, c: r.replace(c, '')
        end_time = float(opts['end_time'])
        start_time = float(opts['start_time'])
        FPLOG.debug('start time= %s, end time= %s, columns= "%s"' % (start_time, end_time, columns))
        if 'wait_for_boundary' in opts:
            wait_for_boundary = opts['wait_for_boundary']
        else:
            wait_for_boundary = True
        if wait_for_boundary == True:
            boundary = (end_time - (end_time % 300)) + 300
            current_time = self.Get_FP_Time(return_epoch=True)
            FPLOG.debug('time boundary= %s, current_time= %s' % (boundary, current_time))
            while current_time < boundary:
                current_time = self.Get_FP_Time(return_epoch=True)
                sleep(1)
        mark = start_time - (start_time % 300)
        FPLOG.debug('time mark= %s' % mark)
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
            FPLOG.debug('sending command: %s' % cmd)
            dialog.send(cmd)
            dialog.expect(PROMPT)
            resp = dialog.current_output_clean
            FPLOG.debug('response was: %s' % resp)
        except Exception as estr:
            FPLOG.debug('erred response was: %s' % estr)
            return (estr)
        column_headers = re.findall('^#\w\S+', resp, re.MULTILINE)
        assert len(column_headers) > 0, 'unable to fetch column headers'
        headers = column_headers[0]
        extract = columns.split(',')
        cpucol = self.get_columns(headers, 'iCPUs')
        cmd = 'cat /var/sf/detection_engines/%s*/instance-*/now | grep -v "####" |cut -s -d "," -f %s |grep -v "#" |tail -1' % (
            uuid, cpucol)
        FPLOG.debug('sending command: %s' % cmd)
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
        FPLOG.debug('sending expert command to FP at %s: \n%s\n' % (self.ftd_IP, cmd))
        dialog.send(cmd)
        dialog.expect(PROMPT)
        # raw = dialog.current_output_clean
        # FPLOG.debug('raw response was\n%s\n' % raw)

        # resp = dialog.current_output_clean.split('\n')
        resp = re.findall('^\d{10,12}.*', dialog.current_output_clean, re.MULTILINE)
        FPLOG.debug('response was:\n%s...\n' % str(resp)[0:1000])

        return (resp, hdr_dict)

    @keyword()
    def Get_FP_CPU_Stats(self, start_time=None, end_time=None, usr_limitstr='30.0', sys_limitstr='10.0', **opts):
        from math import floor, ceil

        if end_time == None or end_time == 'None':
            end_time = start_time
            start_time = str(float(end_time) - 300.0)
            FPLOG.debug('no end time supplied...using start= %s, end= %s' % (start_time, end_time))
        cstats = self.get_cpu_stats(start_time=start_time, end_time=end_time, **opts)
        # FPLOG.debug('fetched CPU stats: \n%s' % str(cstats))
        usr_limit = float(usr_limitstr)
        sys_limit = float(sys_limitstr)
        header = '\n      '
        result_val = ''
        if len(cstats) == 0:
            return (
                'ERROR:No stats were return for the period specified...did you mean to set the "include_idle_periods" flag?')
        periods = sorted(cstats)

        headers = []
        cpus = []
        print_group = 0
        sub_header = ''
        rval = ''
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
                    if float(cstats[period][cpu]['usr']) > usr_limit:
                        tval = strftime('%0H:%0M:%0S', localtime(fperiod))
                        result_val += '\nPeriod %s FAILED: a usage value for "usr" on one or more CPUs exceeded the specified limit of %4.2f' % (
                            tval, usr_limit)
                    if float(cstats[period][cpu]['sys']) > sys_limit:
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

    @fpExpert()
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
        FPLOG.debug('fetching cpu stats from %s to %s (mark= %s)' % (opts['start_time'], opts['end_time'], str(mark)))
        resp, headers = self.get_stats(dialog, 'time,iCPUs,pkt_stats.pkts_recv,usr,sys', **opts)
        if resp[0].startswith('cat'):
            resp.remove(resp[0])
        rval = ''
        periods = {}
        FPLOG.debug('headers: %s' % str(headers))  # list of indices for the relevant columns
        FPLOG.debug('first line: %s' % resp[0])
        nCPUs = resp[0].split(',')[headers['iCPUs']]
        FPLOG.debug('Number of cpus= %s' % nCPUs)
        cpus = {}
        for x in range(0, int(nCPUs)):
            cpus['cpu%d' % x] = []
        cpus = sorted(cpus, lambda x, y: int(x.replace('cpu', '')) - int(y.replace('cpu', '')))
        FPLOG.debug('cpus: %s' % str(cpus))
        for period in resp:
            FPLOG.debug('period: %s', period)
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

            if pkts_rcvd == '0' and include_idle_periods == False:  # filter out the periods with no traffic
                continue

            periods[ptime] = {}
            for cpustr in cpus:
                cpu = int(cpustr.replace('cpu', ''))
                periods[ptime]['cpu%d' % cpu] = {'usr': field[headers['usr[%d]' % cpu] - 1],
                                                 'sys': field[headers['sys[%d]' % cpu] - 1]}
        return (periods)

    ################################################################

    def check_fp_cpu_usage(self, resp, limit_str):
        limit = float(limit_str)
        lines = resp.split('\n')
        discard = lines.pop(0)
        cores = re.findall('\d+', lines.pop(0))
        loads = []
        for line in lines:
            loads.extend(re.findall('\d+', line))
        result = map(lambda x: 'FAILED' if float(x) > limit else 'PASSED', loads)
        rval = resp
        if 'FAILED' in result:
            rval += "\n\nFAILED: the load in one or more of the core's periods exceeded the limit of %s%c" % (
                limit_str, 0x25)
        else:
            rval += "\n\nPASSED: all periods for all cores were within the limit of %s%c" % (limit_str, 0x25)
        return (rval)

    @keyword()
    @keyword()
    def Get_FP_Memory_Usage(self, limit='100.0'):
        raw = self.get_memory_data(limit=limit)
        return (raw)

    @keyword()
    def Get_FP_Time(self, **opts):
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        datestr = self.fetch_fp_time()
        dre = re.match('.*(\w{3})\s+(\d+)\s+(\d{2})\:(\d{2})\:(\d{2})\s+\w+\s+(\d{4}).*', datestr.strip('\n')).groups()
        tu = map(lambda s: int(s) if s not in months else int(months.index(s)) + 1, dre)
        epoch = mktime((tu[5], tu[0], tu[1], tu[2], tu[3], tu[4], 0, 0, 0))
        if 'return_epoch' in opts:
            return (epoch)
        if 'return_elapsed' in opts:
            return (datestr, epoch, epoch - float(opts['return_elapsed']))
        return (datestr, epoch)

    @keyword()
    def Get_FP_Model(self):
        resp = self.fp_command('show model')
        return (resp.rstrip())

    def Get_FP_Info(self):
        resp = self.fp_command('show version')
        return (resp)

    def Get_SRU_Version(self, **opts):
        info = self.Get_FP_Info()
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


class FMC(FirePower):
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
        self.fp = None
        self.policy_names = {'balanced': 'atf_perf_bal', 'security': 'atf_perf_sec', 'connectivity': 'atf_perf_con'}
        self.deploy_cmd = lambda p, n, f: 'bin/oink.sh --policy ari-%s --access %s --deploy --file tmp/%s' % (p, n, f)
        self.deploy_policy = lambda p: 'bin/oink.sh --access %s --deploy --debug' % p
        self.upload_files = {}
        self.expect_buf = []
        self.interface_stats = {}
        FPLOG.debug('created FMC instance for host @ %s' % self.fmc_IP)

    def capture_expect_output(self, xstr):
        self.expect_buf += xstr
        full = re.findall('^#+$', xstr)
        if len(full) > 3:
            raise AssertionError, 'TRAP'

    @fmc_sudo()
    def purge_ctu_rulesets(self, dialog, **opts):
        self.dialog = dialog
        cmd = 'echo PRUNE |/var/sf/bin/delete_rules.pl --prune -n local\n'
        dialog.send('sudo su -p')
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect(PROMPT)
        dialog.send(cmd)
        dialog.expect(PROMPT)
        FPLOG.debug('SENT: %s' % cmd)
        raw = dialog.current_output_clean
        FPLOG.debug('RESPONSE:\n%s\n' % raw)
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
        FPLOG.debug('SENT:\nbin/oink.sh %s\n' % opts['command'])
        dialog.send('bin/oink.sh %s\n' % opts['command'])
        dialog.expect(PROMPT)

        raw = dialog.current_output_clean
        FPLOG.debug('RESPONSE:\n%s\n' % raw)
        return (raw)

    @fmc_sudo()
    def fmc_fat(self, dialog, **opts):
        assert 'command' in opts, 'ERROR: nothing to do'
        self.dialog = dialog
        dialog.send('sudo su -p')
        dialog.expect('Password:\s+')
        dialog.send('%s' % self.fmc_Password)
        dialog.expect(PROMPT)
        FPLOG.debug('Send sudo command: %s' % opts['command'])
        dialog.send(opts['command'])
        dialog.expect(PROMPT)
        FPLOG.debug('received: %s' % dialog.current_output_clean)
        FPLOG.debug('Send sudo command: %s' % 'cd /var/sf/bin/fat')
        dialog.send('cd /var/sf/bin/fat\n')
        dialog.expect(PROMPT)
        FPLOG.debug(
            'Send sudo command: %s' % '/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.send('/var/opt/CSCOpx/MDC/vms/jre/bin/java -jar /var/sf/bin/fat/lib/firepower-automation-*.jar')
        dialog.expect(PROMPT)
        raw = dialog.current_output_clean
        return (raw)

    @fmcCall()
    def fmcGET(self, url, data=None, **opts):
        if 'parameters' in opts:
            parameters = opts['parameters']
        else:
            parameters = {}
        FPLOG.info('sent GET request to FMC: %s' % url)
        raw = self.session.get(url, headers=self.headers, verify=False, params=parameters)
        return (raw)

    @fmcCall()
    def fmcPUT(self, url, put_data=None, **opts):
        self.request_body = put_data
        FPLOG.info('sent PUT request to FMC: %s with headers:\n%s, data:\n%s' % (url, self.headers, dumps(put_data)))
        raw = self.session.put(url, data=dumps(put_data), headers=self.headers, verify=False)
        return (raw)

    @fmcCall()
    def fmcPOST(self, url, post_data=None, **opts):
        self.request_body = post_data
        FPLOG.info('sent POST request to FMC: %s\nPOST data:\n%s' % (url, dumps(post_data)))
        with open('fppost.txt', 'w') as f:
            f.write(dumps(post_data))

        raw = self.session.post(url, headers=self.headers, data=dumps(post_data), verify=False)
        return (raw)

    @keyword()
    def Remove_Existing_Rulesets(self):
        resp = self.purge_ctu_rulesets()
        if 'all done' in resp:
            rval = 'SUCCESSFULLY pruned all CTU rulesets...deploying\n'
            rval += self.Deploy_Policy_To_FP()
            return (rval)
        return ('ERROR: failed to prune rulesets')

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
            FPLOG.debug('fetching info on device: %s' % device_name)
            intstats = self.fmcGET('devices/devicerecords/%s/etherchannelinterfaces' % device.Id)
            intstats = self.fmcGET('object/urls')
        return (rval)

    @keyword()
    def Get_Policy_Assignments(self, **opts):
        assignments = self.fmcGET('assignment/policyassignments', parameters={'expanded': 'True'})
        if len(self.policies['access']) < 2:
            self.Get_Access_Policies()

        rval = 'No policy found for FP device @ %s' % self.ftd_IP
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
                if device['name'] == self.fp.Name:
                    self.fp.Policy = policy
                    rval = policy.Name
        return (str(rval))

    @keyword()
    def Set_Policy_Assignment(self, new_policy_name=None, policy_type='access'):

        J = JSONEncoder()
        assert new_policy_name != None, 'ERROR: the policy name to which the FP is to be assigned was not specified'
        if len(self.policies[policy_type]) < 2:
            self.Get_Policies(policy_type)
        assert new_policy_name in self.policies[
            policy_type], 'ERROR: the specified policy name "%s" is invalid' % policy_type
        old_policy_assignment = self.fp.Policy.json
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
                    'id': self.fp.Id,
                    'type': self.fp.Type,
                    'name': self.fp.Name
                }
            ]
        }
        send_json = J.encode(new_policy.json)
        FPLOG.debug('sending policy assignment request:\n%s' % send_json)
        resp = self.fmcPOST('assignment/policyassignments', new_policy.json)
        assert 'ERROR' not in resp, '%s\n\n%s' % (new_policy.json, resp)

        return (resp)

    @keyword()
    def Deploy_Policy_To_FP(self, wait='1800.0'):
        sleep(120)
        return ('This keyword is deprecated with implementation of FAT utility')
        try:
            waittime = float(wait)
        except:
            FPLOG.error('Invalid wait time specified')
            waittime = 1800.0
        if not self.fp:
            self.Get_Device_Records()
        deployable = self.fmcGET('deployment/deployabledevices', parameters={'expanded': 'True'})
        self.deployable = deployable
        is_deployable = False
        policy_to_deploy = self.Get_Policy_Assignments()
        version = ''
        for item in deployable['items']:
            if item['device']['name'] != self.fp.Name:
                continue
            if item['canBeDeployed'] != True:
                break
            is_deployable = True
            version = item['version']
        if is_deployable == False:
            FPLOG.info('Firepower device "%s" is not in a state to deploy policy "%s"...deploying anyway' % (
                self.fp.Name, policy_to_deploy))
        post_data = {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": [self.fp.Id]
        }
        resp = self.fmcPOST('deployment/deploymentrequests', post_data)
        timed_out = True
        if 'metadata' in resp and 'task' in resp['metadata'] and 'id' in resp['metadata']['task']:
            taskID = resp['metadata']['task']['id']
            timer = time() + waittime
            FPLOG.info('Deployment started, Task ID = %s. Waiting %d seconds to complete' % (taskID, int(waittime)))
            while time() < timer:
                job_status = self.Get_Job_Status(taskID)
                logging.debug('job status: %s' % job_status['message'].replace(self.fp.Id, self.fp.Model))
                if job_status['message'].find('Deploying') >= 0 or job_status['message'].find(
                        'PARTIALLY_SUCCEEDED') >= 0:
                    FPLOG.debug(job_status['message'].replace(self.fp.Id, self.fp.Model))
                    sleep(5)
                    continue
                if job_status['message'].find('SSP_SUCCEEDED') >= 0:
                    FPLOG.debug(job_status['message'].replace(self.fp.Id, self.fp.Model))
                    sleep(5)
                    continue

                if job_status['message'].find('FAILED') >= 0:
                    return ('ERROR: %s' % job_status['message'].replace(self.fp.Id, self.fp.Model))
                timed_out = False
                break
            if timed_out == True:
                return ('ERROR: timed out after %d seconds waiting for policy to deploy' % int(timer))
            return (job_status['message'].replace(self.fp.Id, self.fp.Model))

        return (resp)

    @keyword()
    def Get_Device_Records(self, device_name=None, **opts):
        if device_name == None:
            device_name = self.ftd_IP
        FPLOG.debug('fetching device rercords')
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
                self.fp = device
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
        FPLOG.debug('fetching job status for job %s' % jobid)

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
        FPLOG.info('copying %s on ATF to %s on FMC' % (source, destination))
        resp = C.pushfile(source, destination)
        if 'ERROR' in resp:
            return (resp)
        nfe = non_fatal_error(resp)
        FPLOG.info('Copying ruleset at %s to /var/sf/bin/fat/rulesin.txt' % destination)
        C = Connect(self.fmc_IP)
        C.sudo('cp %s /var/sf/bin/fat/rulesin.txt' % destination)
        C.cnx.close()

        return (destination, resp if not nfe else nfe)

    @keyword()
    def Install_SRU_Rulesets(self, sru_ruleset_shell_script):
        FPLOG.debug('running SRU ruleset installation script "%s"' % sru_ruleset_shell_script)
        C = Connect(self.fmc_IP)
        resp = C.sudo('bash %s' % sru_ruleset_shell_script)
        C.cnx.close()
        nfe = non_fatal_error(resp)
        return (resp if not nfe else nfe)

    @keyword()
    def OLD_Install_CTU_Ruleset(self, ctu_ruleset_file=None, policy_type='ari-balanced', access_policy=None):
        assert ctu_ruleset_file != None, 'ERROR: the CTU ruleset file name was not specified'
        assert access_policy != None, 'ERROR: the access policy name was not specified'
        FPLOG.debug('installing CTU ruleset: policy=%s, access=%s, ctu_ruleset_file=%s' % (
            policy_type, access_policy, ctu_ruleset_file))
        try:
            ctu_ruleset = re.findall('.*(vrt_release_.*\.txt)', ctu_ruleset_file)[0]
        except Exception as estr:
            raise AssertionError, 'ERROR: invalid ruleset filename "%s" :\n%s' % (ctu_ruleset_file, str(estr))
        C = Connect(self.fmc_IP)
        check_ruleset_location = C.sudo('ls tmp/%s' % ctu_ruleset.strip())
        assert 'No such file or directory' not in check_ruleset_location, 'ERROR: CTU ruleset %s has not been uploaded to the FMC' % ctu_ruleset
        cmd = '--policy %s --access %s --deploy --file /var/tmp/%s' % (policy_type, access_policy, ctu_ruleset.strip())
        resp = self.fmc_oink(command=cmd)
        assert 'Completed ARI Tool Run' in resp, 'ERROR: installation of CTU rulesets failed to complete in 90 seconds'
        FPLOG.debug('CTU ruleset installation Complete:\n%s' % resp)
        nfe = non_fatal_error(resp)
        if 'ARI failed' in resp:
            resp = 'ERROR: %s' % resp
        if nfe != None:
            resp = 'WARNING: %s' % resp
        return (resp)

    @keyword()
    def Install_CTU_Ruleset(self, ctu_ruleset_file=None, policy_type='ari-balanced', access_policy=None):
        assert ctu_ruleset_file != None, 'ERROR: the CTU ruleset file name was not specified'
        FPLOG.debug('installing CTU ruleset: policy=%s, access=%s, ctu_ruleset_file=%s' % (
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
        FPLOG.debug('CTU ruleset installation Complete:\n%s' % resp)
        return (resp)

    @keyword()
    def Download_CTU_Ruleset(self, version):
        FPLOG.debug('attempting to download CTU ruleset version %s' % version)
        V = VulnDB()
        vrt_ruleset, tmp_vrt_rulset = V.fetch_vrt_ruleset(version)
        if vrt_ruleset == None:
            return ('ERROR: downloading CTU rulesets:\n%s' % V.error)
        FPLOG.info('downloaded CTU Rulesets %s and stored in temporary file %s' % (vrt_ruleset, tmp_vrt_rulset))
        return (tmp_vrt_rulset)

    @keyword()
    def Get_Released_CTU_Ruleset_Version(self, version=''):
        V = VulnDB()
        rs_version = V.fetch_vrt_ruleset()
        return (rs_version)

    @keyword()
    def Download_CTU_Ruleset_Diffs(self, first=None, second=None):
        FPLOG.debug('Arguments: %s, %s' % (str(first), str(second)))
        assert first != None, 'ERROR: at least one version must be supplied'
        if second == None or int(second) <= int(first):
            second = str(int(first, 10))
            first = str(int(first, 10) - 1)
        vlndb = VulnDB(self.TestEnv, self.ATF_User)
        diffs = vlndb.fetch_ctu_ruleset_diffs(first, second)
        return ('Ruleset differences between %s and %s\n%s' % (first, second, diffs))


class Policy:
    def __init__(self, policy):
        for item in policy:
            self.__dict__[item.capitalize()] = policy[item]
        self.__dict__['json'] = policy


class Device:
    def __init__(self, data):
        for item in data:
            self.__dict__[item.capitalize()] = data[item]
        self.__dict__['Policy'] = None


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

            FPLOG.debug('creating transport session for %s' % self.ip)
            T = Transport((self.ip, 22))
            FPLOG.debug('starting transport client for %s' % self.ip)
            T.start_client()
            key = T.get_remote_server_key()
        except Exception as estr:
            FPLOG.error('unable to insert isert host key for %s\n%s' % (self.ip, str(estr)))
            raise AssertionError, 'Trap %s' % estr

        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if keypath == None:
                FPLOG.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword, look_for_keys=False, allow_agent=False)
                FPLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                FPLOG.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    FPLOG.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except:
                    FPLOG.debug(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.cnx.connect(self.ip, username=user, password=pword)
                    FPLOG.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                    self.connection_established = True
        except Exception as error:
            self.error = "Connection failure to device at %s, user:%s\n%s" % (
                self.ip, user, str(error) + ',' + pword)
            FPLOG.error(self.error)
            self.connection_established = False
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
        self.user = user
        self.device = device
        self.BUF_SIZE = 65535
        self.rxc = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def cmd(self, command, **kwords):
        if self.connection_established == False:
            FPLOG.error('Connection error...cannot execute remote command')
            return ('Connection Error')
        # self.cnx = paramiko.SSHClient()

        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            FPLOG.debug("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)
        except Exception as estr:
            FPLOG.debug('Error connecting to FMS: "%s"' % str(estr))
            self.error = ''
            self.reconnect()
            if self.error != '':
                FPLOG.error('Error connecting to FMS: %s' % self.error)
            stdin, stdout, stderr = self.cnx.exec_command("%s" % command)

        response = stdout.read()
        if response == '':
            response = stderr.read()
        FPLOG.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            FPLOG.debug('reconnecting to host %s' % self.ip)
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            FPLOG.error(self.error)
            raise AssertionError, self.error
        FPLOG.debug('re-connection successful')

    def sudo(self, command, **flags):
        if self.connection_established == False:
            FPLOG.error('Connection error...cannot execute remote sudo')
            return ('Connection Error')
        # self.cnx = paramiko.SSHClient()
        flist = ''
        if len(flags) > 0:
            for f in flags.keys():
                flist += " \-%s %s" % (f, flags[f])

        response = ''
        error = ''
        FPLOG.info('Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
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
            FPLOG.error('ERROR in response to sudo command: %s' % "sudo -S %s 2>&1" % command)
        FPLOG.info("Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response.replace('Password: ', ''))

    def pushfile(self, source, destination):
        import scpclient as SCP
        from hashlib import md5

        if self.connection_established == False:
            FPLOG.error('Connection error...cannot upload file')
            return ('Connection Error')
        try:
            destination_path = os.path.basename(destination)
            FPLOG.info('uploading file %s from ATF to %s:%s' % (source, self.ip, destination))
            W = SCP.Write(self.transport, os.path.dirname(destination))
            W.send_file(source, destination_path)
            SCP.closing(W)
            C = Connect(self.ip)
            FPLOG.debug('moving %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            resp = C.sudo('mv %s/%s %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            FPLOG.debug('moved %s/%s to %s' % (os.path.dirname(destination), os.path.basename(source), destination))
            FPLOG.debug('comparing MD5 sums between source and destination files after upload')
            md5sum = C.cmd('md5sum %s' % destination).split(' ')[0]
            C.cnx.close()
            with open(source, 'r') as sfile:
                smd5sum = md5(sfile.read())
            assert md5sum == smd5sum.hexdigest(), 'MD5 sums do not match between source and destination files'
            return ('Success: MD5 sums of the source and destination files match: % s\n' % md5sum)
        except Exception as estr:
            FPLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return ('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))

    def pullfile(self, destination, source):
        import scpclient as SCP
        from hashlib import md5
        import traceback

        if self.connection_established == False:
            FPLOG.error('Connection error...cannot upload file')
            return ('Connection Error')

        try:
            source_path = os.path.basename(source)
            print
            'source="%s"' % source
            print
            'destination="%s"' % destination
            FPLOG.info('downloading file %s from %s:%s to ATF' % (source, self.ip, source))
            R = SCP.Read(self.transport, os.path.dirname(source))
            resp = R.receive_file(destination, True, None, source_path)
        except Exception as estr:
            tb = traceback.extract_stack()
            pprint(tb)
            FPLOG.error('ERROR - failed to copy %s to %s (%s)' % (source, destination, str(estr)))
            return ('ERROR - failed to copy %s from %s (%s)' % (source, destination, str(estr)))

        return (resp)
