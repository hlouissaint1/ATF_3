#! /usr/bin/python
# import pycurl
import os
import sys
import re
from time import time, strftime, sleep, gmtime
from subprocess import call
from lxml import etree
from lxml.builder import E
from types import *
from robot.api import logger as logging
from robot.api.deco import keyword
from tempfile import mkstemp
import paramiko
import warnings
# import atf_password
import axsess
from optparse import OptionParser
from atfvars import varImport
from scwxCorelib import Connect

global options
NOW = lambda: strftime('%4Y-%2m-%2dT%2H:%2M:%2S.%Z', gmtime(time() + 2))
BAD_VERSION_FORMAT = 'Incorrect version formatting'
PARSER = etree.XMLParser(remove_blank_text=True)
DOCROOT = '/var/www/html/htdocs'
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())
CTP_ERROR_WAITTIME = 600
CTP_ERROR_SLEEP_TIME = 10
ERRORS_TO_RETRY = ['503', '401']
ERRORS_TO_RETURN_AS_INCIDENTS = ['404']
MAX_RETRY_ATTEMPTS = 6
SESSION_RENEW_SECONDS = 25

import logging

LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)


def RFTime(timestr):  # input the time in RF format and convert to seconds
    dregex = '\d+(?=\s*(s.*|m.*|h.*))'
    mulitpilers = {'s': 1.0, 'm': 60.0, 'h': 3600.0}
    match = re.match(dregex, timestr)
    if match == None:
        return (60.0)
    value = match.group()

    multiplier = timestr.replace(value, '').strip()[0]
    val = float(value)
    if multiplier in mulitpilers:
        val *= mulitpilers[multiplier]
    return (val)


#######################################################################################################################
#
# Equates for Validating Input Arguments
#
#######################################################################################################################

pkeys = {'balanced': '5', 'security': '6', 'connectivity': '7'}
valid_ruleset_categories = ['balanced', 'security', 'connectivity']
is_correctly_formatted = lambda v: re.match('(\d{1,2}\.){4}\d{1,5}', v) != None  # Ruleset version format
valid_ruleset_status = ['AVAILABLE', 'QA_APPROVED', 'QA_REJECTED', 'DISABLED', 'ROLLED_BACK', 'QA_TESTING',
                        'IMPORTED', 'BASELINING', 'IMPORTING', 'IMPORTING_FROM_CTU', 'BUILDING_RPM']


#######################################################################################################################
#
# getServiceAliases provides the URI of the CTP server given the environment (e.g. Agile)
# and optionally the service alias)
#######################################################################################################################


def getServiceAliases(test_env, svc=None):
    env = test_env.lower()
    skeys = {
        'agile': {
            # 'auth': '%s-auth.core.ctp.secureworkslab.com/auth' % env,
            'auth': 'a-auth.core.ctp.secureworkslab.net/auth',
            'prov': '%s-prov.core.ctp.secureworkslab.com/prov/' % env,
            'topo': '%s-topo.core.ctp.secureworkslab.com/topo/' % env,
            'audit': '%s-audit.core.ctp.secureworkslab.com/audit/' % env,
            'notify': '%s-notify.core.ctp.secureworkslab.com/notify/' % env,
            'tkt': '%s-tkt.core.ctp.secureworkslab.com/tkt/' % env,
            'tktpolicy': '%s-tktpolicy.core.ctp.secureworkslab.com/tktpolicy/' % env,
            'evt': '%s-evt.core.ctp.secureworkslab.com/evt/' % env,
            'certcheck': 'agile-idp.secureworks.com/crtchk?r=/portal/',
            'maint': '%s-maint.core.ctp.secureworkslab.com/maint/' % env,
            'sched': '%s-sched.core.ctp.secureworkslab.com/sched/' % env,
            'report': '%s-report.core.ctp.secureworkslab.com/report/' % env,
            'query': '%s-query.core.ctp.secureworkslab.net/query/' % env,
            'jobs': '%s-jobs.core.ctp.secureworkslab.com/jobs/' % env,
            'policy': '%s-policy.core.ctp.secureworkslab.com/policy/' % env,
            'vpn': '%s-vpn.core.ctp.secureworkslab.com/vpn/' % env,
            'intel': '%s-intel.core.ctp.secureworkslab.com/intel/' % env,
            'mntagt': '%s-mntagt.core.ctp.secureworkslab.com/mntagt/' % env,
            'health': '%s-health.core.ctp.secureworkslab.com/health/' % env,
            'asset': '%s-asset.core.ctp.secureworkslab.com/asset/' % env,
            'assetadapter': '%s-assetadapter.core.ctp.secureworkslab.com/assetadapter/' % env,
            'event': '%s-event.core.ctp.secureworkslab.com/event/' % env,
            'exec': '%s-exec.core.ctp.secureworkslab.com/exec/' % env,
            'pcsms': 'a-pcsms.core.ctp.secureworkslab.net/pcsms/',
            'noproxy': '--noproxy secureworkslab.net',
        },

        'pilot': {
            'auth': 'p-auth.core.ctp.secureworks.net/auth',
            'prov': 'p-prov.core.ctp.secureworks.net/prov/',
            'topo': 'p-topo.core.ctp.secureworks.net/topo/',
            'audit': 'p-audit.core.ctp.secureworks.net/audit/',
            'notify': 'p-notify.core.ctp.secureworks.net/notify/',
            'tkt': 'p-tkt.core.ctp.secureworks.net/tkt/',
            'tktpolicy': 'p-tktpolicy.core.ctp.secureworks.net/tktpolicy/',
            'evt': 'p-evt.core.ctp.secureworks.net/evt/',
            'certcheck': 'pilot-idp.secureworks.com/crtchk?r=https://pilot-portal.secureworks.com/portal',
            'maint': 'p-maint.core.ctp.secureworks.net/maint/',
            'sched': 'p-sched.core.ctp.secureworks.net/sched/',
            'report': 'p-report.core.ctp.secureworks.net/report/',
            'query': 'p-query.core.ctp.secureworks.net/query/',
            'jobs': 'p-jobs.core.ctp.secureworks.net/jobs/',
            'policy': 'p-policy.core.ctp.secureworks.net/policy/',
            'vpn': 'p-vpn.core.ctp.secureworks.net/vpn/',
            'intel': 'p-intel.core.ctp.secureworks.net/intel/',
            'mntagt': 'p-mntagt.core.ctp.secureworks.net/mntagt/',
            'health': 'p-health.core.ctp.secureworks.net/health/',
            'asset': 'p-asset.core.ctp.secureworks.net/asset/',
            'assetadapter': 'p-assetadapter.core.ctp.secureworks.net/assetadapter/',
            'event': 'p-event.core.ctp.secureworks.net/event/',
            'exec': 'p-exec.core.ctp.secureworks.net/exec/',
            # 'pcsms': '10.248.82.16/pcsms/',
            'pcsms': 'p-pcsms.core.ctp.secureworks.net/pcsms/',
            'noproxy': '--noproxy secureworks.net',
            # 'noproxy' : '',
        },

        'production': {  # 'auth': '%s-auth.core.ctp.secureworkslab.com/auth' % env,
            # 'auth' : 'pilot-portal.secureworks.com/portal',
            'auth': 'auth.core.ctp.secureworks.net/auth',
            # 'auth': '%s-auth.core.ctp.secureworks.net/auth' % env,
            'prov': 'prov.core.ctp.secureworks.net/prov/',
            'pcsms': 'pcsms.core.ctp.secureworks.net/pcsms/',
            'certcheck': 'idp.secureworks.com/crtchk?r=https://portal.secureworks.com/portal',
            'noproxy': '--noproxy secureworks.net',
        },
    }

    if svc:
        if svc == 'exec_':
            svc = 'exec'
        return (skeys[env][svc])
    return (skeys[env])


def fetch_policy(**pars):
    from copy import deepcopy

    get_by = ['address', 'uin', 'idn', 'regkey', 'mac']
    identity = missing = 'missing'
    for idatt in pars:
        if idatt.lower() in get_by:
            identity = idatt.lower()
            break
    assert identity != missing
    env = pars['environment'].lower() if 'environment' in pars else 'agile'
    value = pars[identity].lower()
    try:
        policy_list = etree.parse('%s/isensor.confd/isensor_inventory.xml' % (DOCROOT))
    except Exception as error:
        raise AssertionError, 'ERROR - unable to parse policy list (%s)' % str(error)
    nodel = policy_list.xpath('//policy[@%s="%s"]' % (identity, value))
    assert len(nodel) > 0, 'ERROR - isensor policy for %s: %s is not stored on the this server' % (identity, value)
    node = nodel[0]
    policy_atts = deepcopy(node.attrib)
    logging.debug(etree.tostring(node, pretty_print=True))
    cert_node = node.find('rcms-cert')
    if cert_node != None:
        cert_path = cert_node.text
        with open(cert_path, 'r') as c:
            cert = c.read()
    else:
        cert = '<rcms-cert/>'

    policy_path = '%s/isensor.confd/%s.isensor-config.xml' % (DOCROOT, value)
    try:
        with open(policy_path, 'r') as f:
            rval = f.read()
            return (False, rval, cert, policy_atts)
    except Exception as error:
        raise AssertionError, 'Policy not found: %s' % str(error)


def update_policy_list(cert_path=None, **pars):
    assert 'environment' in pars, 'ERROR - Test environment unknown'
    env = pars['environment']
    try:
        pxml = etree.parse('%s/isensor.confd/isensor_inventory.xml' % (DOCROOT), PARSER)
        proot = pxml.getroot()
    except:
        proot = E('isensor-policy-list')
    identified = None
    for identity in ['mac', 'regkey', 'idn', 'uin', 'iaddress']:
        if identity in pars and pars[identity] != '':
            identified = identity
            break
    assert identified != None, 'ctpapi.py:update_policy_list - ERROR. No identity provided'
    policy_list = pxml.xpath('//policy[@%s="%s"]' % (identified, pars[identified]))
    if len(policy_list) == 0:
        policy = E.policy()
        proot.append(policy)
    else:
        policy = policy_list[0]
    if policy.find('rcms-cert') != None:
        policy.remove(policy.find('rcms-cert'))
    if cert_path != None:
        certnode = E('rcms-cert', '%s' % cert_path)
        policy.append(certnode)
    for par in pars:
        policy.set(par, pars[par])
    with open('%s/isensor.confd/isensor_inventory.xml' % (DOCROOT), 'w') as f:
        f.write(etree.tostring(proot, pretty_print=True))


def store_policy(policy=None, certs=None, **pars):
    from copy import deepcopy

    assert policy != None, 'Null policy received'
    get_by = ['mac', 'regkey', 'idn', 'uin', 'address']
    identity = missing = 'missing'
    for idatt in pars:
        if idatt in get_by:
            identity = idatt
            break
    assert identity != missing
    env = pars['environment'].lower() if 'environment' in pars else 'agile'
    uin = pars['uin'] if 'uin' in pars else ''
    ip = pars['address'] if 'address' in pars else ''
    regkey = pars['regkey'] if 'regkey' in pars else ''
    mac = pars['mac'] if 'mac' in pars else ''
    idn = pars['idn'] if 'idn' in pars else ''
    stored = None
    cert_path = None
    for store_by in get_by:
        if not store_by in pars or pars[store_by] == '':
            continue
        lpath = '%s/isensor.confd/%s.isensor-config.xml' % (DOCROOT, pars[store_by])
        if os.path.exists(lpath):
            try:
                os.unlink(lpath)
            except Exception as error:
                raise AssertionError, 'ERROR: Unable to remove existing policy: %s' % str(error)
        if stored == None:
            try:
                with open(lpath, 'w') as f:
                    f.write(etree.tostring(policy, pretty_print=True))
                stored = deepcopy(lpath)
                if certs != None:
                    logging.debug('%s - %s' % (store_by, pars[store_by]))
                    cert_path = '%s/isensor.confd/%s.rcms-cert.xml' % (DOCROOT, pars[store_by])
                    try:
                        with open(cert_path, 'w') as f:
                            f.write(etree.tostring(certs, pretty_print=True))
                    except Exception as error:
                        raise AssertionError, 'ERROR: unable to write certs to %s' % cert_path
                continue
            except Exception as error:
                raise AssertionError, 'ERROR: unable to write policy to %s' % lpath

        try:
            os.symlink(stored, lpath)
        except Exception as error:
            raise AssertionError, 'ERROR - unable to create link from %s to %s\n%s' % (lpath, stored, str(error))

    update_policy_list(cert_path, idn=idn, uin=uin, address=ip, regkey=regkey, environment=env, mac=mac)
    return (True, etree.tostring(policy, pretty_print=True))


def read_response(outfd, outname, errfd, errname, **kword):
    with open(outname, 'r') as f:
        raw = f.read()
    try:
        xml = etree.fromstring(raw)
        rsp = etree.tostring(xml, pretty_print=True)
    except:
        rsp = raw
    with open(errname, 'r') as f:
        err = f.read()
    rcodestr = re.findall('<\s+HTTP.*\d{3}.*', err)
    if len(rcodestr) == 0:
        rcode = ''
        eout = err
        logging.debug('No HTTP return code found:\n%s\n' % err)
    else:
        rcode = rcodestr[len(rcodestr) - 1].partition(' ')[2][9:12]  # get the three digit HTTP code
        eout = rcodestr[len(rcodestr) - 1].partition(' ')[2][9:]
        logging.debug('HTTP Response: %s' % eout)
        if kword.has_key('ignore_error') and kword['ignore_error'] == True:
            return (rsp, err, eout)
        with open('/tmp/curl.out', 'a') as w:
            with open(outname, 'r') as r:
                w.write('CURL output to STDOUT:%s\n%s\n%s\n\n' % (NOW(), r.read(), '-' * 80))
            with open(errname, 'r') as r:
                w.write('CURL output to STDERR:%s\n%s\n%s\n\n' % (NOW(), r.read(), '=' * 80))
        assert eout.startswith('20'), eout
    if kword.has_key('object'):
        obj = kword['object']
    try:
        x = rsp.index('</html>\n')
        rsp = rsp[x + 8:]
    except ValueError:
        pass
    # check if the xml contains an error message
    try:
        xml = etree.fromstring(rsp)
        if xml.tag == 'error':
            rsp = "ERROR: " + xml.attrib['type'] + "..."
            msg = xml.xpath('attrs/attr')
            if len(msg) > 0:
                rsp += msg[0].text
    except:
        pass
    return (rsp, err, eout)


def apply_filters(xmlstr, xpathlist):
    xml = etree.fromstring(xmlstr)
    found = []
    for xpath in xpathlist.split(','):
        elements = xml.xpath(xpath)
        for element in elements:
            if element != None:
                found.append('%s=%s' % (element.tag, element.text))
    rstr = ''.join('%s\n' % s for s in found)
    return (rstr)


def show_result(I, **kword):
    print '\nCURL COMMAND:\n%s' % I.curl_cmd
    if kword.has_key('post'):
        print 'POST DATA:\n%s\n' % I.post_data
    print 'RESPONSE CODE: %s\n' % I.rcode
    print 'RESPONSE DATA:\n%s\n' % I.response


"""
class Connect:
    @varImport()
    def __init__(self, **evars):
	if not 'device' in evars:
		self.__dict__['device'] = 'isensor'
	self.__dict__.update(evars)
        warnings.simplefilter('ignore')
        paramiko.util.log_to_file('%s/logs/paramiko.log' % LOGPATH)
        P = axsess.Password()
        try:
            self.ip = evars['%s_IP' % self.device]
            if self.ip == None or len(self.ip) == 0:
                self.ip = evars['%s_host' % self.device]
        except KeyError:
            try:
                self.ip = evars['%s_host' % self.device]
            except KeyError:
                if 'isensor_IP' in os.environ:
                    self.ip = os.environ['isensor_IP']
                else:
                    raise AssertionError, '%s...%s' % (self.device, str(evars))
        self.connection_established = False
        try:
            device_name = evars['%s_name' % self.device]
        except KeyError:
            device_name = self.ip
        self.sftp_chan = None
        if len(self.ip) > 0:
            self.device, user, pword, self.cert_path = P.getCredentials(address=self.ip)
            self.cnx = paramiko.SSHClient()
            self.cnx.load_system_host_keys()
            self.error = ''
            self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
		keypath = evars['keypath'] if 'keypath' in evars else None
                if keypath == None:
                    logging.debug('attempting connection to %s using password' % self.ip)
                    self.cnx.connect(self.ip, username=user, password=pword)
                    logging.debug("Connection established %s (%s) for user %s" % (self.device, self.ip, user))
                    self.connection_established = True
                else:
                    logging.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                    try:
                        key = paramiko.RSAKey.from_private_key_file(keypath)
                        self.cnx.connect(self.ip, username=user, pkey=key)
                        logging.debug(
                            "Connection established %s (%s) for user %s using shared key" % (self.device, self.ip, user))
                        self.connection_established = True
                    except Exception as estr:
                        logging.debug(
                            'failed authentication with shared key...attempting connection to %s using password: %s' % (self.ip,str(estr)))
                        self.cnx.connect(self.ip, username=user, password=pword)
                        logging.debug("Connection established %s (%s) for user %s" % (self.device, self.ip, user))
                        self.connection_established = True

            except Exception as error:
                self.error = "Connection failure to device (%s) at %s, user:%s\n%s" % (
                self.device, self.ip, user, str(error))
                print self.error
                logging.error(self.error)
                self.connection_established = False
            if self.connection_established == True:
                self.transport = self.cnx.get_transport()
                try:
                    self.sftp_client = paramiko.sftp_client.SFTPClient
                except Exception as error:
                    raise AssertionError, 'Missing SFTPClient paramiko module'
            else:
                raise AssertionError, 'Unable to connect to device "%s" @ %s' % (self.device, self.ip)
            self.user = user
            self.ip3q = ''


    def cmd(self, command, **kwords):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            logging.debug("Sent command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)
        except Exception as estr:
            self.connection_established = False
            return ('ERROR: Connection to host %s dropped' % self.device)

        response = stdout.read()
        if response == '':
            respone = stderr.read()
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
            logging.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def sudo(self, command, **flags):
        if self.connection_established == False:
            return ('Connection Error')
        if self.error != '':
            return (self.error)
        flist = ''
        if len(flags) > 0:
            for f in flags.keys():
                flist += " \-%s %s" % (f, flags[f])

        logging.info('Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
        try:
            stdin, stdout, stderr = self.cnx.exec_command("sudo -S %s 2>&1" % command)
        except Exception as estr:
            self.connection_established = False
            return ('ERROR: Connection to host %s dropped' % self.device)
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

"""


# +++++++++++++++++++++++++++++++++++++

class Jump:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.device = "jump"
        self.evars = evars
        self.pause = Connect(self.device, **evars)
        self.ip = self.pause.ip


class VulnDB:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        device = self.device = "vlndb"
        self.evars = evars
        self.apikey = self.vlndb_Password
        self.curl_command = ''
        self.curl_cmd = lambda u, g: 'curl -k -v "https://%s/%s?%s&apikey=%s"' % (
        self.vlndb_IP, u, g, self.vlndb_Password)
        self.tmpfile = lambda s: mkstemp(suffix=s, prefix='atf.vulndb')
        self.wrfile = lambda f: open(f, 'w')
        self.rdfile = lambda f: open(f, 'r')

    @keyword()
    def Download_Ruleset(self, release_number, **opts):
        test_for_int_string = 0
        try:
            test_for_int_string = int(release_number)
        except ValueError:
            assert test_for_int_string != 0, 'Invalid release number supplied'
        od, ofname = self.tmpfile('get_ruleset.out')
        ed, efname = self.tmpfile('get_ruleset.err')
        of = self.wrfile(ofname)
        ef = self.wrfile(efname)
        self.curl_command = self.curl_cmd('latest_vrt_release.txt', 'release_number=%s' % release_number)
        call(self.curl_command, shell=True, stderr=ef, stdout=of)
        of.close()
        ef.close()
        of = self.rdfile(ofname)
        ef = self.rdfile(efname)
        response = of.read()
        error = ef.read()
        of.close()
        ef.close()
        logging.debug(error)
        # print "\n%s\n%s\n" % (ofname,efname)
        os.unlink(ofname)
        os.unlink(efname)
        if opts.has_key('save_file'):
            try:
                f = open(opts['save_file'], 'w')
                f.write(response)
                f.close()
            except IOError:
                raise AssertionError, 'Downloaded ruleset cou;d not be saved to %s' % opts['save_file']
        return (response)

    def parse_ruleset_diffs(self, xmlstr, include_removed=False):
        xml = etree.fromstring(xmlstr)
        rstr = ''
        # sections = ['added', 'removed', 'changed']
        sections = ['added', 'changed', 'removed']
        for section in sections:
            if include_removed == False and section == 'removed':
                continue
            dstr = ''
            diffs = xml.xpath('//signature[@diff="%s"]' % section)
            ndiffs = len(diffs)
            for diff in diffs:
                rev = 'xxx' if 'rev' not in diff.attrib else diff.attrib['rev']
                priority = 'xxxx' if not 'priority' in diff.attrib else diff.attrib['prioruty']
                dstr += '[+] %s VID%s %s (rev: %s, priority: %s)\n' % (
                    diff.attrib['swid'],
                    diff.attrib['vid'],
                    diff.attrib['msg'],
                    rev,
                    priority)
            rstr += '[+] %s (%d)\n%s' % (section.capitalize(), ndiffs, dstr)
        return (rstr)

    @keyword()
    def Download_Ruleset_Diffs(self, engine_version, policy, first_release, second_release, **opts):
        od, ofname = self.tmpfile('get_ruleset_diff.out')
        ed, efname = self.tmpfile('get_ruleset_diff.err')
        of = self.wrfile(ofname)
        ef = self.wrfile(efname)
        uri = 'engine_name=Snort'
        uri += '&engine_version=%s' % engine_version
        uri += '&policy=%s' % policy
        uri += '&first_release_number=%s' % first_release
        uri += '&second_release_number=%s' % second_release
        call(self.curl_cmd('pcs_release_diff.xml', uri), shell=True, stderr=ef, stdout=of)
        of.close()
        ef.close()
        of = self.rdfile(ofname)
        ef = self.rdfile(efname)
        response = of.read()
        error = ef.read()
        of.close()
        ef.close()
        logging.debug(error)
        os.unlink(ofname)
        os.unlink(efname)
#        import io
        if opts.has_key('save_file'):
            try:
                with open(opts['save_file'], 'w') as f:
                    f.write(self.parse_ruleset_diffs(response))
                with open('%s.all' % opts['save_file'], 'w') as f:
                    f.write(self.parse_ruleset_diffs(response, True))
            except IOError as ioerr:
                raise AssertionError, 'Downloaded ruleset diffs could not be saved to %s\n%s' % (
                    opts['save_file'], str(ioerr))
        return (self.parse_ruleset_diffs(response, True))

    @keyword()
    def Latest_CTU_Approved_Ruleset(self, category=None):
        import json
        from urllib2 import urlopen

        od, ofname = self.tmpfile('latest_ctu_approved.out')
        ed, efname = self.tmpfile('latest_cti_approved.err')
        of = self.wrfile(ofname)
        ef = self.wrfile(efname)
        url = 'https://%s/ctu_cms/cms_api/release/current_ruleset_releases?%s' % (self.url, self.apikey)
        resp = urlopen(url)
        jobj = json.loads(resp.read())
        approved_rulesets = {}
        for ruleset in jobj["rulesets"]:
            if not ruleset['latest_release']:
                continue
            try:

                # engine_group_id 2 is iSensor v7/8 but includes VRT; ruleset_id 5 is connectivity; 4 is security; 3 is balanced. Or use name like this:
                if ruleset['engine_group_id'] != 2 or ruleset['sensor_policy']['name'] not in ['security', 'balanced',
                                                                                               'connectivity']:
                    continue
                if category == None:  # then return all categories
                    return (None)

            except Exception as error:
                raise AssertionError, 'Parsing Error - %s' % str(error)
        return (None)


def get_private_key():
    try:
        fxml = etree.parse('%s/%s/%s_servers.xml' % (DOCROOT, os.environ['ATF_User'], os.environ['TestEnv']))
        keynode = fxml.find('atf/private-key')
        if keynode == None:
            return (None)
        keypath = keynode.attrib['name']
        return (keypath)
    except Exception as estr:
        raise AssertionError, 'Cannot locate private key path: %s' % str(estr)


class iSensor:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.device = "isensor"
        self.evars = evars
        self.ct_env = self.TestEnv
        self.user = self.ATF_User
        self.key = get_private_key()
        self.isensor = Connect(self.TestEnv, self.ATF_User, device=self.device, keypath=self.key)
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
        for tag in self.vtags.keys():
            vval = self.cmd('cat /var/iSensor/%s' % tag)
            self.vtags[tag] = vval.rstrip('\n')
        rmVersion = self.cmd(
            "export PATH=$PATH:/secureworks/bin/;/secureworks/bin/sw-info.sh |grep -A 3 Policies |grep Ruleset |pcregrep -o '(\d+\.){4}\d+'")
        category = self.cmd(
            "export PATH=$PATH:/secureworks/bin/;/secureworks/bin/sw-info.sh |grep -A 3 Policies |grep Ruleset |pcregrep -o 'security|balanced|connectivity'")
        if category != '':
            self.category = category.rstrip('\n')
        self.vtags['rmVersion'] = rmVersion.rstrip('\n')

    @keyword()
    def Get_UIN(self):
        return (self.uin)

    def Get_Inspector(self):
        default_inspector = '1.1.1.1'
        dxml = etree.parse('%s/%s/%s_servers.xml' % (DOCROOT, self.ATF_User, self.TestEnv))
        sensor = dxml.find('isensor[address="%s"]' % self.isensor_IP == None)
        if sensor == None:
            return (default_inspector)
        inode = sensor.find('inspector')
        if inode == None:
            return (default_inspector)
        else:
            return (inode.attrib['address'])


##############################################################################################
#
# Decorator for calls to the CTP API
#
###############################################################################################

class apiCall():
    def __call__(self, svc):

        def api_call(self, uri=None, post=None, **opt):  # extract=None, post=None, debug=False):
	    from axsess import Password
            if 'service' in opt:
                alias = opt['service']
            else:
                alias = svc.__name__.lower()
            assert type(uri) is not None, 'Missing URI'
	    errfd, errfn = mkstemp(prefix='atf.ctpapi', suffix='err')
	    outfd, outfn = mkstemp(prefix='atf.ctpapi', suffix='out')
	    self.cacert = '/etc/pki/tls/certs/ca.crt'
	    #auth = self.fetch_service_host('auth')
	    auth = getServiceAliases(self.ct_env.lower(), svc='auth')
            if time() - self.session_timer > 25.0:
		hdrstr = '"Authorization: CT-Certificate true"'
		cmdstr = 'sudo curl -v --key %s --cacert %s --cert %s -d "" -H %s "https://%s/sessions?zone=CT"' % (
			self.keypath,
			self.cacert,
			self.cert_path,
			hdrstr,
			auth
			)
	    	logging.debug('requesting session token from auth server:\n%s' % cmdstr)
		with open("/tmp/curl.out", 'a') as f:
			f.write("CURL COMMAND(to auth server):%s\n%s\n%s\n\n" % (NOW(), cmdstr, '-' * 80))
		ret = call([cmdstr], shell=True, stderr=errfd, stdout=outfd)
		with open("/tmp/curl.out", 'a') as w:
			with open(outfn, 'r') as r:
				w.write("CURL output to STDOUT:\n%s\n%s\n\n" % (r.read(), "-" * 80))
		with open(errfn, 'r') as rerr:
			resp = rerr.read()
		with open("/tmp/curl.out", 'a') as w:
			with open(outfn, 'r') as r:
				w.write("CURL output to STDERR:\n%s\n%s\n\n" % (resp, "=" * 80))
		if ret != 0:
			logging.error('ERROR %d executing: %s' % (ret, cmdstr))
		assert ret == 0, 'ERROR %d executing: %s' % (ret, cmdstr)
		self.location = re.findall('(?<=Location:\s)https:.*$',resp, re.MULTILINE)
		assert len(self.location) > 0, 'ERROR:Failed to retrieve session token from %s\n\tusing cert: %s\nresponse:\n%s\n' % (cmdstr,self.cert_path, resp)
		self.token = self.location[0].rstrip()
		self.session_timer = time() + SESSION_RENEW_SECONDS

            pars = {}
            self.outfd, self.response_filename = mkstemp(suffix='stdout', prefix='atf.%s' % alias)
            self.errfd, self.error_filename = mkstemp(suffix='stdout', prefix='atf.%s' % alias)
            pars['srvc'] = alias
            hdrstr = 'Authorization: CT-Session %s' % (self.token)
	    cmdstr = 'sudo curl -v -k -H "%s" ' % hdrstr 
            if 'PUT' in opt:
                cmdstr += ' -X PUT'
                if len(post) > 0:
                    cmdstr += ' -d "%s"' % post
                else:
                    cmdstr += ' -d ""'
            elif post != None or 'POST' in opt:
                self.post_data = post
                cmdstr += ' -X POST'
                if post.startswith('@'):
                    with open(post.lstrip('@'), 'r') as f:
                        self.postXML = f.read()
                        logging.debug('Post data in %s:\n%s' % (post, self.postXML))
                else:
                    logging.debug('Post data:\n%s' % post)
                    self.postXML = post
                cmdstr += ' -d "%s"' % post
            cmdstr += ' "https://%s%s"\n' % (getServiceAliases(self.ct_env.lower(),svc=alias), uri )
            self.error = None
            self.response = None
            # f, fn = mkstemp(prefix=alias, suffix='curl_cmd')
            # f.write(cmdstr)
            self.curl_cmd = cmdstr

            logging.debug('api_call to "%s" service: %s' % (alias, cmdstr))

            svc(self, cmdstr, pars)

            with open(self.response_filename, 'r') as f:
                self.stdout_text = f.read()
                if len(self.stdout_text) > 256:
                    logging.debug('response (stdout):\n%s...(truncated the remaining %d characters)' % (
                        self.stdout_text[256], len(self.stdout_text) - 256))
                else:
                    logging.debug('response (stdout):\n%s' % self.stdout_text)
            with open(self.error_filename, 'r') as f:
                self.stderr_text = f.read()
                # logging.debug('response (stderr):\n%s' % self.stderr_text)
            os.unlink(self.response_filename)
            os.unlink(self.error_filename)
            if post and self.post_xml.has_key(post):
                os.unlink(post)
                self.post_xml.pop(post)

        return (api_call)


def clear_empty_nodes(xml):
    root = xml.getroot()
    for child in root.iterdescendants():
        if child.text == None:
            child.getparent().remove(child)
    return (xml)


class API:
    @varImport()
    def __init__(self, **evars):
	from axsess import Password
        self.__dict__.update(evars)
        ct_env = evars['TestEnv']
        if ct_env != None:
            self.ct_env = ct_env.lower()
        else:
            self.ct_env = 'agile'
        self.session_user = evars['Session_User']
        auth_server_address = evars['auth_IP']
        if 'auth_Certificate' in evars:
            self.cert_path = evars['auth_Certificate']
            self.password = evars['auth_Password']
            self.user = None
        elif 'auth_User' in evars:
            self.user = evars['auth_User']
            self.password = evars['auth_Password']
            self.cert_path = None
        else:
            trap
        self.device = "ngpcs"
        self.evars = evars
        if evars.has_key('debug') and evars['debug'] == True:
            self.debug = True
        else:
            self.debug = False
        # self.cnx = pycurl.Curl()
        self.url = ''
        self.uri = ''
        self.session = ''
        self.token = ''
        self.session_timer = 0
        self.services = getServiceAliases(self.ct_env)
        self.cb_value = None
        self.error = None
        self.jobID = None
        self.rval = 0
        self.response = None
        self.post_xml = {}
        self.postXML = ''
        self.xml = ''
        self.isensor = None
        self.jump = None
        self.rcode = ''
        self.ignore_error = False
        self.curl_cmd = ''
        self.post_data = ''
        self.cert_curl_cmd = ''
        self.cert_token = ''
        self.session_curl_cmd = ''
        self.session_token = ''
        self.log_test_limit = 256
        self.docroot = evars['DOCROOT']
        self.incidents = {}
        self.service_call_frequency_timer = 0.0  # limit the frequency of service cals so that we can't DOS the CTP back-end
        self.service_call_frequency_limit = 5.0  # don't make service calls more frequent than this

        self.parser = etree.XMLParser(remove_blank_text=True)

        self.svccall = call

        self.default_response_codes = {
            '200': 'OK',
            '201': 'POST Successful',
            '204': 'No Response',
            '400': 'Bad Request',
            '401': 'Unauthorized',
            '403': 'Request Forbidden',
            '404': 'URI Not Found',
            '500': 'Internal Error',
            '501': 'Not Implemented',
            '502': 'Server Busy',
        }
        self.response_codes = self.default_response_codes
        try:
            self.isensor = iSensor(self.ct_env, self.session_user, 'isensor_IP=%s' % self.isensor_IP)
            logging.debug('__init__ - Connected to iSensor at %s' % self.isensor.ip)

        except Exception as error:
            logging.debug('__init__ - Unable to connect to iSensor @ %s \n %s' % (self.isensor_IP, str(error)))
	K = Password(self.TestEnv,self.ATF_User)
	device, self.user, self.password, self.cert_path, self.keypath = K.getCredentials('auth', return_keypath='yes')

    def process_options(self, opts):
        rstr = None
        if 'include' in opts:
            rstr = apply_filters(self.response, opts['include'])

        if 'rcode' in opts and opts['rcode'] == True:
            rstr = '%s\n%s' % (self.rcode, self.response)

        return (rstr)

    def isensorCall(self):
        def __call__(p):
            def iwrap(**kwd):
                if not self.isensor:
                    self.isensor = iSensor()
                p()

            return (iwrap)

    def fetch_idn(self):
        return (self.isensor.idn.rstrip('\n'))

    def fetch_uin(self):
        return (self.isensor.uin.rstrip('\n'))

    def fetch_service_host(self, service):
	server_file = '%s/admin/%s_servers.xml' % (DOCROOT, self.TestEnv.lower())
	servers = etree.parse(server_file)
	hostnode = servers.xpath('//%s' % service)
	assert len(hostnode) > 0, 'The host for the %s service is not in %s ' % (service, server_file)
	if 'name' in  hostnode[0].attrib:
		return(hostnode[0].attrib['name'])
	elif 'address' in  hostnode[0].attrib:
		return(hostnode[0].attrib['address'])
	else:
		raise AssertionError, 'The host for the %s service is missconfigured in %s ' % (service, server_file)
	

    @keyword()
    def Get_Incidents(self):
        return (
        len(self.incidents), ''.join('%s: %s\n' % (incident, self.incidents[incident]) for incident in self.incidents))

    @keyword()
    def Get_iSensor_Info(self):
        assert self.isensor != None
        return (self.isensor)

    @keyword()
    def Refresh_iSensor_Info(self):
        assert self.isensor != None
        self.isensor.uin = self.isensor.cmd('cat /var/iSensor/uin').rstrip('\n')
        self.isensor.idn = self.isensor.cmd('cat /var/iSensor/internal-device-name').rstrip('\n')
        self.isensor.prompt = '[%s]#' % self.isensor.uin
        self.isensor.vprompt = self.isensor.uin + '>'

        for tag in self.isensor.vtags.keys():
            vval = self.isensor.cmd('cat /var/iSensor/%s' % tag)
            self.isensor.vtags[tag] = vval.rstrip('\n')
        rmVersion = self.isensor.cmd(
            "export PATH=$PATH:/secureworks/bin/;/secureworks/bin/sw-info.sh |grep -A 3 Policies |grep Ruleset |pcregrep -o '(\d+\.){4}\d+'")
        self.isensor.vtags['rmVersion'] = rmVersion.rstrip('\n')
        return (self.isensor)

    @keyword()
    def New_Post_XML(self, template=None, **opts):
        if template:
            try:
                f = open(template, 'r')
                try:
                    pxml = etree.parse(template, self.parser)
                except:
                    raise AssertionError, 'template file "%s" is corrupt or malformed' % template
            except IOError:
                try:
                    pxml = etree.fromstring(template, self.parser)
                except:
                    raise AssertionError, 'ERROR:Unable to read template file "%s"' % template
        elif 'root' in opts:
            pxml = E.root()
            pxml.tag = opts['root']
            template = 'postroot'
        elif 'copy' in opts:
            pxml = etree.fromstring(opts['copy'])
            template = 'copy'
        else:
            raise AssertionError, 'Insufficient arguments supplied to create new XML'
        tfd, tfilen = mkstemp(prefix='atf.', suffix=os.path.basename(template))
        self.post_xml[tfilen] = pxml
        f = open(tfilen, 'w')
        f.write(etree.tostring(pxml, pretty_print=True))
        f.close()
        return ('@%s' % tfilen)

    def extract_text_from_nodes(self, nodelist):
        rval = []
        xml = etree.fromstring(self.response)
        for inc in nodelist.split(','):
            xpath = '//%s' % inc
            node = xml.xpath(xpath)
            if len(node) > 0:
                rval.append(node[0].text)
        return (rval)

    @keyword()
    def Inject_XML_Data(self, xmlf, save_as=None, **updates):
        tag = xmlf.lstrip('@')
        assert tag in self.post_xml, 'XML tag is undefined'
        pxml = self.post_xml[tag]
        for update in updates:
            unodes = pxml.xpath('//%s' % update)
            if len(unodes) > 0:
                unode = unodes[0]
            else:
                unode = None
            assert unode != None, 'ERROR: %s does not contain an XML element "%s" to update (%s)' % (
                tag, update, '//%s' % update)
            unode.text = updates[update]
        f = open(tag, 'w')
        f.write(etree.tostring(pxml, pretty_print=True))
        f.close()
        if save_as:
            f = open(save_as, 'w')
            f.write(etree.tostring(pxml, pretty_print=True))
            f.close()
            unlink(tag)
        return ('\n%s\n' % etree.tostring(pxml, pretty_print=True))

    def Remove_Empty_Elements(self, xmlf, save_as=None):
        tag = xmlf.lstrip('@')
        assert tag in self.post_xml, 'XML tag is undefined'
        pxml = clear_empty_nodes(self.post_xml[tag])
        f = open(tag, 'w')
        f.write(etree.tostring(pxml, pretty_print=True))
        f.close()
        if save_as:
            f = open(save_as, 'w')
            f.write(etree.tostring(pxml, pretty_print=True))
            f.close()
            unlink(tag)
        return ('\n%s\n' % etree.tostring(pxml, pretty_print=True))

    def Verify_XML_Elements(self, xml_to_verify, template, **opts):
        if xml_to_verify == None or xml_to_verify == '':
            return ('ERROR: Nothing to verify')
        try:
            template_xml = etree.parse(template, self.parser)
        except:
            return ('ERROR: Template is malformed XML')
        try:
            vroot = etree.fromstring(xml_to_verify, self.parser)
        except:
            return ('ERROR: Data to verify is malformed XML')
        troot = template_xml.getroot()
        if troot.tag != vroot.tag:
            return (
                    'ERROR: Root element "%s" of data does not match template root element "%s"' % (
            vroot.tag, troot.tag))
        estr = ''
        try:
            f = open(self.post_data.lstrip('@'), 'r')
            sent = f.read()
            f.close()
        except IOError:
            sent = 'No POST file'
        for tdescendant in troot.iterdescendants():
            search = vroot.xpath('//%s' % tdescendant.tag)
            regex = tdescendant.text
            if regex != None:
                for content in search:
                    match = re.match(regex, content.text)
                    if match == None or match.group() != content.text:
                        estr += 'Element "%s" contains unexpected content expecting regex "%s"\nSent:\n%s\nXML data received:\n%s\n\n' % (
                            tdescendant.tag, regex, sent, xml_to_verify)
            if len(search) == 0:
                estr += 'Element "%s" from template was not found in XML data\nSent:\n%s\nXML data received:\n%s\n\n' % (
                    tdescendant.tag, sent, xml_to_verify)
                break
        for vdescendant in vroot.iterdescendants():
            search = troot.xpath('//%s' % vdescendant.tag)
            if len(search) == 0:
                estr += 'Element "%s" in XML data was not found in template\nSent:\n%s\nXML data received:\n%s\n\n' % (
                    vdescendant.tag, sent, xml_to_verify)
                break
        if len(estr) > 0:
            return ('ERROR:\n%s' % estr)
        return ('XML Data is VALID')

    def Validate_Against_Schema(self, xml_to_validate, schemafile, **opts):
        if xml_to_validate == None or xml_to_validate == '':
            return ('ERROR: Nothing to validate')
        try:
            schema_xml = etree.parse(schemafile)
            schema = etree.XMLSchema(schema_xml)
        except etree.XMLSchemaParseError as Error:
            return ('ERROR: %s' % Error)
        try:
            f = open(self.post_data.lstrip('@'), 'r')
            sent = f.read()
            f.close()
        except IOError:
            sent = 'No POST file: %s' % self.post_data.lstrip('@')
        try:
            xml = etree.fromstring(xml_to_validate)
            children = xml.getchildren()
            if len(children) > 1:
                for x in range(1, len(children)):
                    xml.remove(children[x])
                xml = etree.fromstring(etree.tostring(xml))
        except:
            return (
                    'ERROR: Data to verify is malformed XML:\nSent:\n%s\nXML data received:\n%s\n\n' % (
                sent, xml_to_validate))
        try:
            schema.assertValid(xml)
        except etree.DocumentInvalid as Error:
            return ('ERROR: %s\nSent:\n%s\nXML data received:\n%s\n\n' % (Error, sent, xml_to_validate))
        return ('XML data received is valid')

    ############################################################################################################
    # Generic Methods for accessing all services
    ###########################################################################################################

    @apiCall()
    def generic_api_call(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename, ignore_error=self.ignore_error)
        return (self.response)

    @keyword()
    def CTP_Service(self, alias, uri, poststr=None, xpath=None):
        self.generic_api_call(uri, poststr, service=alias)
        return (self.response)

    @keyword()
    def CTP_Service_Return_Raw(self, alias, uri, poststr=None):
        self.ignore_error = True
        self.generic_api_call(uri, poststr, service=alias)
        self.ignore_error = False
        return (self.response, self.rcode, self.error, self.curl_cmd)

        ############################################################################################################
        # Methods for accessing the 'pcsms' services
        ###########################################################################################################


class PCSMS(API):
    @keyword()
    def Build_Ruleset_Query(self, category=None, version=None, status=None, snort=None, limit='1', **kwargs):
        predicates = E.predicates()
        if version:
            ver = E.version(E.value(version))
            ver.tag = 'one-of'
            vpred = E.predicate(ver)
            vpred.set('field-name', 'version')
            predicates.insert(0, vpred)
        if status:
            stat = E.stat(E.value(status))
            stat.tag = 'one-of'
            pred = E.predicate(stat)
            pred.set('field-name', 'status')
            predicates.insert(0, pred)
        if category:
            assert category in valid_ruleset_categories, 'Invalid category %s' % category
            cat = E.cat(E.value(category))
            cat.tag = 'one-of'
            pred = E.predicate(cat)
            pred.set('field-name', 'ruleset-category')
            predicates.insert(0, pred)
        if snort:
            sver = E.sver(E.value(snort))
            sver.tag = 'one-of'
            pred = E.predicate(sver)
            pred.set('field-name', 'snort-version')
            predicates.insert(0, pred)

        iir = E.iir()
        iir.tag = 'include-in-response'
        for field in ['id', 'ruleset-category', 'status', 'import-date', 'version', 'snort-version', 'new-rules',
                      'modified-rules', 'removed-rules']:
            tag = E.tag(field)
            iir.append(tag)
        order = E.order()
        order.set('field-name', 'import-date')
        order.set('order', 'DESC')
        order.tag = 'sort-order'
        sort = E.sort(order)
        sort.tag = 'sort-ordering'
        lim = E.limit(limit)
        rsq = E.tmptag(predicates, iir, sort, lim)
        rsq.tag = 'ruleset-query'
        tfd, tfname = mkstemp(prefix='atf.rsquery', suffix='.xml')
        with open(tfname, 'w') as f:
            f.write(etree.tostring(rsq, pretty_print=True))
        return (tfname)

    @apiCall()
    def pcsms(self, cmdstr, pars):
        # print '-------------\n%s\n--------------------' % cmdstr
        """
        with open('/tmp/curl.out', 'a') as w:
                w.write('CURL COMMAND (call to pcsms svc):%s\n%s\n%s\n\n' % (NOW(),cmdstr, '-' * 80))
                w.write('POST DATA sent to pcsms service:\n%s\n%s\n\n' % (self.postXML, '-' * 80))
        """
        timeout = time() + CTP_ERROR_WAITTIME
        sleep_interval = 12
        retry_attempts = 0
        while time() < timeout:
            try:
                logging.debug('attempting service call to PCS services')
                self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd, close_fds=True)
                if self.service_call_frequency_timer > time():
                    sleep(self.service_call_frequency_timer - time())
                    self.service_call_frequency_timer = time() + self.service_call_frequency_limit
                logging.debug('validating response received from service')
                self.response = self.error = self.rcode = ''
                self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                                      self.error_filename, object=self)
                self.__dict__['last_server_error'] = '\nrcode %s:\nerror \n%s' % (self.rcode, self.error)
                """
    # this is used only for testing CTP BO errors...comment out if in production
                if retry_attempts < os.environ[MAX_RETRY_ATTEMPTS]: # fake an error
                        self.rcode = self.rcode.replace('200','404').replace('202','404')
                """
                assert self.rcode.startswith('20'), self.rcode

                logging.debug('response validation completed without exception or incident')
                break
            except Exception as estr:
                assert 'no_retries' not in pars, estr
                self.rcode = str(estr).rstrip('\r') if self.rcode == '' else self.rcode
                trap_codes = ERRORS_TO_RETRY + ERRORS_TO_RETURN_AS_INCIDENTS
                logging.debug('will trap on return codes %s' % str(trap_codes))

                is_incident = False
                is_retry = False
                trap_code_match = re.match('^\d{3}', self.rcode)
                assert trap_code_match != None, '\n%s:' % (self.rcode)
                trap_code = trap_code_match.group()
                for code in ERRORS_TO_RETURN_AS_INCIDENTS:
                    if trap_code == code:
                        logging.debug('response validation incountered an incident')
                        self.response = 'INCIDENT: %s' % self.rcode
                        self.error = self.rcode
                        is_incident = True
                        break
                if is_incident == True:
                    break
                for code in ERRORS_TO_RETRY:
                    if trap_code == code:
                        is_retry = True
                        break

                if is_retry != True:
                    raise AssertionError, 'Received ERROR from CTP BO server: %s\n%s' % (self.rcode, estr)

                """
                assert re.match('^\d{3}', self.rcode) != None, '\n%s:' % (self.rcode)
                            try:
                    is_in_list = trap_codes.index(re.match('^\d{3}', self.rcode).group()) >= 0
                except ValueError:
                    raise AssertionError, '%s\n%s' % (self.rcode, estr)
                if ERRORS_TO_RETURN_AS_INCIDENTS.index(re.match('^\d{3}', self.rcode).group()) >= 0:
                                logging.debug('response validation incountered an incident')
                    self.response = 'INCIDENT: %s' % self.rcode
                    self.error = self.rcode
                    break
                """

                retry_attempts += 1
                logging.debug('retry_attempts %d' % retry_attempts)
                self.incidents[
                    self.rcode.rstrip('\r')] = 'CTP core services responded with the error on %d attempts out of %d' % (
                    retry_attempts, MAX_RETRY_ATTEMPTS)
                os.close(self.outfd)
                os.unlink(self.response_filename)
                os.close(self.errfd)
                os.unlink(self.error_filename)
                self.__dict__['outfd'], self.__dict__['response_filename'] = mkstemp(prefix='retry', suffix='out')
                self.__dict__['errfd'], self.__dict__['error_filename'] = mkstemp(prefix='retry', suffix='err')
                self.response = None

                logging.error(
                    'service responded with an error on attempt %d of %d...pausing for %d seconds before retry\n\t%s' % (
                        retry_attempts, MAX_RETRY_ATTEMPTS, sleep_interval, str(estr)))
                if retry_attempts > MAX_RETRY_ATTEMPTS:
                    raise AssertionError, '%s...FATAL_ERROR...retries to access CTP service exceeded limit of %d' % (
                    self.rcode, MAX_RETRY_ATTEMPTS)
                sleep(sleep_interval)
                sleep_interval += 12

    def show_post(self):
        if self.post_data == '':
            return ('No post data')
        if not self.post_data.startswith('@'):
            return (self.post_data)
        try:
            with open(self.post_data.lstrip('@'), 'r') as f:
                return (f.read())
        except Exception as estr:
            return (str(estr))

    def getJobID(self):
        if not self.rcode.startswith('20'):
            logging.debug('2XX response for JobID: %s' % self.error)
            logging.debug('\nresponse=\n%s' % self.response)
            return (-1)
        locstr = re.findall('Location:.*', self.error)
        if len(locstr) == 0:
            jxml = etree.fromstring(self.response, PARSER)
            jobidnode = jxml.find('job-id')
            if jobidnode == None:
                logging.debug('Invalid XML to parse for JobID: %s' % self.error)
                logging.debug('\nresponse=\n%s' % self.response)
                return (-2)
            else:
                return (int(jobidnode.text))
        logging.debug('Valid XML for JobID: %s' % self.error)
        loc = locstr[len(locstr) - 1].rstrip('\n')
        try:
            jobx = loc.index('job') + 4
        except ValueError:
            return (-3)
        self.jobID = int(loc[jobx:])
        return (int(loc[jobx:]))

    @keyword()
    def CTP_Get_PCSMS(self, uri):
        self.pcsms(uri)
        return (self.response)

    @keyword()
    def CTP_Post_PCSMS(self, uri, poststr=None, **opts):
        if poststr != None:
            self.pcsms(uri, poststr, **opts)
        else:
            self.pcsms(uri, '', POST='empty')
        return (self.response)

    @keyword()
    def CTP_Put_PCSMS(self, uri, data='', **opts):
        putargs = []
        if 'PUT' in opts:
            putargs.extend(opts['PUT'])
        self.pcsms(uri, data, PUT=True)
        return (self.response)

    @keyword()
    def Get_Job_Status(self, jobID=None, **opts):
        if jobID == None:
            jobint = self.getJobID()
        else:
            try:
                jobint = int(jobID)
            except:
                raise AssertionError, 'Specified Job ID is not an integer'
        if jobint < 0:
            return ('Status Unknown (%s)' % str(jobID))
        uri = 'job/summary/%s' % jobID
        self.CTP_Get_PCSMS(uri)
        try:
            xml = etree.fromstring(self.response)
            logging.debug('status response:\n%s' % self.response)
        except:
            return ('Unable to retrieve status for job %s' % jobID)
        if 'rawXML' in opts:
            return (self.response)
        snodes = xml.xpath('//status-text')
        if len(snodes) == 0:
            snodes = xml.xpath('//status')
            if len(snodes) == 0:
                return ('Status was not returned')
        statusnode = snodes[0]
        status = statusnode.text
        if 'includeID' in opts:
            return ('%s %s' % (jobID, status))
        return (status)

    @keyword()
    def Get_Job_Log(self, jobID=None, **opts):
        if jobID == None:
            jobint = self.getJobID()
        else:
            try:
                jobint = int(jobID)
            except:
                raise AssertionError, 'Specified Job ID is not an integer'
        if jobint < 0:
            return ('Status Unknown (%s)' % str(jobID))
        uri = 'job/logs/%s' % jobID
        log = self.CTP_Get_PCSMS(uri)
        try:
            xml = etree.fromstring(log)
        except:
            return ('Unable to retrieve log for job %s' % jobID)
        rval = ''
        log_entries = xml.iterchildren('log-entry')
        while True:
            try:
                log_entry = log_entries.next()
                log_data = log_entry.iterchildren()
                while True:
                    try:
                        datum = log_data.next()
                        rval += '%s ' % datum.text.rstrip('\n')
                        continue
                    except StopIteration:
                        rval += '\n'
                        break
                continue
            except StopIteration:
                break
        if 'Ruleset check failed' in rval and self.isensor != None:
            checkstr = self.isensor.cmd('grep ERROR /secureworks/log/sw-check-snort-ruleset.log |tail -1')
            rval += 'Error found in iSensor sw-check-snort-ruleset.log:\n%s' % checkstr
        return (rval)

    @keyword()
    def Get_Ruleset_Groups(self, category, version, **opts):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        uri = 'ruleset/%s/%s' % (category, version)
        try:
            self.CTP_Get_PCSMS(uri)
        except AssertionError as why:
            return (' :ERROR Could not retrieve ruleset details for %s.%s: %s' % (category, version, why))
        if 'return_raw' in opts and opts['return_raw'] == True:
            return (self.response)
        try:
            xml = etree.fromstring(self.response)
        except:
            return ('ERROR parsing PCSMS response:\n"%s"' % self.response)
        group_list = []
        if not 'group' in opts:
            groups = xml.xpath('//rule-group/file')
            for group in groups:
                if 'group' in opts and group.text in opts['group'].split(','):
                    group_list.append(group.text)
                else:
                    group_list.append(group.text)
        if 'pretty_print' in opts and opts['pretty_print'] == True:
            return ''.join('%s\n' % g for g in group_list)
        return (group_list)

    @keyword()
    def Add_Shun(self, uin=None, address_list=None, **opts):
        uri = 'policy/firewall/shun'
        opts.update({'action': 'add'})
        try:
            shun_xml = self.configure_shun(uin, address_list, **opts)
        except AssertionError as estr:
            logging.error(str(estr))
            return ('failed to add shun...%s' % str(estr))
        logging.debug(shun_xml)
        fd, fn = mkstemp(prefix='atf.ctpapi', suffix='out')
        with open(fn, 'w') as f:
            f.write(shun_xml)
        try:
            rval = self.CTP_Post_PCSMS(uri, '"@%s"' % fn)
        except AssertionError as estr:
            return ('ERROR:\n\t' + str(estr))
        os.unlink(fn)
        return ('Successfully added shun for address(es) %s on %s (%s)' % (address_list, uin, fn))

    @keyword()
    def Remove_Shun(self, uin=None, address_list=None, **opts):
        uri = 'policy/firewall/unshun'
        opts.update({'action': 'remove'})
        try:
            shun_xml = self.configure_shun(uin, address_list, **opts)
        except AssertionError as estr:
            logging.error(str(estr))
            return ('failed to remove shun...%s' % str(estr))
        logging.debug(shun_xml)
        fd, fn = mkstemp(prefix='atf.ctpapi', suffix='out')
        with open(fn, 'w') as f:
            f.write(shun_xml)
        try:
            rval = self.CTP_Post_PCSMS(uri, '"@%s"' % fn)
        except AssertionError as estr:
            return ('ERROR:\n\t' + str(estr))
        os.unlink(fn)
        return ('Successfully removed shun for address(es) %s on %s (%s)' % (address_list, uin, fn))

    def Sync_Policy(self, **opts):
        assert self.isensor != None
        uri = 'policies/%s' % self.isensor.idn
        xml = E('isensor-policy',
                E('command-execution-devices',
                  E('command-execution-device',
                    E.uin(self.isensor.uin)
                    )
                  ),
                E('application-component', 'shun'),
                E('wait-for-return', '0')
                )
        xml_text = etree.tostring(xml, pretty_print=True)
        print xml_text
        resp = self.CTP_Post_PCSMS(uri, xml_text)
        return (resp)

    @keyword()
    def Get_Shuns(self, **opts):
        assert self.isensor != None
        uri = 'policies/shun-addresses/%s' % self.isensor.idn
        try:
            shun_xml = self.CTP_Get_PCSMS(uri)
        except Exception as estr:
            return (str(estr))
        shuns = etree.fromstring(shun_xml)
        shun_addresses = shuns.xpath('//ip-address')
        rval = ''.join('%s,' % s.text for s in shun_addresses)
        if 'search_for' in opts:
            found = []
            search_for = opts['search_for'].split(',')
            for address in rval.rstrip(',').split(','):
                if address in search_for:
                    found.append(address)
            rval = ''.join('%s,' % a for a in found)
        return (rval.rstrip(','))

    def configure_shun(self, uin, address_list=None, **opts):
        import ipaddress
        declaration = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        set_if_assert = lambda a, default: '1' if opts[a] == 'yes' or opts[a] == True else default
        unset_if_reset = lambda a, default: '0' if opts[a] == 'no' or opts[a] == False else default
        assert uin != None, 'ERROR:no UIN was supplied with the keyword'
        assert address_list != None, 'ERROR:no address(es) were supplied with the keyword'
        force = '0'
        if 'force' in opts:
            force = set_if_assert('force', force)
        assert force == '0' or force == '1', 'ERROR:invalid "force" value "%s"' % force
        monitor = '1'
        if 'monitor_logging' in opts:
            monitor = unset_if_reset('monitor_logging', monitor)
        assert monitor == '0' or monitor == '1', 'invalid "monitor_logging" value "%s"' % monitor
        protocol = None
        if 'protocol' in opts:
            protocol = opts['protocol']
        ports = None
        if 'ports' in opts:
            ports = opts['ports']
        addresses = address_list.split(',')
        blocks = E.blocks()
        for address in addresses:
            try:
                if '/' in address:
                    valid_addr = ipaddress.ip_network(unicode(address.strip('\t ')))
                else:
                    valid_addr = ipaddress.ip_address(unicode(address.strip('\t ')))
            except ValueError:
                raise AssertionError, 'ERROR:invalid ip address format "%s"' % address
            shun = E('shun-entry', E.address(address.strip('\t ')))
            if ports != None:
                shun.append(E.port(ports.strip('\t ')))
            if protocol != None:
                shun.append(E.protocol(protocol.strip('\t ')))
            shun.append(E('type', opts['action']))
            blocks.append(shun)

        assert monitor == '0' or monitor == '1', 'bad monitor_logging value'
        shun_xml = E('firewall-modification', E.force(force), E.uin(uin), blocks, E('monitor-logging', monitor))
        return (etree.tostring(shun_xml, pretty_print=True))

    @keyword()
    def Set_AMPD(self, uin, state, **opts):
        assert state.lower() in ['enable', 'disable']
        uri = 'engine-customizations/AMPD'
        s = state.upper()
        uin_node = E.uins(uin)
        action_node = E.action(s)
        xml = E('engine-customizations-AMPD', uin_node, action_node)
        xmlstr = etree.tostring(xml, pretty_print=True)
        logging.debug('sending request to %s AMPD for UIN: %s\n%s' % (s, uin, xmlstr))
        try:
            self.CTP_Post_PCSMS(uri, xmlstr)
        except Exception as estr:
            rval = 'ERROR: unable to set AMPD: %s' % estr
            logging.error('%s\n%s' % (rval, self.response))
            return (rval)
        return ('Setting AMPD to %s for UIN:%s succeeded' % (s, uin))

    @keyword()
    def Import_Ruleset(self, category, version, **opts):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        uri = 'ruleset/import/%s/%s' % (category, version)
        try:
            self.CTP_Post_PCSMS(uri, '', no_retries=True)
        except AssertionError as why:
            if 'same Category and Version exists' in str(why):
                return (' :ADVISORY...import ruleset %s.%s: %s' % (category, version, str(why).rstrip('\r')))
            else:
                return (' :ERROR importing ruleset %s.%s: %s' % (category, version, why))
        if 'wait' in opts:
            expire_after = RFTime(opts['wait'])
        else:
            expire_after = 2400
        timeout = time() + expire_after
        retries = 0
        while time() < timeout:
            sleep(10)
            try:
                status = self.Get_Ruleset_Status(category, version)
            except AssertionError as why:
                status = str(why)
                if 'No ruleset record was found' in str(why) and 'second_attempt' in opts:
                    raise AssertionError, ' :Import of ruleset %s.%s failed after second attempt' % (category, version)
                elif '401' in status:
                    logging.debug('Received spurious 401 auth error TLN-10021...continuing to wait for Imported state')
                    continue
            if status == None:
                logging.debug('PCSMS service returned no status')
                continue
            if status == 'IMPORTING':
                logging.debug('Ruleset is still in importing state...continuing to wait for Imported state')
                continue
            elif status == 'IMPORTED':
                return (' :Ruleset %s.%s was successfully imported' % (category, version))
            elif '401' in status:
                logging.debug('Received spurious 401 auth error TLN-10021..continuing to wait for Imported state')
                continue
            elif '404' in status:  # an error occurred upstream in the pcsworker so let's try an import a second time
                retries += 1
                self.incidents['Import Failure (attempt %d)' % retries] = status
                assert retries < 2, 'ERROR:Unable to import ruleset after second attempt'
                sleep(120)
                timeout = time() + expire_after
                self.CTP_Post_PCSMS(uri, '', no_retries=True)
                continue
            else:
                return (' :Import of ruleset %s.%s returned "%s" status' % (category, version, status))

        return (' :Import of ruleset %s.%s is still in progress after %s minutes' % (
        category, version, int(expire_after)))

    @keyword()
    def Wait_For_Job_To_Complete(self, timestr='30s', intervalstr='5s', success='job completed SUCCESSfully',
                                 fail='job FAILED', **opt):
        job = self.getJobID()
        assert job > 0, self.rcode
        default_waittime = 15.0
        jobID = str(job)
        waittime = RFTime(timestr)
        interval = RFTime(intervalstr)
        logging.debug('waiting %4.1f for deployment result' % waittime)
        timeout = time() + waittime
        while timeout > time():
            status = self.Get_Job_Status(jobID, includeID=True)
            if status == 'SUCCESS':
                logging.info('%s:%s' % (jobID, success))
                return (False, '%s:%s' % (jobID, success))
            elif status == 'FAILED':
                log = self.Get_Job_Log(jobID)
                logging.error('%s:%s\n' % (jobID, log))
                return (True, 'ERROR:%s:%s\n%s' % (jobID, fail, log))
            sleep(interval)
        return (None, '%s:Timed out waiting for job completion' % jobID)

    @keyword()
    def Deploy_Ruleset(self, category, version, uin, policy='1', **opt):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        current_version, rsid = self.Get_Ruleset_Info(category, version, include='id')
        logging.info('Deploying ruleset "%s.%s" (policy %s) to UIN %s' % (category, version, policy, uin))
        if 'use_id' in opt and opt['use_id'] == True:
            self.CTP_Post_PCSMS('ruleset/%s/deploy/%s' % (rsid, uin))
        else:
            self.CTP_Post_PCSMS('ruleset/deploy/%s/%s/%s/%s' % (category, version, uin, policy))
        job = self.getJobID()
        assert job > 0, self.rcode
        # if job <=0:
        #    return('-1:%s' % self.rcode)
        default_waittime = 1200.0
        jobID = str(job)
        if not 'no_wait' in opt or opt['no_wait'] == False:
            try:
                waittime = float(opt['waittime'])
            except:
                waittime = default_waittime
                logging.debug('Using default waittime')
            logging.debug('waiting %4.1f for deployment result' % waittime)
            timeout = time() + waittime
            while timeout > time():
                status = self.Get_Job_Status(jobID)
                if status == 'SUCCESS':
                    # log = self.Get_Job_Log(jobID)
                    logging.info('Deployment of ruleset "%s.%s" (policy %s) to UIN %s succeeded' % (
                        category, version, policy, uin))
                    return ('%s:Deployment of ruleset "%s.%s" (policy %s) to UIN %s succeeded' % (
                        jobID, category, version, policy, uin))
                elif status == 'FAILED':
                    log = self.Get_Job_Log(jobID)
                    logging.error('ERROR:Deployment of ruleset "%s.%s" (policy %s) to UIN %s failed:\n%s' % (
                        category, version, policy, uin, log))
                    return ('ERROR:%s:%s\n%s' % (jobID, status, log))
                sleep(5)
            return ('%s:Timed out waiting for deployment completion' % jobID)

        else:
            return (jobID)

    @keyword()
    def Rollback_Ruleset(self, category, version, uin, **opt):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        self.CTP_Put_PCSMS('ruleset/deploy/rollback/%s/%s/%s' % (category, version, uin))

    @keyword()
    def Activate_Ruleset(self, category, version, **opt):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        self.CTP_Put_PCSMS('ruleset/activate/%s/%s' % (category, version))

    @keyword()
    def Deactivate_Ruleset(self, category, version, **opt):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        self.CTP_Put_PCSMS('ruleset/deactivate/%s/%s' % (category, version))

    @keyword()
    def Get_Rulesets_By_Status(self, status=None, limit='3'):
        assert status in valid_ruleset_status, 'Invalid Status'
        assert type(limit) == str, '"limit" must be a string'
        post = self.Build_Ruleset_Query(None, None, status, limit=limit)
        self.CTP_Post_PCSMS('ruleset/ruleset-query', '@%s' % post)
        os.unlink(post)
        rval = []
        xml = etree.fromstring(self.response)
        rsets = xml.xpath('//ruleset')
        for rset in rsets:
            version = rset.find('version')
            idate = rset.find('import-date')
            cat = rset.find('ruleset-category')
            rval.append('%s\t%s\t%s\t' % (idate.text, version.text, cat.text))
        rstr = ''.join('%s\n' % s for s in rval)
        return (rstr.rstrip('\n'))

    @keyword()
    def Get_Latest_Ruleset_Version(self, category=None, status='AVAILABLE', snort=None, **opts):
        logging.debug(
            'ctpapi.py:class PCSMS:Get_Latest_Ruleset_Version - called with category=%s, status=%s, snort=%s, opts=%s' % (
                category, status, snort, opts))
        assert status in valid_ruleset_status, 'Invalid ruleset status: "%s" expected one of...%s' % (
            status, ''.join('"%s", ' % s for s in valid_ruleset_status))
        post = self.Build_Ruleset_Query(category, None, status, snort)
        self.CTP_Post_PCSMS('ruleset/ruleset-query', '@%s' % post)
        os.unlink(post)
        if opts.has_key('raw_xml') and opts['raw_xml'] == True:
            return (self.response)
        rval = []
        xml = etree.fromstring(self.response)
        ver = xml.xpath('//version')
        if len(ver) == 0:
            return ('0.0.0.0')
        if not opts.has_key('include'):
            return (ver[0].text)
        rval.append(ver[0].text)
        rval.extend(self.extract_text_from_nodes(opts['include']))
        return (rval)

    @keyword()
    def Get_Ruleset_Info(self, category=None, version=None, **opts):
        assert version != None, 'version was not supplied'
        post = self.Build_Ruleset_Query(category, version)
        self.CTP_Post_PCSMS('ruleset/ruleset-query', '@%s' % post)
        os.unlink(post)
        if opts.has_key('raw_xml') and opts['raw_xml'] == True:
            return (self.response)
        rval = []
        xml = etree.fromstring(self.response)
        st = xml.xpath('//status')
        assert len(st) > 0, 'Version %s does not exist in the %s category' % (version, category)
        if not opts.has_key('include'):
            return (st[0].text)
        rval.append(st[0].text)
        rval.extend(self.extract_text_from_nodes(opts['include']))
        return (rval)

    @keyword()
    def Get_Current_Ruleset_Subscription(self, uin=None, **opts):
        rval = self.Get_Ruleset_Subscription(uin, 'current',
                                             include='ruleset-category, current-snort-version, current-release')
        if 'csv' in opts:
            rs, cat, m_ver, iver = rval.split(',')
            rs_ver = rs.replace('%s.' % cat, '')
            return (rs_ver, cat)
        return (rval)

    @keyword()
    def Get_Target_Ruleset_Subscription(self, uin=None, **opts):
        rval = self.Get_Ruleset_Subscription(uin, 'target',
                                             include='ruleset-category, target-snort-version, current-release')
        if 'csv' in opts:
            rs, cat, iver = rval.split(',')
            rs_ver = rs.replace('%s.' % cat, '')
            return (rs_ver, cat)
        return (rval)

    @keyword()
    def Get_Previous_Ruleset_Subscription(self, uin=None, **opts):
        logging.debug(str(opts))
        rval = self.Get_Ruleset_Subscription(uin, 'previous',
                                             include='ruleset-category, previous-snort-version, current-release')
        if 'csv' in opts:
            rs, cat, iver = rval.split(',')
            rs_ver = rs.replace('%s.' % cat, '')
            return (rs_ver, cat)
        return (rval)

    @keyword()
    def Get_Ruleset_Subscription_XML(self, uin=None, **opts):
        if uin == None:
            uin = self.isensor.uin
        if 'policy' in opts:
            uri = 'ruleset-subscription/%s/%s' % (uin, opts['policy'])
        else:
            uri = 'ruleset-subscriptions/%s' % uin
        self.CTP_Get_PCSMS(uri)
        return (self.response)

    @keyword()
    def Add_Group_Customization(self, uin=None, group=None, deploy=False, policy='1', **opts):
        assert uin != None, 'ERROR - UIN cannot be None'
        assert group != None, 'ERROR:group cannot be None'
        # self.deploy_undeployed_customizations(uin, True, policy)
        uri = 'customizations/rule-group/%s/%s/%s' % (uin, policy, group)
        if 'enabled' in opts:
            enabled = '1' if opts['enabled'] == True else '0'
        else:
            enabled = '0'
        xml = E('rule-group-customization', E.enabled(enabled))
        try:
            rval = self.CTP_Post_PCSMS(uri, etree.tostring(xml))
        except Exception as error:
            if 'has undeployed Customizations' in str(error):
                self.deploy_undeployed_customizations(uin, True, policy)
                return (self.Add_Group_Customization(uin, group, deploy, policy))
            raise AssertionError, str(error)
        if deploy == True:
            rval = self.Deploy_Customizations(uin, category, version)
            if 'ERROR' in rval:
                return ('ERROR: Deploying Group Customization %s - %s' % (group, rval))
            rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200')
            if 'ERROR' in rval:
                return ('ERROR: Verifying Group Deployment %s - %s' % (group, rval))
        return (rval)

    @keyword()
    def Add_Ruleset_Variable(self, uin=None, var_name=None, var_value=None, deploy=False, policy='1', **opts):
        assert uin != None, 'ERROR - UIN cannot be None'
        assert var_name != None, 'ERROR - variable name cannot be None'
        # self.deploy_undeployed_customizations(uin, deploy, policy)
        customized_variables = self.Get_Ruleset_Customizations(uin, 'variables', policy)
        try:
            vxml = etree.fromstring(customized_variables)
            existing = vxml.xpath('//rule-variable-customization[variable="%s"]' % var_name)
            assert len(existing) == 0, 'Variable already exist'
        except AssertionError:
            return (self.Update_Ruleset_Variable(uin, var_name, var_value, deploy, policy))
        except Exception as error:
            return ('ERROR: %s' % str(error))
        uri = 'customizations/rule-variable/%s/%s/%s' % (uin, policy, var_name)
        xml = E('rule-variable-customization', E('new-value', '%s' % var_value))
        try:
            rval = self.CTP_Post_PCSMS(uri, etree.tostring(xml))
        except Exception as error:
            if 'has undeployed Customizations' in str(error):
                self.deploy_undeployed_customizations(uin, True, '1')
                return (Add_Ruleset_Variable(uin, var_name, var_value, deploy, policy))
            raise AssertionError, str(error)
        if deploy == True:
            subxml = etree.fromstring(self.Get_Ruleset_Subscription_XML(uin))
            category = subxml.xpath('//current-ruleset/category')[0].text
            version = subxml.xpath('//current-ruleset/version')[0].text
            rval = self.Deploy_Customizations(uin, category, version)
            if not 'ERROR' in rval:
                rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200')
                if not 'ERROR' in rval:
                    return ('Deployment of variable "%s" update to value "%s" was successful' % (var_name, var_value))
        if not 'ERROR' in rval:
            return ('Addition of variable "%s" with value "%s" was successful' % (var_name, var_value))
        return ('ERROR: Adding ruleset variable: %s' % rval)

    def deploy_undeployed_customizations(self, uin, deploy=True, policy='1'):
        if deploy == False:
            return
        customizations = self.Get_Ruleset_Customizations(uin, 'all')
        undeployed = False

        if 'undeployed' in customizations or 'Undeployed' in customizations:
            subxml = etree.fromstring(self.Get_Ruleset_Subscription_XML(uin))
            category = subxml.xpath('//current-ruleset/category')[0].text
            version = subxml.xpath('//current-ruleset/version')[0].text
            rval = self.Deploy_Customizations(uin, category, version)
            if not 'ERROR' in rval:
                rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200')
                if not 'ERROR' in rval:
                    logging.debug('Previously undeployed customizations have been deployed')
                logging.debug(rval)

        else:
            logging.debug('No previous customizations to deploy')

    @keyword()
    def Update_Ruleset_Variable(self, uin=None, var_name=None, var_value=None, deploy=True, policy='1', **opts):
        assert uin != None, 'ERROR - UIN cannot be None'
        assert var_name != None, 'ERROR - variable name cannot be None'
        customized_variables = self.Get_Ruleset_Customizations(uin, 'variables')
        logging.debug(customized_variables)
        try:
            vxml = etree.fromstring(customized_variables)
            logging.debug('parsed:%s' % vxml.tag)
        except Exception as error:
            logging.error('ERROR: ???%s??? - %s' % (customized_variables, str(error)))
            return ('ERROR: ???%s??? - %s' % (customized_variables, str(error)))
        try:
            logging.debug('//rule-variable-customization[variable="%s"]' % var_name)
            existing = vxml.xpath('//rule-variable-customization[variable="%s"]' % var_name)
            logging.debug('existing=%s' % str(existing))
            if len(existing) == 0:
                logging.error('ERROR: Variable "%s" does not currently exist...use "Add Ruleset Variable' % var_name)
                return ('ERROR: Variable "%s" does not currently exist...use "Add Ruleset Variable' % var_name)
        except Exception as error:
            logging.error('ERROR: ??(%s)%s?? %s' % (existing, etree.tostring(vxml), str(error)))
            return ('ERROR: ??(%s)%s?? %s' % (existing, etree.tostring(vxml), str(error)))
        existing_var = existing[0]
        try:
            current_value = existing_var.find('new-value').text == var_value
        except AttributeError:
            current_value = None
        current_state = existing_var.find('state').text
        if current_value == var_value:
            if current_state == 'Deployed':
                logging.info(
                    'Variable %s is already set to %s and has been deployed...no action taken' % (var_name, var_value))
                return (
                        'Variable %s is already set to %s and has been deployed...no action taken' % (
                var_name, var_value))
        logging.info(
            'Updating "%s" from current value of "%s" to new value of "%s"' % (var_name, current_value, var_value))
        undeployed = existing_var.find('undeployed-value')
        subxml = etree.fromstring(self.Get_Ruleset_Subscription_XML(uin))
        category = subxml.xpath('//current-ruleset/category')[0].text
        version = subxml.xpath('//current-ruleset/version')[0].text
        if undeployed != None:
            if var_value == undeployed.text:
                if deploy == True:
                    self.Deploy_Customizations(uin, category, version)
                    rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200')
                    if not 'ERROR' in rval:
                        logging.info(
                            'Deployment of variable "%s" update to value "%s" was successful' % (var_name, var_value))
                        return (
                                'Deployment of variable "%s" update to value "%s" was successful' % (
                        var_name, var_value))
                    return (rval)
                else:
                    logging.info(
                        'Variable %s is already set to %s but has yet to be deployed (use option "deploy=True")' % (
                            var_name, var_value))
                    return ('Variable %s is already set to %s but has yet to be deployed (use option "deploy=True")' % (
                        var_name, var_value))
            logging.error('ERROR:Unable to set "%s" due to current undeployed state of the variable' % var_name)
            return ('ERROR:Unable to set "%s" due to current undeployed state of the variable' % var_name)
        xml = E('rule-variable-customization', E('new-value', '%s' % var_value))
        uri = 'customizations/rule-variable/%s/%s/%s' % (uin, policy, var_name)
        try:
            rval = self.CTP_Post_PCSMS(uri, etree.tostring(xml))
        except Exception as error:
            if 'has undeployed Customizations' in str(error):
                self.deploy_undeployed_customizations(uin, deploy=True, policy='1')
                return (Update_Ruleset_Variable(uin, var_name, var_value, True, policy))
            raise AssertionError, str(error)
        if deploy == True:
            self.Deploy_Customizations(uin, category, version)
            rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200')
            if not 'ERROR' in rval:
                return ('Deployment of variable "%s" update to value "%s" was successful' % (var_name, var_value))
        return (rval)

    @keyword()
    def Deploy_Customizations(self, uin=None, category=None, version=None, policy=1, **opts):
        assert uin != None, 'ERROR - UIN cannot be None'
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        logging.info('Deploying %s.%s customizations to UIN: %s' % (category, version, uin))
        uri = 'deploy/customizations/%s/%s/%s' % (category, version, uin)
        rval = self.CTP_Post_PCSMS(uri, '')

        job = self.getJobID()
        assert job > 0, self.rcode
        jobID = str(job)
        default_waittime = 1200.0
        if not 'no_wait' in opts or opts['no_wait'] == False:
            try:
                waittime = float(opts['waittime'])
            except:
                waittime = default_waittime
                logging.debug('Using default waittime')
            logging.debug('waiting %4.1f for deployment result' % waittime)
            timeout = time() + waittime
            while timeout > time():
                status = self.Get_Job_Status(jobID)
                if status == 'SUCCESS':
                    # log = self.Get_Job_Log(jobID)
                    logging.info('Deployment of customizations for "%s.%s" (policy %s) to UIN %s succeeded' % (
                        category, version, policy, uin))
                    return ('%s:Deployment of customizations for "%s.%s" (policy %s) to UIN %s succeeded' % (
                        jobID, category, version, policy, uin))
                elif status == 'FAILED':
                    log = self.Get_Job_Log(jobID)
                    logging.error('ERROR:Deployment of customizations for "%s.%s" (policy %s) to UIN %s failed:\n%s' % (
                        category, version, policy, uin, log))
                    return ('ERROR:%s:%s\n%s' % (jobID, status, log))
                sleep(5)
            return ('%s:Timed out waiting for deployment completion' % jobID)

        else:
            return (jobID)

        sleep(30)
        return (rval)

    def extract_incident_from_isensor_log(self, regex, log, tail_value="-1", **opts):
        from ctpapi import iSensor as target

        try:
            I = self.isensor  # target(self.ct_env.capitalize(), self.session_user, self.test_vars)
            incident = I.cmd('pcregrep %s /secureworks/log/%s |tail %s' % (regex, log, tail_value))
        except Exception as estr:
            incident = 'Unable to retrieve incident from %s (%s)' % (log, str(estr))
        return (incident)

    @keyword()
    def Verify_Customizations_Deployed(self, uin=None, policy='1', **opts):
        assert uin != None, 'ERROR: UIN cannot be None'
        job = self.getJobID()
        default_waittime = 1200
        if 'wait' in opts:
            try:
                waittime = int(opts['wait'])
            except:
                logging.info('PCSMS::Verify_Group_Customizations - invalid "wait" time specification')
                waittime = default_waittime
        else:
            waittime = default_waittime
        action = '%s and ' % opts['action'] if 'action' in opts else ''
        successful_deployment = 'All customizations have been %sdeployed...' % action
        failed_deployment = 'ERROR - customizations failed to deploy...error return from pcsms service'
        timed_out = 'ERROR - timed out waiting for customizations to deploy after %d seconds' % waittime
        expired = int(time()) + waittime
        logging.info('Waiting up to %s seconds for customizations to to deploy' % (waittime))
        while int(time()) < expired:
            deployed = True
            log_trace = self.Get_Job_Log(job)
            if 'Error' in log_trace:
                deploy_error = self.extract_incident_from_isensor_log('ERROR', 'sw-snort-test-on-install.log')
                return (
                        failed_deployment + '\n' + log_trace + '\n' + '...info retrieved from sw-snort-test-on-install.log:\n' + deploy_error)
            if not 'Job is success' in log_trace:
                sleep(30)
                continue
            logging.debug(log_trace)
            grpxml = etree.fromstring(self.Get_Ruleset_Customizations(uin))
            grpnodes = grpxml.iterdescendants('rule-group')
            while True:
                try:
                    group = grpnodes.next()
                    try:
                        state = group.itersiblings('state').next().text
                        if state != 'Deployed':
                            deployed = False
                            break
                    except StopIteration:
                        logging.info('PCSMS::Verify_Group_Customizations - group missing "state" node')
                        continue
                except StopIteration:
                    break
            varxml = etree.fromstring(self.Get_Ruleset_Customizations(uin, 'variables'))
            varnodes = varxml.iterdescendants('variable')
            while True:
                try:
                    var = varnodes.next()
                    try:
                        state = var.itersiblings('state').next().text
                        if state != 'Deployed':
                            deployed = False
                            break
                    except StopIteration:
                        logging.info('PCSMS::Verify_Customizations - variable missing "state" node')
                except StopIteration:
                    break

            if deployed == True:
                break
            else:
                sleep(30)
        rval = successful_deployment if deployed == True else timed_out
        joblog = self.Get_Job_Log(job)
        logging.info("%s\n%s" % (rval, joblog))
        return ("%s\n%s" % (rval, joblog))

    def get_customized_group_info(self, uin, group, xml, policy=1):
        assert uin != None, 'UIN cannot be None'
        assert group != None, 'group cannot be None'
        rval = {}
        logging.debug('get_customized_group_info: - %s' % str(xml))
        grpnode = etree.fromstring(xml).xpath('//rule-group-customizations[rule-group="%s"]' % group)
        if len(grpnode) == 0:
            return (rval)
        for child in grpnode[0].iterchildren():
            rval[child.tag] = child.text
        return (rval)

    def update_customized_group(self, uin=None, group=None, enabled='1', dgxml=None, policy=1, **opts):
        assert uin != None, 'UIN cannot be None'
        assert group != None, 'group cannot be None'
        assert enabled in ['1', '0']
        grp_info = self.get_customized_group_info(uin, group, dgxml, policy)
        assert len(grp_info) != 0, 'ERROR...attempted to update an non-existing customized group'
        uri = 'customizations/rule-group/%s/%s/%s' % (uin, policy, group)
        xml = E('rule-group-customization', E.enabled(enabled), E.state(grp_info['state']))
        rval = self.CTP_Post_PCSMS(uri, etree.tostring(xml))
        return (rval)

    def set_customized_groups(self, action=None, uin=None, policy='1', **opts):
        excluded_groups = ['assurance.rules', 'local.rules', 'sensitive-data.rules']
        if 'exclude' in opts:
            excluded_groups.extend(opts['exclude'])
        enabled_value = '1' if action == 'enable' else '0'
        xml = etree.fromstring(self.Get_Ruleset_Subscription_XML(uin))
        category = xml.xpath('//current-ruleset/category')[0].text
        version = xml.xpath('//current-ruleset/version')[0].text
        current_groups = self.Get_Ruleset_Groups(category, version)
        deployed_groups = self.Get_Ruleset_Customizations(uin, 'groups', policy)
        if 'ERROR' in str(current_groups):
            raise AssertionError, 'No ruleset group customizations found for %s.%s' % (category, version)
        changes_made = False
        for group in current_groups:
            if group in excluded_groups:  # a temporary means of skipping over problematic groups...fix later
                logging.info('Excluding %s from being %sd' % (group, action))
                continue
            grp_info = self.get_customized_group_info(uin, group, deployed_groups, policy)
            # print grp_info
            if len(grp_info) == 0:
                eflag = True if action == 'enable' else False
                logging.info('Adding customized group %s to policy %s of UIN: %s' % (group, policy, uin))
                self.Add_Group_Customization(uin, group, False, policy, enabled=eflag)
                changes_made = True

            elif 'undeployed-enabled' not in grp_info and grp_info['state'] != 'Undeployed' and grp_info[
                'enabled'] != enabled_value:
                logging.debug('Updating group %s...setting enabled to %s' % (group, enabled_value))
                self.update_customized_group(uin, group, enabled_value, deployed_groups, policy)
                changes_made = True
        if changes_made == True:
            logging.info('Deploying group customizations for %s.%s' % (category, version))
            self.Deploy_Customizations(uin, category, version, policy)
            vaction = 'enabled' if enabled_value == '1' else 'disabled'
            rval = self.Verify_Customizations_Deployed(uin, policy, wait='1200', action=vaction)
        else:
            rval = 'No changes in customizations needed'
        return (rval)

    @keyword()
    def Enable_Customized_Groups(self, uin, policy='1'):
        rval = self.set_customized_groups('enable', uin, policy)
        return (rval)

    @keyword()
    def Disable_Customized_Groups(self, uin, policy='1', **opts):
        if 'exclude' in opts:
            groups = []
            for group in opts['exclude'].split(' '):
                groups.append(os.path.basename(group))
            rval = self.set_customized_groups('disable', uin, policy, exclude=groups)
        else:
            rval = self.set_customized_groups('disable', uin, policy)
        return (rval)

    @keyword()
    def Get_Ruleset_Customizations(self, uin=None, customization='groups', policy='1', **opts):
        if not uin:
            uin = self.isensor.uin
        assert uin != None, 'No UIN supplied'
        customization_top_nodes = {
            'groups': 'rule-group-customizations',
            'variables': 'rule-variable-customizations',
            'rules': 'rule-customizations',
            'all': None}
        rval = ''
        assert customization in customization_top_nodes, 'ERROR: Invalid customization specified: "%s"' % customization
        uri = 'customizations/%s/%s' % (uin, policy)
        self.CTP_Get_PCSMS(uri)
        try:
            xml = etree.fromstring(self.response)
        except:
            return ('ERROR parsing PCSMS response:\n"%s"' % self.response)
        if customization_top_nodes[customization] == None:
            return (self.response)
        groupnode = xml.find(customization_top_nodes[customization])
        if groupnode == None or len(groupnode.getchildren()) == 0:
            return ('No %s customizations found' % customization if 'pretty_print' in opts else self.response)
        if not 'pretty_print' in opts or opts['pretty_print'] != True:
            return (etree.tostring(groupnode))
        groups = groupnode.findall(customization_top_nodes[customization].rstrip('s'))
        for group in groups:
            rval += 'href: %s' % group.attrib['href'] if 'href' in group.attrib else ''
            for child in group.getchildren():
                if 'get' in opts:
                    if child.tag in opts['get'].split(','):
                        rval += '\n\t%s: %s' % (child.tag, child.text)
                else:
                    rval += '\n\t%s: %s' % (child.tag, child.text)
            rval += '\n'
        return (rval)

    @keyword()
    def Set_Ruleset_Group_Status(self, uin=None, rule_group=None, policy='1', **opts):
        if not uin:
            uin = self.isensor.uin
        assert uin != None, 'No UIN supplied'
        assert rule_group != None, 'No rule group supplied'
        uri = 'customizations/rule-group/%s/%s/%s' % (uin, policy, rule_group)
        disabled = ['0', 'no', False, 'No', 'NO', 'False']
        enabled = '0' if 'enabled' in opts and opts['enabled'] in disabled else '1'
        xml = E('rule-group-customization', E.enabled(enabled))
        fd, fn = mkstemp(prefix='atf.ctpapi', suffix='out')
        with open(fn, 'w') as f:
            f.write(etree.tostring(xml, pretty_print=True))
        rval = self.CTP_Put_PCSMS(uri, PUT='@%s' % fn)
        os.unlink(fn)
        return (rval)

    @keyword()
    def Get_Device_Policy(self, uin=None, **opts):
        if not uin:
            uin = self.isensor.uin
        assert uin != None, 'No UIN supplied'
        uri = 'device-policies'
        dnode = E.device(uin)
        rxml = E.rxml(dnode)
        rxml.tag = 'ruleset-subscriptions-request'
        fd, fn = mkstemp(prefix='atf.ctpapi', suffix='out')
        f = open(fn, 'w')
        f.write(etree.tostring(rxml, pretty_print=True))
        f.close()
        rval = self.CTP_Post_PCSMS(uri, '@%s' % fn)
        os.unlink(fn)
        return (rval)

    @keyword()
    def Set_Device_Policy(self, uin=None, policy='1', **opts):
        home_net = None
        if not uin:
            uin = self.isensor.uin
            home_net = self.isensor.home_net
        assert uin != None, 'No UIN supplied'
        option_defaults = [
            ('ruleset-version', '-1'),
            ('snort-version', '-1'),
            ('home-net', home_net),
            ('ruleset-category', 'balanced'),
            ('vlan', ''),
            ('alert-only', '1'),
            ('active', '1'),
            ('mode', 'ips'),
            ('physical', '1'),
        ]

        uri = 'policy-management/policy/%si/-1' % uin
        polxml = E.pol()
        polxml.tag = 'box-policy'
        for x in range(0, len(option_defaults)):
            node = option_defaults[x][0]
            default_value = option_defaults[x][1]
            nodexml = E.node(default_value) if not node in opts else E.node(opts[node])
            if nodexml.text == '':
                continue
            nodexml.tag = node
            polxml.insert(0, nodexml)
        fd, fn = mkstemp(prefix='atf.ctpapi', suffix='out')
        f = open(fn, 'w')
        f.write(etree.tostring(polxml, pretty_print=True))
        f.close()
        rval = self.CTP_Post_PCSMS(uri, '@%s' % fn)
        os.unlink(fn)
        return (self.rcode)

    @keyword()
    def Set_Ruleset_Subscription(self, uin=None, policy='1', xml='', **opts):
        elements = ['target-ruleset', 'previous-ruleset', 'current-ruleset', 'ruleset-category', 'pinned',
                    'current-snort-version',
                    'target-snort-version', 'current-release', 'target-ruleset-category']
        try:
            policyint = int(policy)
        except:
            raise AssertionError, 'Specified policy is not an integer'
        assert policyint > 0, 'Invalid policy specified'
        if not xml.startswith('@'):
            xmlstr = xml
        else:
            try:
                f = open(xml.lstrip['@'])
                xmlstr = f.read()
                f.close()
            except:
                raise AssertionError, 'Could not read XML file %s' % xml.lstrip('@')
        try:
            xmlobj = etree.fromstring(xmlstr)
        except:
            raise AssertionError, 'XML is malformed and cannot be parsed:\n %s' % xmlstr
        if not uin:
            uin = self.isensor.uin
        uri = 'ruleset-subscription/%s/%s' % (uin, policy)
        fd, fn = mkstemp(prefix='ctpapi', suffix='out')
        f = open(fn, 'w')
        f.write(xmlstr)
        f.close()
        rval = self.CTP_Post_PCSMS(uri, '@%s' % fn)
        unlink(fn)
        return (rval)

    @keyword()
    def Get_Ruleset_Subscription(self, uin=None, which='target', inc_category=True, inc_version=True, inc_status=False,
                                 inc_rsid=False, **opts):
        rs = which
        if not rs.endswith('-ruleset'):
            rs += '-ruleset'
        rsnodes = ['target-ruleset', 'previous-ruleset', 'current-ruleset']
        assert rs in rsnodes, 'parameter %s is invalid' % which
        rval = ''
        xmlstr = self.Get_Ruleset_Subscription_XML(uin, **opts)
        try:
            xml = etree.fromstring(xmlstr)
        except:
            return (xmlstr)
        rsnode = xml.xpath('//ruleset-subscription/%s' % rs)
        node = rsnode[0]
        cat = node.find('category')
        version = node.find('version')
        status = node.find('status')
        rsid = node.find('id')
        rval = '%s.%s' % (cat.text, version.text)
        if inc_status:
            rval += ',%s' % status.text
        if inc_rsid:
            rval += '.%s' % rsid.text
        if 'get' in opts:
            get = self.extract_text_from_nodes(opts['get'])
            rval = get[0] if len(get) > 0 else ''
        elif opts.has_key('include'):
            includes = self.extract_text_from_nodes(opts['include'])
            incstr = ''.join(',%s' % s for s in includes)
            rval += incstr
        return (rval)

    @keyword()
    def Get_Ruleset_Rollout(self, cat=None, lasts='1', **opts):
        if opts.has_key('uin'):
            uin = opts['uin']
        else:
            uin = self.fetch_uin()
        lastn = int(lasts)
        assert uin != None and uin != '', 'No iSensor UIN supplied'
        url = 'ruleset-rollouts/%s' % uin
        self.pcsms(url)
        if cat != None:
            assert cat == 'all' or cat == 'balanced' or cat == 'security' or cat == 'connectivity', 'Invalid ruleset category "%s"' % cat
            try:
                xml = etree.fromstring(self.response)
                if cat != 'all':
                    nodes = xml.xpath('//rollout[@category="%s"]' % cat)
                else:
                    nodes = xml.xpath('//rollout')
                rstr = ''
                for node in nodes:
                    rstr += ''.join(
                        '%s\t' % (node.attrib[k]) for k in node.attrib if k != 'category' or cat == 'all') + '\n'
                rstr = sorted(rstr.rstrip('\n').split('\n'), cmp=cmp, key=None, reverse=True)
                if lastn > len(rstr):
                    lastn = len(rstr)
                return ''.join('%s\n' % s for s in rstr[0:lastn]).rstrip('\n')
            except:
                pass

        rstr = self.process_options(opts)
        return (rstr if rstr else self.response)

    @keyword()
    def Get_Ruleset_Category_Subscribers(self, cat, **opts):
        assert cat == 'balanced' or cat == 'security' or cat == 'connectivity', 'Invalid ruleset category "%s"' % cat
        url = 'ruleset-category/subscribers-summary/%s' % pkeys[cat]
        self.pcsms(url)
        rstr = self.process_options(opts)
        return (rstr if rstr else self.response)

    @keyword()
    def Get_Ruleset_Categories(self, **opts):  # Broken
        self.pcsms('ruleset-categories')
        rstr = self.process_options(opts)
        return (rstr if rstr else self.response)

    @keyword()
    def Create_Baseline_Record(self, record):
        return (self.CTP_Post_PCSMS(self, 'ruleset-baselines', record))

    @keyword()
    def Get_Ruleset_Record(self, category, version, **opts):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        uri = 'ruleset/%s/%s' % (category, version)
        self.pcsms(uri)
        if len(opts) == 0:
            return (self.response)
        xml = etree.fromstring(self.response)
        rstr = ''
        filterspec = '//rule'
        for element in opts:
            filterspec += '[%s="%s"]' % (element, opts[element])
        # print filterspec, element
        rules = xml.xpath(filterspec)
        for rule in rules:
            for child in rule.iterchildren():
                rstr += '%s: %s\n' % (child.tag, child.text)
            rstr += '\n'
        return (rstr)

    @keyword()
    def Get_Ruleset_Status(self, category, version, **opts):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        uri = 'ruleset/%s/%s/status' % (category, version)
        self.pcsms(uri)
        try:
            xml = etree.fromstring(self.response)
        except:
            return (self.response)
        sname = xml.xpath('//status-name')
        if len(sname) > 0:
            return (sname[0].text)
        if '404' in self.response:  # No ruleset record was found for the given category and version
            self.incidents['Get Ruleset Status incident'] = self.response
            return ('INCIDENT:' + str(self.response))
        return (self.response)

    @keyword()
    def Set_Ruleset_Status(self, category=None, version=None, status=None, **opts):
        assert category in valid_ruleset_categories, 'Invalid ruleset category "%s"' % category
        assert is_correctly_formatted(version), BAD_VERSION_FORMAT
        assert status in valid_ruleset_status, 'Invalid Status'
        statpath = status.lower().replace('_', '-')
        current_status, rsid = self.Get_Ruleset_Info(category, version, include='id')
        uri = 'ruleset/status/%s/%s' % (statpath, rsid)
        self.CTP_Post_PCSMS(uri, '')
        return (self.response)

    @keyword()
    def Get_Box_Policies(self, uin=None, **opts):
        response_codes = {
            '200': 'The box-policy records were successfully retrieved',
            '404': 'The uin was not found',
        }
        if not uin:
            uin = self.fetch_uin()
        self.response_codes.update(response_codes)
        self.pcsms('box-info/policies/%s' % uin)
        rstr = self.process_options(opts)
        if rstr:
            return (rstr)
        return (self.response)

    @keyword()
    def Get_Box_Policy(self, uin=None, policy='1', **opts):
        response_codes = {
            '200': 'The box-policy records were successfully retrieved',
            '404': 'The uin was not found',
        }
        self.response_codes.update(response_codes)
        if not uin:
            uin = self.fetch_uin()
        assert uin != None, 'The UIN must be specified'
        self.pcsms('box-info/policy/%s/%s' % (uin, policy))
        rstr = self.process_options(opts)
        if rstr:
            return (rstr)
        return (self.response)

    @keyword()
    def Set_Ruleset_Category(self, uin=None, policy='1', wait='300.0', category='security', homenet='172.16.0.0',
                             **elements):
        # assert len(elements) > 0, 'No elements were supplied to update'
        response_codes = {
            '200': 'The box-policy records were successfully retrieved',
            '404': 'The uin was not found',
        }
        element_order = ['physical', 'mode', 'active', 'alert-only', 'vlan',
                         'ruleset-category', 'home-net', 'snort-version', 'ruleset-version']
        default_elements = {
            'physical': '',
            'mode': '',
            'active': '',
            'alert-only': '',
            'vlan': '',
            'ruleset-category': category if not 'ruleset-category' in elements else elements['ruleset-category'],
            'home-net': '172.16.0.0',
            'snort-version': '-1',
            'ruleset-version': '-1',
        }
        self.response_codes.update(response_codes)
        if uin == None:
            uin = self.fetch_uin()
        assert uin != None, 'Unable to set ruleset category due to missing UIN'
        xml = E.root()
        xml.tag = 'box-policy'
        # get the current box settings
        current_policy = self.Get_Box_Policy(uin, policy)
        cxml = etree.fromstring(current_policy)
        given_elements = {}

        for node in cxml.getchildren():  # these will be overwritten by any elements passed in
            given_elements[node.tag] = node.text
        for element in elements:
            given_elements[element.replace('_', '-')] = elements[element]
        for element in element_order:
            if element in given_elements:
                if given_elements[element] == None:
                    continue
                else:
                    subelement = E.subelement(given_elements[element])
            else:
                if default_elements[element] == '':
                    continue
                else:
                    subelement = E.subelement(default_elements[element])
            subelement.tag = element
            xml.append(subelement)
        # print etree.tostring(xml, pretty_print=True)
        self.xml = etree.tostring(xml, pretty_print=True)
        category = xml.find('ruleset-category').text
        assert category in valid_ruleset_categories, 'Invalid category specified (%s)' % category
        homenet = xml.find('home-net').text
        self.uri = 'policy-management/policy/%s/%s' % (uin, policy)
        self.pcsms(self.uri, post=etree.tostring(xml, pretty_print=True).strip('\n'), PUT=True)
        job = self.getJobID()
        assert job > 0, self.rcode
        jobID = str(job)
        waittime = float(wait)
        logging.info('waiting %4.1f for deployment result' % waittime)
        timeout = time() + waittime
        while timeout > time():
            status = self.Get_Job_Status(jobID)
            if status == 'SUCCESS':
                logging.info(
                    'Changing of ruleset category to %s for policy %s on UIN %s succeeded' % (category, policy, uin))
                return ('%s:Changing of ruleset category to %s for policy %s on UIN %s succeeded' % (
                    jobID, category, policy, uin))
            elif status == 'FAILED':
                log = self.Get_Job_Log(jobID)
                logging.error(
                    'Changing of ruleset category to %s for policy %s on UIN %s failed:\n%s' % (
                        category, policy, uin, log))
                return ('ERROR:%s:%s\n%s' % (jobID, status, log))
            sleep(5)
        return ('%s:Timed out waiting for job completion' % jobID)

        ############################################################################################################
        # Methods for accessing the 'prov' services
        ###########################################################################################################

    @keyword()
    def Set_AMPD_State(self, uin=None, enable='ENABLE'):
        assert uin != None, 'ERROR - UIN cannot be None'
        if enable.upper().startswith('ENABLE') == True:
            enable = 'ENABLE'
        else:
            enable = 'DISABLE'
        logging.info('Setting AMPD to %s' % enable)
        uri = 'engine-customizations/AMPD'
        xml = '<engine-customizations-AMPD><uins>%s</uins><action>%s</action></engine-customizations-AMPD>' % \
              (uin, enable)
        rval = self.CTP_Post_PCSMS(uri, xml)
        sleep(30)
        return (rval)


class PROV(API):
    @apiCall()
    def prov(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_PROV(self, uri):
        self.prov(uri)
        return (self.response)

    @keyword()
    def CTP_Post_PROV(self, uri, poststr):
        self.prov(uri, poststr)
        return (self.response)

    @keyword()
    def Get_Device_Metadata(self, idn=None, **opts):
        uri = self.Get_Device_URI(idn)
        self.prov(uri)
        if 'include' in opts:
            xpaths = ''.join('//%s,' % s for s in opts['include'].split(','))
            rstr = self.process_options({'include': xpaths.rstrip(',')})
        else:
            rstr = None
        if rstr:
            return (rstr)
        return (self.response)

    @keyword()
    def Get_Device_URI(self, internal_device_name=None, **opts):
        if not internal_device_name:
            internal_device_name = self.fetch_idn()
        self.prov('devices?internal-device-name=%s' % internal_device_name)
        assert self.rval == 0, self.error
        if self.rval != 0:
            raise AssertionError(self.error)
        try:
            logging.debug(self.response)
            xml = etree.fromstring(self.response)
        except:
            return ('ERROR: %s' % self.response)
        dnode = xml.find('device-ref')
        if dnode is not None:
            return (dnode.attrib['href'].lstrip('/prov/'))

            ############################################################################################################
            # Methods for accessing the 'mntagt' services
            ###########################################################################################################


class MNTAGT(API):
    @apiCall()
    def mntagt(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_MNTAGT(self, uri):
        self.mntagt(uri)
        return (self.response)

    @keyword()
    def CTP_Post_MNTAGT(self, uri, poststr):
        self.mntagt(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'topo' services
        ###########################################################################################################


class TOPO(API):
    @apiCall()
    def topo(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_TOPO(self, uri):
        self.topo(uri)
        return (self.response)

    @keyword()
    def CTP_Post_TOPO(self, uri, poststr):
        self.topo(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'audit' services
        ###########################################################################################################


class AUDIT(API):
    @apiCall()
    def audit(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_AUDIT(self, uri):
        self.audit(uri)
        return (self.response)

    @keyword()
    def CTP_Post_AUDIT(self, uri, poststr):
        self.audit(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'jobs' services
        ###########################################################################################################


class JOBS(API):
    @apiCall()
    def jobs(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_Jobs(self, uri):
        self.jobs(uri)
        return (self.response)

    @keyword()
    def CTP_Post_Jobs(self, uri, poststr):
        self.jobs(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'maint' services
        ###########################################################################################################


class MAINT(API):
    @apiCall()
    def maint(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_MAINT(self, uri):
        self.maint(uri)
        return (self.response)

    @keyword()
    def CTP_Post_MAINT(self, uri, poststr):
        self.maint(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'policy' services
        ###########################################################################################################


class POLICY(API):
    @apiCall()
    def policy(self, cmdstr, pars):
        # print '-------------\n%s\n--------------------' % cmdstr
        if self.service_call_frequency_timer > time():
            sleep(self.service_call_frequency_timer - time())
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd, close_fds=True)
        # print self.rcode, self.response
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename, object=self)
        self.service_call_frequency_timer = time() + self.service_call_frequency_limit
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_POLICY(self, uri):
        self.policy(uri)
        return (self.response)

    @keyword()
    def CTP_Post_POLICY(self, uri, poststr=None, **opts):
        if poststr != None:
            self.policy(uri, poststr, **opts)
        else:
            self.policy(uri, '', POST='empty')
        return (self.response)

    @keyword()
    def CTP_Put_POLICY(self, uri, data='', **opts):
        putargs = []
        if 'PUT' in opts:
            putargs.extend(opts['PUT'])
        self.policy(uri, data, PUT=True)
        return (self.response)

    def update_policy_list(self, **pars):
        assert 'idn' in pars, 'ERROR - failed to specify IDN'
        try:
            pxml = etree.parse('%s/isensor.confd/isensor_inventory.xml' % (DOCROOT), PARSER)
            proot = pxml.getroot()
        except:
            proot = E('isensor-policy-list')

        idn = pars['idn']
        policy_list = pxml.xpath('//policy[@idn="%s"]' % idn)
        if len(policy_list) == 0:
            policy = E.policy(idn=idn)
            proot.append(policy)
        else:
            policy = policy_list[0]
        for par in pars:
            print par, pars[par]
            policy.set(par, pars[par])
        with open('%s/isensor.confd/isensor_inventory.xml' % (DOCROOT), 'w') as f:
            f.write(etree.tostring(proot, pretty_print=True))

    @keyword
    def Get_Policy(self, identity, **pars):
        rval = fetch_policy(identity, **pars)
        return rval

    @keyword
    def Deploy_Policy(self, destination='/tmp/isensor-policy.xml', refresh=False, **pars):
        assert self.isensor != None, 'ERROR - failure to specify the iSensor IP address'
        idn = idn if idn != None else self.isensor.idn if self.isensor != None else None
        if refresh == True:  # download the policy rfrom CTP service
            policyxml = self.Download_Policy(idn)
        else:
            policy_path = '%s/isensor.confd/%s.isensor-config.xml' % (self.docroot, idn)
            assert os.path.exists(
                policy_path), 'ERROR- the iSensor policy for %s has not been stored on the ATF' % self.isensor.ip
            with open(policy_path, 'r') as f:
                policyxml = f.read()
        try:
            self.isensor.pushfile(policy_path, destination)
        except Exception as error:
            raise AssertionError, 'ERROR deploying iSensor Policy to %s:%s (%s)' % (
                self.isensor.ip, destination, str(error))
        return ('successfully deployed isensor policy to %s:%s' % (self.isensor.ip, destination))

    @keyword
    def Download_Policy(self, idn=None, all_config_items=True, copyto=None, **pars):
        idn = idn if idn != None else self.isensor.idn if self.isensor != None else None
        assert idn != None, 'ERROR - failure to specify the internal device name'
        uri = 'isensor-policies/%s' % idn
        if all_config_items == True:
            uri += '/all-config-items'
        rval = self.CTP_Get_POLICY(uri)
        if copyto == None:
            copyto = '%s/isensor.confd/%s.isensor-config.xml' % (self.docroot, idn)
        else:
            copyto += '/%s.isensor-config.xml' % (idn)
        try:
            with open(copyto, 'w') as f:
                f.write(rval)
        except Exception as error:
            raise AssertionError, 'ERROR - destination path invalid...unable to write to %s\n%s\n' % (
                copyto, str(error))
        env = pars['environment'] if 'environment' in pars else self.ct_env
        assert env != None, 'ERROR - test environment was not specified "?environment=<Pilot|Agile>"'
        regkey = self.Get_Reg_Key(idn, include='registration-key').rstrip('\n')
        uin = pars['uin'] if 'uin' in pars else self.isensor.uin if self.isensor != None else ''
        ip = pars['address'] if 'address' in pars else self.isensor_IP if self.isensor_IP != None else ''
        mac = pars['mac'] if 'mac' in pars else self.isensor.mac if self.isensor != None else ''
        self.update_policy_list(idn=idn, uin=uin, address=ip, regkey=regkey, environment=env, mac=mac)
        lpath = '%s/%s.isensor-config.xml' % (os.path.dirname(copyto), uin)
        try:
            if os.path.exists(lpath) == False:
                os.symlink(os.path.basename(copyto), lpath)
        except Exception as error:
            raise AssertionError, 'ERROR - unable to create link from %s to %s\n%s' % (lpath, copyto, str(error))
        lpath = '%s/%s.isensor-config.xml' % (os.path.dirname(copyto), ip)
        try:
            if os.path.exists(lpath) == False:
                os.symlink(os.path.basename(copyto), lpath)
        except Exception as error:
            raise AssertionError, 'ERROR - unable to create link from %s to %s\n%s' % (lpath, copyto, str(error))
        lpath = '%s/%s.isensor-config.xml' % (os.path.dirname(copyto), mac)
        try:
            if os.path.exists(lpath) == False:
                os.symlink(os.path.basename(copyto), lpath)
        except Exception as error:
            raise AssertionError, 'ERROR - unable to create link from %s to %s\n%s' % (lpath, copyto, str(error))

        return (rval)

    @keyword
    def Get_Reg_Key(self, idn=None, **pars):
        idn = idn if idn != None else self.isensor.idn if self.isensor != None else None
        assert idn != None, 'ERROR - failure to specify the internal device name'
        uri = 'isensorregkeys/%s' % idn
        self.rval = self.CTP_Get_POLICY(uri)
        if 'raw_xml' in pars and pars['raw_xml'] == True:
            return (self.rval)
        xml = etree.fromstring(self.rval)
        if not 'include' in pars:
            rklist = {}
            nodes = xml.getchildren()
            for node in nodes:
                rklist[node.tag] = node.text
            return (rklist)
        rval = ''
        for node in pars['include'].split(','):
            xpath = '//%s' % node
            nodevalue = xml.xpath(xpath)
            if len(nodevalue) != 0:
                rval += '%s\n' % nodevalue[0].text
        return (rval)

        ############################################################################################################
        # Methods for accessing the 'health' services
        ###########################################################################################################


class HEALTH(API):
    @apiCall()
    def health(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_Health(self, uri):
        self.health(uri)
        return (self.response)

    @keyword()
    def CTP_Post_Health(self, uri, poststr):
        self.health(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'event' services
        ###########################################################################################################


class EVENT(API):
    @apiCall()
    def event(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)
        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_Event(self, uri):
        self.event(uri)
        return (self.response)

    @keyword()
    def CTP_Post_Event(self, uri, poststr):
        self.event(uri, poststr)
        return (self.response)

        ############################################################################################################
        # Methods for accessing the 'exec' services
        ###########################################################################################################


class CT_EXEC(API):
    @apiCall()
    def EXEC(self, cmdstr, pars):
        self.rval = self.svccall(cmdstr, shell=True, stderr=self.errfd, stdout=self.outfd)
        self.response, self.error, self.rcode = read_response(self.outfd, self.response_filename, self.errfd,
                                                              self.error_filename)

        os.unlink(self.response_filename)
        os.unlink(self.error_filename)

    @keyword()
    def CTP_Get_Exec(self, uri):
        self.EXEC(uri)
        return (self.response)

    @keyword()
    def CTP_Post_Exec(self, uri, poststr):
        self.EXEC(uri, poststr)
        return (self.response)

    @keyword()
    def Get_RCMS_Command_Defs(self, reference=None, **opts):
        if reference:
            url = 'command-definitions/%s' % reference
        else:
            url = 'command-definitions'
        self.CTP_Get_Exec(url)
        return (self.response)

    @keyword()
    def Get_RCMS_Command(self, command_name=None, **opts):
        defs_xml_str = self.Get_RCMS_Command_Defs()
        defs_xml = etree.fromstring(defs_xml_str)
        cmd_elements = []
        if command_name:
            cmd_elements = defs_xml.xpath('//command-definition-ref[command-name="%s"]' % command_name)
        elif 'id' in opts:
            cmd_elements = defs_xml.xpath('//command-definition-ref[@href="/exec/command-definitions/%s"]' % opts['id'])
        elif 'href' in opts:
            cmd_elements = defs_xml.xpath('//command-definition-ref[@href="%s"]' % opts['href'])
        if len(cmd_elements) == 0:
            return ('ERROR:RCMS command not found')
        ref = cmd_elements[0].attrib['href']
        cmd_name = cmd_elements[0].find('command-name').text
        active_value = cmd_elements[0].find('active').text
        href_number = os.path.basename(ref)
        rev_vals = {'href': ref, 'id': href_number, 'active': 'YES' if active_value == '1' else 'NO',
                    'command-name': cmd_name}
        if 'include' in opts:
            try:
                rstr = ''.join('%s\n' % (rev_vals[include]) for include in opts['include'].split(','))
            except KeyError as Error:
                rstr = 'ERROR: Unknown reference to %s' % Error
            return (rstr)
        return ('command:%s\nhref:%s\nactive:%s\n' % (cmd_name, ref, 'YES' if active_value == '1' else 'NO'))

    @keyword()
    def Execute_RCMS_Command(self, command=None, timeout='600', **devices):
        valid_device_ids = ['uin', 'internal-device-name', 'device-ref', 'prov_group', 'pcsms_group']
        assert command != None, 'No RCMS script was given'
        assert len(devices) > 0, 'No device was given on which to execute script'
        cmdparsed = command.split(' ')
        script = E('command-name', cmdparsed.pop(0))
        rcms_request = E('command-execution-request', script)
        exec_devices = E('command-execution-devices')
        for device in devices:
            assert device in valid_device_ids, 'Invalid device: "%s"' % device
            deviceID = E(device)
            if device != 'device-ref':
                deviceID.text = devices[device]
            else:
                deviceID.set('href', devices[device])
            exec_devices.append(E('command-execution-device', deviceID))
        rcms_request.append(exec_devices)
        if len(cmdparsed) > 0:
            parameters = E('command-execution-parameters')
            order = 1
            while True:
                try:
                    cmd_par = E('command-execution-parameter', E('param-number', str(order)),
                                E('param-value', cmdparsed.pop(0)))
                    parameters.append(cmd_par)
                except IndexError:
                    break
            rcms_request.append(parameters)
        reportID = strftime('%Y%02m%02dT%02H%02M%02S', gmtime()) + '-%s' % str(os.getpid())
        starttime = gmtime(time() + 2)
        endtime = gmtime(time() + float(timeout))
        specific = E('rcms-specific-parameters',
                     E('fail-if-offline', '1'),
                     E('timeout-seconds', timeout),
                     E('report-id', reportID),
                     E('start-tume', strftime('%4Y-%2m-%2dT%2H.%2M.%2SZ', starttime)),
                     E('not-after', strftime('%4Y-%2m-%2dT%2H.%2M.%2SZ', endtime)),

                     )
        rcms_request.append(specific)
        self.CTP_Post_Exec('command-execution', etree.tostring(rcms_request, pretty_print=True))

        return (self.response)


#########################################################################
class mySQL:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        import pymysql.cursors
        self.cnx = None

    @keyword()
    def Connect_To_MYSQL(self, server_name, database_name):
        try:
            self.cnx = pymysql.connect(
                host=evars['%s_IP' % server_name],
                password=evars['%s_Password' % server_name],
                port=3306,
                database=database_name,
                cursorclass=pymysql.cursors.DictCursor
            )
        except Exception as error:
            raise AssertionError, 'ERROR: failed to connect to database:\n\t%s' % str(error)

    @keyword()
    def MySQL(self, command):
        resp = ''
        try:
            with self.cnx.cursor() as cursor:
                resp = cursor.execute(command)
        except Exception as error:
            raise AssertionError, 'ERROR: The server rejected the SQL command:\n\t%s' % str(error)
        finally:
            self.cnx.close()
        return (resp)


############################################################################################################
# command line functions
############################################################################################################


def main_get(args, env, user):
    instance = API(env, user)
    method = {
        'pcsms': [PCSMS, lambda i, u: i.CTP_Get_PCSMS(u)],
        'prov': [PROV, lambda i, u: i.CTP_Get_PROV(u)],
        'maint': [MAINT, lambda i, u: i.CTP_Get_MAINT(u)],
        'mntagt': [MNTAGT, lambda i, u: i.CTP_Get_MNTAGT(u)],
        'exec': [CT_EXEC, lambda i, u: i.CTP_Get_EXEC(u)],
        'jobs': [JOBS, lambda i, u: i.CTP_Get_Jobs(u)],

    }
    instance = method[args[0].lower()][0](env, user)
    try:
        method[args[0].lower()][1](instance, args[1])
    except AssertionError as estr:
        print 'ERROR: %s' % estr
        print instance.curl_cmd
        return
    show_result(instance)


def main_post(args, env, user):
    method = {
        'pcsms': [PCSMS, lambda i, u, p: i.CTP_Post_PCSMS(u, p)],
        'prov': [PROV, lambda i, u, p: i.CTP_Post_PROV(u, p)],
        'maint': [MAINT, lambda i, u, p: i.CTP_Post_MAINT(u, p)],
        'mntagt': [MNTAGT, lambda i, u, p: i.CTP_Post_MNTAGT(u, p)],
        'exec': [CT_EXEC, lambda i, u, p: i.CTP_Post_EXEC(u, p)],
    }
    try:
        instance = method[args[0].lower()][0](env, user)
    except KeyError as estr:
        print '%s is not supported in command-line mode...contact the administrator' % estr
        return
    try:
        method[args[0].lower()][1](instance, args[1], args[2])
    except AssertionError as estr:
        print 'ERROR: %s' % estr
        print instance.curl_cmd
        return
    show_result(instance, post=True)


if __name__ == '__main__':

    optprsr = OptionParser(usage="Usage %s <options> <service_alias> <url> [<post_data>]" % sys.argv[0])
    optprsr.add_option('-u', '--user', action='store', dest='user', default='None',
                       help='ATF user (must be provsioned in the automation server)')
    optprsr.add_option('-e', '--environment', action='store', dest='environment', default='Pilot',
                       help='set the CTP environement (e.g. Agile | Pilot) default=Pilot"')
    """"
    optprsr.add_option('-p', '--password', action='store', dest='password', default='None',
                       help='Password if using "Password Authentication"')
    optprsr.add_option('-c', '--certificate', action='store', dest='certificate', default='None',
                       help='Use Certificate Authentication with default certificate')
    optprsr.add_option('-C', '--certpath', action='store', dest='certpath', default='None',
                       help='Use CSO certifcate locate at <CERTPATH>')
    optprsr.add_option('-P', '--devicefile', action='store', dest='devicefile', default='None',
                       help='Use device file to store encrypted passwords')
"""

    options, cliargs = optprsr.parse_args()
    assert len(sys.argv) > 2, 'Not enough arguments; syntax is: cptservices.py <ctp service> <uri> [<post data>]'
    if len(cliargs) > 2:
        main_post(cliargs, options.environment, options.user)
    else:
        main_get(cliargs, options.environment, options.user)
