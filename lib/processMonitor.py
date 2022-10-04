#! /usr/bin/python
import sys
import os
import re
import paramiko
import atf_password
from time import time, sleep
import logging
import warnings
import signal

global ERROR
ERROR = ''

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='/var/www/cgi-bin/ATF.log',
                    level=logging.DEBUG)



class WebVars:
        def __call__(self,p):
                def wrapper(self,duser='admin', dsession='00000001'):
                        getvar = lambda s, d: os.getenv(s) if os.getenv(s) else d
                        User = getvar('User',duser)
                        Session = getvar('Session',dsession)
                        webvars = {}
                        wvars = os.getenv('webvars')
                        if not wvars:
                                infile ='/var/www/html/atfweb/%s.%s.argumentfile.txt' % (User,Session)
                                f = open(infile,'r')
                                pars = f.read().split('\n')
                                f.close()
                                for par in pars:
                                        if par.startswith('--variable'):
                                                evar = par[11:].split(':')
                                                value = ''.join('%s:' % evar[x] for x in range(1,len(evar)))
                                                os.putenv(evar[0],value.rstrip(':'))
                                                webvars[evar[0]] = value.rstrip(':')
                        else:
                                for wvar in wvars.split(','):
                                        webvars[wvar] = os.getenv(wvar)
                        p(self,webvars)
                return(wrapper)

def xlog(xstr):
        f = open('/home/atf/logs/paramiko.log', 'w')
        f.write('%s\n' % xstr)
        f.close()



class Connect:
    def __init__(self, device, **kword):
        import signal
        global ERROR
        warnings.simplefilter('ignore')
        #paramiko.util.log_to_file ('/home/atf/logs/paramiko.log')
        setvar = lambda v: os.getenv(v) if os.getenv(v) else kword['webvars'][v]
        P = atf_password.Password()
        self.ip = setvar('%s_IP' % device)
        user = setvar('%s_User' % device)
        password = setvar('%s_Password' % device)
        pword = self.password = password
        self.device = device
        self.ip3q = ''
        self.error = ''
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.user = user
        try:
                self.cnx.connect(self.ip, username=user, password=pword)
        except:
                self.error = ERROR =  "processMonitor.py:Connect - Connection Failure to device at %s, user:%s" % (self.ip, user)
                logging.error(self.error)
                raise AssertionError, self.error
        logging.info("processMonitor.py:Connect - Connection established %s (%s) for user %s" % (device, self.ip, user))

    def cmd(self, command, **kwords):
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
                logging.debug('processMonitor.py:cmd - Sent command %s to %s (%s)' % (command, self.device, self.ip))
        stdin, stdout, stderr = self.cnx.exec_command("%s 2>&1" % command)
        response = stdout.read()
        if response == '':
            respone = stderr.read()
        if not kwords.has_key('logsuppress') or kwords['logsuppress'] == False:
                logging.debug("processMonitor.py:cmd = Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)

    def sudo(self, command):
        logging.debug('processMonitor.py:sudo - Sent sudo command %s to %s (%s)' % (command, self.device, self.ip))
        stdin, stdout, stderr = self.cnx.exec_command("sudo -S %s 2>&1" % command)
        stdin.write("%s\n" % self.password)
        stdin.flush()
        response = stdout.read()
        if response == '':
            respone = stderr.read()
        logging.debug("processMonitor.py:Connect - Rcvd response %s from device %s (%s)" % (response, self.device, self.ip))
        return (response)


class processMonitor:
        @WebVars()
        def __init__(self, webvars):
                self.device = "isensor"
                try:
                        self.iSensor = Connect(self.device,webvars=webvars)
                        self.error = None

                except:
                        self.error = 'processMonitor.py:ProcessMonitor - ERROR: unable to connect to %s (%s)\n' % (self.device,ERROR)
                        logging.error('%s (%s)' % (self.device,ERROR))
                        raise AssertionError, '%s' % self.error
                if not self.error:
                        try:
                                self.tmpfile = '/tmp/%s' % os.getenv('TestID')
                                self.pfile = open(self.tmpfile,'w')
                                self.error = None
                        except:
                                logging.error('processMonitor.py:ProcessMonitor - ERROR:unable to create a temporary file for monitor\n')
                                self.error = 'processMonitor.py:ProcessMonitor - ERROR:unable to create a temporary file for monitor'
                                raise AssertionError, '%s' % self.error
                        regex = '\d{2}:\d{2}:\d{2}\s.*%s.*' % sys.argv[2]
                        self.regex = re.compile(regex)
                        try:
                                self.flags = sys.argv[3]
                        except IndexError:
                                self.flags = '-ef'
                        signal.signal(signal.SIGTERM, self.sigTermHandler)

        def sigTermHandler(self, signuml, frame):
                self.pfile.close()
                #os.unlink(self.tmpfile)
                return

        def pMon(self, runtime='900'):
                endmonitor = time() + float(runtime)
                plist = {}
                while True:
                        outstr = ''
                        try:
                                ps = self.iSensor.cmd('ps %s' % self.flags)
                        except:
                                self.error = 'Error: unable to send command to iSensor\n'
                                raise AssertionError, '%s' % self.error
                        match = re.findall(self.regex, ps)
                        ptup = []
                        for tokens in match: # scan the proceses found this second
                                token = tokens.split(' ')
                                discard = token.pop(0)
                                line = ''.join('%s ' % s for s in token)
                                ptup.append(line)
                                if not plist.has_key(line): # first time the process appeared
                                        plist[line] = [0,time()]
                                        outstr += '%s up since monitor started\n' % (line)
                                elif plist[line][0] < 0: # tranition from not running to running
                                        outstr += '%s up (quiescent for %d seconds)\n' % (line,time() - plist[line][1]) # output the time it slept
                                        plist[line] = [0,time()]
                        for key in sorted(plist.keys()): # scan the list of processes that have ever run
                                try:
                                        x = ptup.index(key)
                                        plist[key][0] = time() - plist[key][1]
                                except ValueError: # process was up before but is down now
                                        if plist[key][0] >= 0: # transition from running to not running
                                                outstr += '%s down (active for %d seconds)\n' % (key,time() - plist[key][1])
                                                plist[key] = [-1, time()]
                                        else:
                                                plist[key][0] = (time() - plist[key][1]) * -1
                        if len(outstr) > 0:
                                self.pfile.write(outstr)
                                outstr = ''
                                self.pfile.flush()
                        sleep(1)
                        sys.stdout.flush()
                        if time() > endmonitor:
                                self.pfile.close()
                                #os.unlink(self.tmpfile)
                                break

if __name__ == '__main__':
        pm = processMonitor(sys.argv)
        if pm.error:
                print pm.error
        else:
                error = pm.pMon()
                if error:
                        print error

