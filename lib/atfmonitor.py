#! /usr/bin/python
import sys
import subprocess
import logging as L
from time import time
from time import sleep
from time import ctime
import tempfile
import signal
import os
import logging

# logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',filename='atf.log', level=logging.DEBUG)

class atfmonitor:
    def __init__(self, **kargs):
        if kargs.has_key('lifetime'):
            lifetime = kargs['lifetime']
        else:
            lifetime = '900.0'
        if kargs.has_key('pid'):
            pid = int(kargs['pid'])
        else:
            pid = 0
        if kargs.has_key('logging'):
            logging = kargs['logging']

        expire = time() + float(lifetime)
        self.mcb = {
            'args': [],
            'expire': time() + float(lifetime),
            'launch_time': ctime(time()),
            'pfile': '',
            'output': '',
            'error': False,
            'buffer': '',
            'ecode': 0,
            'timeout': False,
            'status': 'staged',
            'msg': '',
            'signal': None,
            'pid': pid,
            'heartbeat': ''}
        self.pfile = tempfile.NamedTemporaryFile('wt')

        self.perror = tempfile.NamedTemporaryFile('wt')
        self.pout = tempfile.NamedTemporaryFile('wt', delete=False)
        self.proc = None

    def sigIntHandler(self, signuml, frame):
        self.mcb['signal'] = signal.SIGINT
        return

    def launch(self, cargs, **kargs):
        top_error = None
        args = ''.join('%s ' % s for s in cargs)
        self.mcb['args'] = args
        signal.signal(signal.SIGINT, self.sigIntHandler)
        # logging.info('atfmonitor.py: mcb - %s' % str(self.mcb))
        logging.info('atfmonitor.py: monitoring spawned process "%s"' % str(args))
        proc = subprocess.Popen([args], shell=True, executable='/bin/bash', stderr=self.perror, stdout=self.pout)
        out = open(self.pout.name, 'r')
        self.mcb['proc'] = proc
        self.mcb['status'] = 'running'
        #logging.info('atfmonitor.py: mcb - %s' % str(self.mcb))

        sleep(2)
        ttime = 0
        while True:
            now = int(time())
            self.mcb['pid'] = proc.pid
            status = proc.poll()
            if status != None:
                if status != 0:
                    self.mcb['error'] = True
                    self.mcb['ecode'] = status
                    eout = open(self.perror.name, 'r')
                    top_error = eout.readline()
                    estr = eout.read()
                    logging.info('ERROR: %s' % top_error)
                    logging.debug('atfmonitor.py: ERROR: %s\n%s' % (top_error, estr))
                    eout.close()
                else:
                    self.mcb['error'] = False
                    self.mcb['ecode'] = status
                #logging.info('atfmonitor.py: normal termination, mcb - %s' % str(self.mcb))
                #self.perror.flush()
                #self.pout.flush()

                outstr = out.read()
                if outstr != '':
                    self.mcb['buffer'] += outstr
                out.close()
                return (status)
            if now > self.mcb['expire'] or self.mcb['signal'] == signal.SIGINT:
                if ttime == 0:
                    if self.mcb['signal'] == signal.SIGINT:
                        self.mcb['buffer'] += 'Received SIGINT'
                        ttime = now
                    ttime = now + 60
                    self.mcb['ecode'] = status
                    self.mcb['status'] = 'sent sigterm'
                    logging.debug('atfmonitor.py: ERROR: %s' % str(self.mcb))
                    self.mcb['error'] = True
                    self.mcb['timeout'] = True
                    self.perror.flush()
                    self.pout.flush()
                    outstr = out.read()
                    if outstr != '':
                        self.mcb['buffer'] += outstr
                    proc.terminate()
                    continue
                elif now > ttime:
                    self.mcb['status'] = 'sent sigkill'
                    proc.kill()
                    return (99)
            self.perror.flush()
            self.pout.flush()
            outstr = out.read()
            if outstr != '':
                self.mcb['buffer'] += outstr

            sleep(1)
        return (top_error)


if __name__ == "__main__":
    margs = []
    margs.extend(sys.argv[1:])
    M = atfmonitor(lifetime='900')
    M.launch(margs)

