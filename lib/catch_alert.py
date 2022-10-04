#! /usr/bin/python
##########################################

# catch_alert.py - uploaded to the iSensor to catch interrupt when wite occurs on alert directory

##########################################
from fcntl import fcntl, F_SETSIG, F_NOTIFY, DN_MODIFY, DN_CREATE, DN_DELETE
import os
import signal
from time import time, strftime
import sys
from glob import glob

global JOBID, INTERRUPT 
JOBID = ''
INTERRUPT = 0

def handler(signum, frame):
	global INTERRUPT
	signal.alarm(0)
	INTERRUPT = signum

def timeout_handler(signum, frame):
	global INTERRUPT
	signal.alarm(0)
	INTERRUPT = signum

def bail(idstr, msg):
	f = open('/secureworks/log/atf.log','a')
	f.write('\n%s ATF - ID: %s, %s' % (strftime('%b %2d %02H:%02M:%02S'), idstr, msg))
	quit(1)

def quit(rcode):
	try:
		os.exit(rcode)
	except:
		exit(rcode)

def main(dirname, logmsg, idstr, timeout=2000):
	signal.signal(signal.SIGRTMIN, handler)
	signal.signal(signal.SIGALRM, timeout_handler)
	signal.alarm(timeout)
	try:
		fd = os.open(dirname, os.O_RDONLY)
	except:
		bail(idstr, "ERROR - can't get fd on '%s' directory" % dirname)

	try:
		fcntl(fd, F_SETSIG, signal.SIGRTMIN)
	except:
		bail(idstr, "ERROR - can't set signal on fd")

	try:
		fcntl(fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_DELETE)
	except:
		bail(idstr, "ERROR -failed to register notification on fd\n")

	signal.pause()
	os.close(fd)
	
	if INTERRUPT == signal.SIGALRM:
		logmsg = 'Timed out waiting for alert'
		alerts = []
	else:
		alerts = glob('%s/*' % dirname)
		
	f = open('/secureworks/log/atf.log','a')
	f.write('\n%s ATF - ID: %s, %s, %f' % (strftime('%b %2d %02H:%02M:%02S'), idstr, logmsg, time()))
	if len(alerts) > 0:
		filelist = ''.join('%s,' % os.path.basename(alert) for alert in alerts)
		f.write('\n%s ATF - ID: %s, found:%s' % (strftime('%b %2d %02H:%02M:%02S'), idstr,filelist.rstrip(','))) 
	f.write('\n%s ATF - ID: %s, Job Complete \n' % (strftime('%b %2d %02H:%02M:%02S'), idstr))
	f.close()

if __name__ == '__main__':
	if len(sys.argv) < 3:
		quit(1)
	monitored_directory = sys.argv[1]
	log_message = sys.argv[2]
	logmarkid = sys.argv[3]
	try:
		timeout = int(sys.argv[4])
	except IndexError:
		timeout = 2000
	JOBID = logmarkid
	pid = os.fork()
	if pid == 0:
		main(monitored_directory, log_message,  logmarkid, timeout)
		quit(0)
	else:
		f = open('/secureworks/log/atf.log','a')
		f.write('\n%s ATF - ID: %s, Job Started under pid:%d, wait time is %d secs' % (strftime('%b %2d %02H:%02M:%02S'), logmarkid, pid, timeout))
		f.close()
		print '%d' % pid
		quit(0)
	

