#! /usr/bin/python
from __future__ import absolute_import
import os
from os import path as P
from os import mkdir, stat, chown, chmod, unlink, rename, chdir, makedirs
from pwd import getpwuid, getpwnam
import sys
from glob import glob
from shlex import shlex
from subprocess import call
from tempfile import mktemp

DOCROOT = '/mnt/efs/htdocs'
HTMLROOT = '/var/www/html'
LIBPATH = '/var/www/cgi-bin/lib'
EFSMOUNT = '/mnt/efs'
LIB2PATH = '/var/www/cgi-bin/lib/lib2'
CGIPATH = '/var/www/cgi-bin'
LOGPATH = '/var/www/cgi-bin/lib/logs'
DIR_READ_EXECUTE = 0o755
DIR_READ_WRITE_EXECUTE = 0o777
FILE_READ_WRITE = 0o766
FILE_READ_EXECUTE = 0o755
FILE_READ_WRITE_EXECUTE = 0o777

global pout
global perr
perr = open('atf_install.err', 'w')
pout = open('atf_install.log', 'w')
global err_cnt
err_cnt = 0

user_list = ['CTU%d' % u for u in range(1, 14)]
user_list.extend(['atf', 'gowen', 'hlouissaint'])

changedir = lambda s: chdir(s)

packages = {
    'yum': ['sudo yum -y upgrade\n'],
    'apache': ['sudo yum -y install httpd\n',
               'sudo yum -y install mod_ssl\n',
               ],
    'git': ['sudo yum -y install git\n'],
    'glibc': ['sudo yum -y install glibc.i686\n'],
    'libgcc': ['sudo yum -y install libgcc.i686\n'],
    'robotframework': ['/usr/bin/git clone "https://github.com/robotframework/robotframework.git"\n',
                       # { 'robotframework\n' : changedir},
                       'cd robotframework;sudo python setup.py build install --record robotframework.files.txt\n',
                       # { '../' : changedir},
                       ],
    'paramiko': ['sudo yum -y install python-paramiko\n'],
    'SSHLibrary': ['git clone "https://github.com/robotframework/SSHLibrary.git"\n',
                   'cd SSHLibrary;sudo python setup.py build install --record SSHLibrary.files.txt\n',
                   ],
    'pcregrep': ['sudo yum -y install pcre-tools\n'],
    'vim': ['sudo yum -y install vim\n'],
    'python-requests': ['sudo yum -y install python-requests\n'],
    'python-lxml': ['sudo yum -y install python-lxml\n'],
    'python-devel': ['sudo yum -y install python-devel\n'],
    'pycrypto': ['sudo yum -y install pycrypto\n'],
    'pyOpenSSL': ['sudo yum -y install pyOpenSSL\n'],
    'pip': ['sudo yum install -y epel-release\n',
            'sudo yum install -y python-pip\n',
            ],
    'hvac': ['sudo pip install hvac\n'],
    'expect': ['echo "dummy...expect is a tar file in the atf repository and gets installed later"'],
    'scpclient': ['echo "dummy...scpclient is a gz file in the atf repository and gets installed later"'],
    'bind-utils': ['sudo yum -y install bind-utils\n'],
    'wget': ['sudo yum -y install wget\n'],
}

uninstall_packages = {
    'yum': ['echo "dummy since yum does not get unintall"\n'],
    'git': ['sudo yum -y remove git\n'],
    'glibc': ['sudo yum -y remove glibc.i686\n'],
    'libgcc': ['sudo yum -y remove libgcc.i686\n'],
    'apache': ['sudo systemctl stop httpd\n',
               'sudo yum -y remove mod_ssl',
               'sudo yum -y remove httpd\n'],
    'robotframework': [
        'cd robotframework;cat robotframework.files.txt |xargs sudo rm -rf\n',
        'sudo rm -rf robotframework\n',
    ],
    'paramiko': ['sudo yum -y remove python-paramiko\n'],
    'SSHLibrary': [
        'cd SSHLibrary;cat SSHLibrary.files.txt |xargs sudo rm -rf\n',
        'sudo rm -rf SSHLibrary\n',
    ],
    'pcregrep': ['sudo yum -y remove pcre-tools\n'],
    'vim': ['sudo yum -y remove vim\n'],
    'python-requests': ['sudo yum -y remove python-requests\n'],
    'python-lxml': ['sudo yum -y remove python-lxml\n'],
    'python-devel': ['sudo yum -y remove python-devel\n'],
    'pyOpenSSL': ['sudo yum -y remove pyOpenSSL\n'],
    'pycrypto': ['sudo yum -y remove pycrypto\n'],
    'hvac': ['sudo pip uninstall --yes hvac\n'],
    'pip': [
        'sudo yum remove -y python-pip\n',
        'sudo yum remove -y epel-release\n',
    ],
    'expect': ['cd paramiko-expect-0.2.8;cat expect.txt |xargs sudo rm -rf\n',
               'sudo rm -r -f paramiko-expect-0.2.8'],
    'scpclient': ['cd scpclient-0.7;cat scpclient.txt |xargs sudo rm -rf\n',
                  'sudo rm -r -f paramiko-expect-0.2.8'],
    'bind-utils': ['sudo yum -y remove bind-utils\n'],
    'wget': ['sudo yum -y remove wget\n'],
}

package_install_order = [
    'yum',
    'apache',
    'git',
    'glibc',
    'robotframework',
    'paramiko',
    'SSHLibrary',
    'python-requests',
    'python-lxml',
    'python-devel',
    'pycrypto',
    'pyOpenSSL',
    'pcregrep',
    'vim',
    'pip',
    'hvac',
    'expect',
    'scpclient',
    'bind-utils',
    'wget',
    'libgcc',
]

# package_install_order = ['robotframework','paramiko','SSHLibrary']

environment_export = [
    "export ATF_LIBPATH=/var/www/cgi-bin/lib",
    "export HTTP_PROXY=http://squid.internal.secureworks.net:3128",
    "export HTTPS_PROXY=$HTTP_PROXY",
    "export http_proxy=$HTTP_PROXY",
    "export https_proxy=$HTTPS_PROXY",
    "export FTP_PROXY=$HTTP_PROXY",
    "export ftp_proxy=$HTTP_PROXY",
    "printf -v no_proxy_list '%s,' 172.16.144.{1..255};",
    "export no_proxy=\"${no_proxy_list%,},$no_proxy\";",
    "export VAULT_ADDR=https://vault.aws.secureworks.com"
]

INSTALL = 'install'
UNINSTALL = 'uninstall'
UPDATE = 'update'


def package(action, plist=None):
    if action == INSTALL:
        package_list = packages
        order = package_install_order
        pout.write('Installing packages %s' % str(order))
    elif action == UNINSTALL:
        bash('sudo rm -rf atf\n')
        package_list = uninstall_packages
        order = package_install_order
        order.reverse()
        pout.write('Removing packages %s' % str(order))
    if plist != None:
        order = plist.split(',')
    for p in order:
        print('Package %s is being %s' % (p, 'INSTALLED' if action == INSTALL else 'UNINSTALLED'))
        for command in package_list[p]:
            rval = False
            pout.write('\n\n%s' % str(command))
            try:
                if isinstance(command, str):
                    ret = call([command], shell=True, stderr=perr, stdout=pout)
                else:
                    break
                pout.write('\nret= %s' % str(ret))
                if ret != 0:
                    if action == UNINSTALL:
                        continue
                    print('Return from %s=%d\n' % (command, ret))
                    break
                rval = True
            except Exception as estr:
                print(command)
                print(str(estr))
                perr.write(command)
                perr.write(str(estr))
                if action == UNINSTALL:
                    continue
                else:
                    break
        if rval == False:
            if action == UNINSTALL:
                pass
            else:
                trap
                break
    return rval


def remove_atf_dir_trees():
    orig_cnt = err_cnt
    for user in user_list:
        bash('sudo rm -rf %s/%s' % (DOCROOT, user))
    bash('sudo rm -rf /var/www/html/htdocs\n')
    bash('sudo rm -rf %s\n' % DOCROOT)
    bash('sudo rm -rf /var/www/cgi-bin/lib\n')
    bash('sudo rm -rf /var/www')
    return (err_cnt - orig_cnt)


def set_file_properties(user, path_list, properties):
    for path in path_list:
        try:
            uid = getpwnam(user).pw_uid
            gid = getpwnam('apache').pw_gid
            chown(path, uid, gid)
            chmod(DOCROOT, properties)
            return (True, None)
        except OSError as estr:
            return (False, estr)


def unpack_tar_files(user, filen):
    from tarfile import TarFile as tar
    libfiles = ['atfvars.py', 'axsess.py', 'global.py', 'ctpapi2.py', 'scwxBPlib2.py', 'scwxDCIMlib2.py',
                'scwxDRAClib.py',
                'bpsh-linux-x86-249089', 'bpsh8301314']
    lib2files = ['scwxCorelib.py']
    xmlfiles = ['email.xml', 'agile_servers.xml']
    try:
        T = tar.open(filen, 'r')
        for tfile in libfiles:
            xfile = T.getmember(tfile)
            T.extract(xfile, LIBPATH)
            set_file_properties(user, ['%s/%s' % (LIBPATH, tfile)], FILE_READ_EXECUTE)
        for tfile in lib2files:
            xfile = T.getmember(tfile)
            T.extract(xfile, LIB2PATH)
            set_file_properties(user, ['%s/%s' % (LIB2PATH, tfile)], FILE_READ_EXECUTE)
        for tfile in xmlfiles:
            xfile = T.getmember(tfile)
            T.extract(xfile, '%s/%s' % (DOCROOT, user))
            set_file_properties(user, ['%s/%s/%s' % (DOCROOT, user, tfile)], FILE_READ_WRITE)
    except Exception as estr:
        return (False, str(estr))
    return (True, None)


logfiles = {
    'debugfiles': None,
    'logs': None,
    'outputs': None,
    'reports': None,
}

histories = [
    'isensor_ruleset',
    'vrt_ruleset',
    'pan_ruleset',
    'nsxt_ruleset',
    'isensor_release',
    'zeek_performance',
    'hyperscan',
]

iSensor_Regression = {
    '1_PreTest': logfiles,
    'AgentandAlerting': logfiles,
    'common': None,
    'DPDK': logfiles,
    'GeneralRegression': logfiles,
    'IPQ3': logfiles,
    'LSM': logfiles,
    'NID': logfiles,
    'OpenVPN': logfiles,
    'OSSEC': logfiles,
    'Pause': logfiles,
    'Performance': logfiles,
    'PostDeploy': logfiles,
    'Preprocessors': logfiles,
    'PreTest': logfiles,
    'RCMS': logfiles,
    'Snort': logfiles,
    'XPD': logfiles,
}

session_user_tree = {
    'htdocs': {
        'admin': None,
        'CTU1': None,
        'CTU2': None,
        'CTU3': None,
        'CTU4': None,
        'CTU5': None,
        'CTU6': None,
        'CTU7': None,
        'CTU8': None,
        'CTU9': None,
        'CTU10': None,
        'CTU11': None,
        'CTU12': None,
        'CTU13': None,
        'CTU14': None,
        'DPDK': None,
        'AutoRegression': None,
        'Performance1': None,
        'Performance2': None,
        'PostDeploy': None,
    }
}

test_suite_dir_tree = {
    'htdocs/iSensor_Regression': iSensor_Regression,
    'htdocs/Ruleset_Performance/Ruleset_Performance': logfiles,
}

library_dir_tree = '/var/www/cgi-bin/lib/logs'


def install_session_user_files():
    from glob import glob

    for user in session_user_tree['htdocs']:
        server_files = glob('atf/config/%s/*.xml' % user)
        pout.write('atf/%s/*.xml server_files: %s\n' % (user, str(server_files)))
        for serverfile in server_files:
            print('Created %s/%s/%s' % (DOCROOT, user, P.basename(serverfile)))
            with open(serverfile, 'r') as rf:
                with open('%s/%s/%s' % (DOCROOT, user, P.basename(serverfile)), 'w') as wf:
                    wf.write(rf.read())


def install_apache_files():
    bash('sudo cp --no-preserve=mode,ownership -f atf/apache/%s/ssl.conf /etc/httpd/conf.d/ssl.conf\n' % os.environ[
        'TestEnv'])
    bash('sudo cp --no-preserve=mode,ownership -f atf/apache/%s/httpd.conf /etc/httpd/conf/httpd.conf\n' % os.environ[
        'TestEnv'])
    bash('sudo cp --no-preserve=mode,ownership -f atf/apache/%s/*.html /mnt/efs/htdocs/\n' % os.environ['TestEnv'])
    bash('sudo mv /var/www/cgi-bin/lib/apache_startup.py /var/www/cgi-bin/apache_startup.py\n')
    bash('sudo chmod 755 /var/www/cgi-bin/apache_startup.py\n')
    bash('sudo chmod 755 /var/www/cgi-bin/lib/*.py\n')
    bash('sudo chmod -R 766 /var/www/cgi-bin/lib/logs')
    bash('sudo chown -R centos:apache /var/www/cgi-bin/*\n')
    bash('sudo chown -R -h centos:apache /var/www/cgi-bin/*\n')
    bash('sudo cp atf/apache/testrun /etc/init.d/\n')
    bash('sudo chmod 755 /etc/init.d/testrun\n')
    bash('sudo semanage fcontext -a -t httpd_sys_script_exec_t "/var/www/cgi-bin(/.*)?"\n')
    bash('sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/htdocs(/.*)?"\n')
    bash('sudo systemctl start httpd && sudo systemctl enable httpd\n')
    bash('sudo systemctl start testrun && sudo systemctl enable testrun\n')


def install_sym_links():
    from glob import glob
    common_files = glob('atf/htdocs/iSensor_Regression/common/*.txt')
    for subdir in iSensor_Regression:
        if subdir == 'common':
            continue
        bash('sudo ln -s %s %s/iSensor_Regression/%s/lib\n' % (LIBPATH, DOCROOT, subdir))
        for commonfile in common_files:
            bash('sudo ln -s %s/iSensor_Regression/common/%s %s/iSensor_Regression/%s/%s\n' % (
                DOCROOT, P.basename(commonfile), DOCROOT, subdir, P.basename(commonfile)))
    bash('sudo ln -s %s %s/logs' % (LOGPATH, CGIPATH))
    bash('sudo chmod -R 766 %s/logs' % CGIPATH)
    bash('sudo ln -s /usr/bin/robot /usr/local/bin/pybot')
    bash('sudo ln -s %s/lib %s\n' % (CGIPATH, DOCROOT))
    bash('sudo chown -h %s/lib\n' % DOCROOT)


def mount_efs(action):
    efs_spec = {
        'agile': {'fileSystemId': 'fs-fe37a508:/',
                  },
        'pilot': {'fileSystemId': 'fs-784f2b8f:/',
                  },
        'production': {'fileSystemId': 'fs-532ab6a5:/',
                       },
    }
    spec = efs_spec[os.environ['TestEnv'].lower()]
    if action == INSTALL:
        bash('sudo mkdir /mnt/efs\n')
        bash('sudo mount -t efs %s /mnt/efs\n' % spec['fileSystemId'])
        bash('sudo mkdir -p %s/htdocs\n' % EFSMOUNT)
        for directory in histories:
            bash('sudo mkdir -p %s/htdocs/history/%s\n' % (EFSMOUNT, directory))
        bash('sudo ln -s %s/htdocs %s\n' % (EFSMOUNT, HTMLROOT))
    elif action == UNINSTALL:
        bash('sudo umount -f /mnt/efs\n')


def bash(command):
    global err_cnt
    try:
        pout.write(command)
        print('Executing %s' % command)
        err_cnt += call([command], shell=True, stderr=perr, stdout=pout)
    except Exception as estr:
        perr.write(command)
        perr.write('%s\n' % str(estr))


def create_atf_dir_tree():
    print('Creating ATF file system...')
    for subdir in session_user_tree['htdocs']:
        pathstr = '%s/htdocs/%s' % (EFSMOUNT, subdir)
        print('\tCreating %s' % pathstr)
        pout.write('%s\n' % pathstr)
        try:
            command = 'sudo mkdir -p %s\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
            command = 'sudo chmod 766 %s\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
            command = 'sudo semanage fcontext -a -t httpd_sys_rw_content_t "%s(/.*)?"\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
        except OSError as estr:
            if str(estr).find('File exists') >= 0:
                continue
            perr.write(command)
            perr.write('%s\n' % estr)
        except Exception as estr:
            perr.write(command)
            perr.write('%s\n' % estr)
    try:
        bash('sudo mkdir -p %s\n' % library_dir_tree)
        bash('sudo chmod 777 %s\n' % library_dir_tree)
    except OSError as estr:
        if str(estr).find('File exists') >= 0:
            pass
        else:
            perr.write(command)
            perr.write('%s\n' % estr)
    except Exception as estr:
        perr.write('%s\n' % estr)
    for subdir in iSensor_Regression:
        if iSensor_Regression[subdir] == None:
            pathstr = '%s/iSensor_Regression/%s' % (DOCROOT, subdir)
            print('\tCreating %s' % pathstr)
            pout.write('%s\n' % pathstr)
            try:
                command = 'sudo mkdir -p %s\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)
                command = 'sudo chmod 766 %s\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)
                command = 'sudo semanage fcontext -a -t httpd_sys_rw_content_t "%s(/.*)?"\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)

                # makedirs(pathstr,  DIR_READ_WRITE_EXECUTE)
                # set_file_properties('apache', [pathstr], DIR_READ_WRITE_EXECUTE)
            except OSError as estr:
                if str(estr).find('File exists') >= 0:
                    pass
                else:
                    perr.write(command)
                    perr.write('%s\n' % estr)
            except Exception as estr:
                perr.write(command)
                perr.write('%s\n' % estr)
            continue
        for log in logfiles:
            pathstr = '%s/iSensor_Regression/%s/%s' % (DOCROOT, subdir, log)
            print('\tCreating %s' % pathstr)
            try:
                command = 'sudo mkdir -p %s\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)
                command = 'sudo chmod 766 %s\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)
                command = 'sudo semanage fcontext -a -t httpd_sys_rw_content_t "%s(/.*)?"\n' % pathstr
                pout.write(command)
                call([command], shell=True, stderr=perr, stdout=pout)

            except OSError as estr:
                if str(estr).find('File exists') >= 0:
                    pass
                else:
                    perr.write(command)
                    perr.write('%s\n' % estr)
            except Exception as estr:
                perr.write(command)
                perr.write('%s\n' % estr)

        bash('sudo chmod -R 766 %s\n' % DOCROOT)
        bash('sudo chmod -R 755 %s\n' % library_dir_tree)
        bash('sudo semanage fcontext -a -t httpd_sys_rw_content_t "%s(/.*)?"\n' % DOCROOT)

    for log in logfiles:
        pathstr = '%s/Ruleset_Performance/Ruleset_Performance/%s' % (DOCROOT, log)
        print('\tCreating %s' % pathstr)

        try:
            command = 'sudo mkdir -p %s\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
            command = 'sudo chmod 766 %s\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
            command = 'sudo semanage fcontext -a -t httpd_sys_rw_content_t "%s(/.*)?"\n' % pathstr
            pout.write(command)
            call([command], shell=True, stderr=perr, stdout=pout)
        except OSError as estr:
            if str(estr).find('File exists') >= 0:
                pass
            else:
                perr.write('%s\n' % estr)
        except Exception as estr:
            perr.write('%s\n' % estr)
    bash('sudo ln -s %s %s/Ruleset_Performance/lib' % (LIBPATH, DOCROOT))
    pout.write('setting file/directory ownership\n')
    bash('sudo chown -R centos:apache %s\n' % DOCROOT)
    bash('sudo chown -h -R centos:apache %s\n' % DOCROOT)


def install_atf_programs(action):
    orig_cnt = err_cnt
    if action == UPDATE:
        bash('sudo rm -f -r atf\n')
    bash('git clone -b %s "ssh://git@stash.secureworks.net:7999/is/atf.git"\n' % os.environ['TestEnv'])
    pout.write('installing ATF libraries and utilities\n')
    bash('sudo cp -r --no-preserve=mode,ownership atf/lib/* /var/www/cgi-bin/lib/\n')
    bash('sudo cp -r --no-preserve=mode,ownership atf/utilities/* /var/www/cgi-bin/lib/\n')
    bash(
        'sudo cp -r --no-preserve=mode,ownership atf/htdocs/Ruleset_Performance/* /var/www/html/htdocs/Ruleset_Performance/\n')
    bash('sudo chown centos:apache /var/www/html/htdocs/Ruleset_Performance/*\n')
    bash('tar -xf atf/packages/paramiko-expect-0.2.8.tar\n')
    bash('cd paramiko-expect-0.2.8;sudo python setup.py build install --record expect.txt\n')
    bash('tar -xzf atf/packages/scpclient-0.7.tar.gz\n')
    bash('cd scpclient-0.7;sudo python setup.py build install --record scpclient.txt\n')
    bash('sudo mv /var/www/cgi-bin/lib/axsess.py /usr/lib/python2.7/site-packages/\n')
    bash('sudo mv /var/www/cgi-bin/lib/vault.py /usr/lib/python2.7/site-packages/\n')
    return (err_cnt - orig_cnt)


def install_ssh_keys(key_path):
    import hvac
    import warnings
    def noop(*args, **kargs):
        pass

    warnings.warn = noop
    client = hvac.Client(url=os.environ.get('VAULT_ADDR'))
    response = client.auth_approle(os.environ.get('VAULT_ROLE_ID'), os.environ.get('VAULT_SECRET_ID'))

    TOKEN = response['auth']['client_token']
    client.token = TOKEN
    assert client.is_authenticated()
    try:
        secrets_dict = client.secrets.kv.read_secret_version(path=key_path, mount_point='atf')
        pout.write('git keys fetched\n%s\n' % str(secrets_dict))
        assert 'data' in secrets_dict.keys(), 'failed to fetch data from %s' % key_path
        keys = secrets_dict['data']['data']
        assert 'public-key' in keys, 'public key is missing from %s' % key_path
        assert 'private-key' in keys, 'private key is missing from %s' % key_path

    except Exception as e:
        perr.write('FAILED to retrieve keys:\n %s' % str(e))
        raise AssertionError('Failed to read from Vault %s\n' % str(e))
        exit(4)
    if os.path.exists('%s/.ssh' % os.getcwd()) == False:
        os.mkdir('%s/.ssh' % os.getcwd())

    with open('%s/.ssh/id_rsa' % os.getcwd(), 'w') as f:
        f.write(keys['private-key'])
    with open('%s/.ssh/id_rsa.pub' % os.getcwd(), 'w') as f:
        f.write(keys['public-key'])
    with open('%s/.ssh/known_hosts' % os.getcwd(), 'a') as f:
        f.write(keys['known_hosts'])

    bash('chmod 600 %s/.ssh/id_rsa' % os.getcwd())
    bash('chmod 600 %s/.ssh/id_rsa.pub' % os.getcwd())


def install_certificates():
    import hvac
    import warnings
    def noop(*args, **kargs):
        pass

    warnings.warn = noop
    client = hvac.Client(url=os.environ.get('VAULT_ADDR'))
    response = client.auth_approle(os.environ.get('VAULT_ROLE_ID'), os.environ.get('VAULT_SECRET_ID'))
    TOKEN = response['auth']['client_token']
    client.token = TOKEN
    assert client.is_authenticated()
    key_path = '%s/apache' % os.environ['TestEnv']
    try:
        secrets_dict = client.secrets.kv.read_secret_version(path=key_path, mount_point='atf')
        pout.write('apache secrets fetched\n%s\n' % str(secrets_dict))
        assert 'data' in secrets_dict.keys(), 'failed to fetch data from %s' % key_path
        keys = secrets_dict['data']['data']
        with open('/tmp/apache_certificate', 'w') as f:
            f.write(keys['certificate'])
        bash('sudo mv /tmp/apache_certificate %s\n' % keys['certpath'])
        with open('/tmp/apache_key', 'w') as f:
            f.write(keys['key'])
        bash('sudo mv /tmp/apache_key %s\n' % keys['keypath'])
    except Exception as e:
        perr.write('FAILED to retrieve apache secrets:\n %s' % str(e))
        raise AssertionError('Failed to read from Vault %s\n' % str(e))
        exit(4)


INSUFFICIENT_ARGS = '\n\nERROR:Insufficient number of arguments...\n\t%s install <environment> <role_id> <secret_id>\n'
INVALID_ENV = '\nERROR:Invalid environment in CLI arguments'

if __name__ == '__main__':
    pout.write(str(sys.argv))
    action = sys.argv[1]
    try:
        if action == 'install':
            environment, role_id, secret_id = [sys.argv[x] for x in range(2, 5)]
            assert environment.lower() in ['agile', 'pilot', 'production']
            os.environ['TestEnv'] = environment
            os.environ['VAULT_ROLE_ID'] = role_id
            os.environ['VAULT_SECRET_ID'] = secret_id
            os.environ['VAULT_ADDR'] = 'https://vault.aws.secureworks.com'
            os.environ['PYTHONPATH'] = '/var/www/cgi-bin/lib'
            bash('sudo rm -f /etc/environment\n')
            with open('vault.env', 'w') as f:
                for envvar in ['TestEnv', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_ADDR', 'PYTHONPATH']:
                    f.write('export %s=%s\n' % (envvar, os.environ[envvar]))
                    bash('sudo echo %s=%s >> environment\n' % (envvar, os.environ[envvar]))
                bash('sudo mv environment /etc/\n')
                f.write('alias vi=vim\n')
            with open('.bash_profile', 'r') as p:
                profile = p.read()
            vault_str = 'source vault.env\n'
            if profile.find(vault_str) < 0:
                profile += vault_str
                with open('.bash_profile', 'w') as p:
                    p.write(profile)

    except IndexError:
        print(INSUFFICIENT_ARGS)
        perr.write(INSUFFICIENT_ARGS)
        perr.write(str(sys.argv))
        exit(3)
    except AssertionError:
        print(INVALID_ENV)
        perr.write(INVALID_ENV)
        perr.write(str(sys.argv))
        exit(2)
    except Exception as estr:
        perr.write(str(estr))
        exit(1)

    package_list = None
    if action == 'install':
        success = package(INSTALL, package_list)
        mount_efs(INSTALL)
        install_ssh_keys('ssh_keys/git')
        create_atf_dir_tree()
        success += install_atf_programs(action)
        install_session_user_files()
        install_sym_links()
        install_apache_files()
        bash('sudo chown -R centos:apache %s\n' % DOCROOT)
        bash('sudo chown -h -R centos:apache %s\n' % DOCROOT)
        bash('sudo usermod -G apache centos\n')
        install_certificates()


    elif action == 'uninstall':
        remove_atf_dir_trees()
        success = package(UNINSTALL, package_list)
        bash('rm .ssh/id_rsa*')
        bash('rm .ssh/known_hosts')
        bash('rm -f vault.env')
        os.environ['TestEnv'] = ''
        os.environ['VAULT_ROLE_ID'] = ''
        os.environ['VAULT_SECRET_ID'] = ''
        os.environ['VAULT_ADDR'] = ''
        bash('sudo rm -f -r /etc/httpd\n')
        bash('sudo rm -f /etc/init.d/testrun\n')
        print(success)
    pout.close()
    perr.close()
