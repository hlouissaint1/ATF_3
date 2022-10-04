__author__ = "Himmler Louissaint"

import boto3
import os
import time
import logging
from os import popen
from vault import Vault


AWS_LOGPATH = '/var/www/cgi-bin/lib/logs'
MODULE = 'scwxFTDlib.py'
AWS_LOG = 'aws_ec2.log'


logging.basicConfig(
    format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    filename='%s/%s' % (AWS_LOGPATH, AWS_LOG),
    filemode='w',
    level=logging.DEBUG)


class AWS_EC2_Instance(object):
    def __init__(self, ip_address, vpc_id, vpc_cred_path):
        self.access_key = None
        self.secret_key = None
        self.ip_address = ip_address
        self.vpc_id = vpc_id
        self.vpc_cred_path = vpc_cred_path
        self.filters = [{
            'Name': 'vpc-id',
            'Values': [vpc_id],
        }]
        self._configure_aws()


    def _configure_aws(self):
        logging.debug('Retrieving vault VAULT_ROLEID and VAULT_SECRET from vault')
        Vault.login('atf')
        role_id = Vault.read_secret('vault','VAULT_ROLEID')
        access_id = Vault.read_secret('vault','VAULT_SECRET')
        token = os.popen("vault write auth/approle/login role_id=%s secret_id=%s | grep -m 1 token | awk '/^token/ { print $2 }'" % (role_id, access_id)).read()
        resp = os.popen('vault login %s' % (token)).read()
        logging.debug('Configuring AWS for VPC %s' % self.vpc_id)
        self.access_key, self.secret_key =  os.popen("vault read %s | awk '/^access_key/ { print $2 }; /^secret_key/ { print $2 }'" % self.vpc_cred_path).read().split()


    def manage_ec2_instance(self, action):
        status = None
        ec2 = boto3.client("ec2", region_name="us-east-1",  aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
        ec2_instances = ec2.describe_instances(Filters=self.filters)
        for reservation in ec2_instances['Reservations']:
           for instance in reservation['Instances']:
              if instance['PrivateIpAddress'] == self.ip_address :
                 instance_id = instance['InstanceId']
                 logging.debug('EC2 Instance with IP: %s is found for the %s VPC.' % (self.ip_address, self.vpc_id))
                 logging.debug('Fetching the instance state for %s.' % self.ip_address)
                 status = self.get_ec2_instance_status()
                 if action.lower() == 'start' and status.lower() in ('stopped', 'shutting-down', 'stopping'):
                    logging.debug('Starting the EC2 Instance with IP: %s...' % self.ip_address)
                    response = ec2.start_instances(InstanceIds=[instance_id])
                    status = response['StartingInstances'][0]['CurrentState']['Name']
                 elif action.lower() == 'stop' and status.lower() in ('running', 'pending'):
                    logging.debug('Stopping the EC2 Instance with IP: %s...' % self.ip_address)
                    response = ec2.stop_instances(InstanceIds=[instance_id])
                    status = response['StoppingInstances'][0]['CurrentState']['Name']
                 else:
                    logging.debug('EC2 instance %s is already at expected state %s. Nothing to do with the EC2 Instance.' % (self.ip_address, status))
                    return status
                 logging.debug('Waiting 3 minutes to give the instance enough time to %s.' % action)
                 time.sleep(180) # wait 3 minutes to give the instance enough time to start/stop.
                 status = self.get_ec2_instance_status()
                 logging.debug('Status %s is retuned after action: %s is performed on the EC2 Instance with IP: %s ' % (status, action, self.ip_address))
                 return status 


    def get_ec2_instance_status(self):
        ec2 = boto3.client("ec2", region_name="us-east-1",  aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
        ec2_instances = ec2.describe_instances(Filters=self.filters)
        for reservation in ec2_instances['Reservations']:
           for instance in reservation['Instances']:
              if instance['PrivateIpAddress'] == self.ip_address :
                 return instance['State']['Name']


    def verify_ec2_instance(self, expected_status, max_wait_time, inc_time):
        status = None
        logging.debug('\nWaiting for %s seconds to get the %s status. Will be checking every %s seconds...' % (max_wait_time, expected_status, inc_time))
        for i in range(0, int(max_wait_time), int(inc_time)):
            ec2 = boto3.client("ec2", region_name="us-east-1",  aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
            ec2_instances = ec2.describe_instances(Filters=self.filters)
            for reservation in ec2_instances['Reservations']:
                for instance in reservation['Instances']:
                    status = instance['State']['Name']
                    if (instance['PrivateIpAddress'] == self.ip_address):
                        if (status.lower() == expected_status.lower()):
                            logging.debug('EC2 instance %s has reached the expected status %s.' % (self.ip_address, expected_status))
                            return status
                        else:
                            logging.debug('The current EC2 Instance state is %s and we are waiting for %s. Sleeping for %s secs.' % (status, expected_status, inc_time))
                            time.sleep(int(inc_time))
        return status      


if __name__ == '__main__':
    
    ATF_VPC_CREDENTIAL_PATH="voltron-cli/aws/us-east-1/prod/vpc/atf-prod-vpc-7558561c-4007-40db-96c4-9b2815949a6e/creds/vpc-7558561-write"
    ISENSOR_VPC_CREDENTIAL_PATH="voltron-cli/aws/us-east-1/prod/vpc/isensor-dev-d93e49bb-8654-414b-8476-ea6f13e8ecfd/creds/vpc-d93e49b-write"
    ATF_VPC = 'vpc-0375f6df9bc325c16'
    I_VPC = 'vpc-0d69173470c40a9cf' 
    obj = AWS_EC2_Instance('10.238.83.183', ATF_VPC, ATF_VPC_CREDENTIAL_PATH)
#    obj = AWS_EC2_Instance('10.238.129.96', I_VPC, ISENSOR_VPC_CREDENTIAL_PATH)
    status = obj.get_ec2_instance_status()
    obj.manage_ec2_instance('start')
#    obj.manage_ec2_instance('stop')
###    status = obj.get_ec2_instance_status()
#    logging.debug('Verifying the EC2 Instance state')
#    print('Verifying the EC2 Instance state')
#    resp = obj.verify_ec2_instance('running', 300, 40)
#    resp = obj.verify_ec2_instance('stopped', 300, 40)
#    logging.debug('**** The current state of EC2 Instance %s is %s.' % (obj.ip_address, resp))
#    print('**** The current state of EC2 Instance %s is %s.' % (obj.ip_address, resp))

