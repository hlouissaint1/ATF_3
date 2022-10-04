#!/usr/bin/python3

import re
import requests
from requests.auth import HTTPBasicAuth
from glob import glob
import sys
from lxml import etree
from lxml.builder import E
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from os.path import basename, dirname
from hashlib import md5
import os
import logging

PARSER = etree.XMLParser(remove_blank_text=True)

NFS_LOGPATH = '/var/log'
MODULE = 'atf_image_dl.py'
NFS_LOG = 'atf_image_dl.log'

logging.basicConfig(
    format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    filename='%s/%s' % (NFS_LOGPATH, NFS_LOG),
    filemode='w',
    level=logging.DEBUG)

NFSLOG = logging.getLogger('ftd_regression')
rhandler = logging.FileHandler('%s/%s' % (NFS_LOGPATH, NFS_LOG))
formatter = logging.Formatter('%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s')
rhandler.setFormatter(formatter)
NFSLOG.addHandler(rhandler)
NFSLOG.setLevel(logging.DEBUG)
NFSLOG.debug('Initialized logging')


def parse_iso_html(index_file):
    iso_list = iso_dates = None
    with open(index_file, 'r') as f:
        contents = f.read()
        iso_list = re.findall('\"https.*iso\"', contents)
        iso_dates = re.findall('\w{3}\s+\d{1,2}\s+\d{1,2}:\d{1,2}:\d{1,2}\s+UTC\s+\d{4}', contents)
    return (iso_list, iso_dates)


class Depot(object):
    def __call__(self, pFunction):

        def depot_call(self, iso_url=None, path=None, **opts):
            bad_status = lambda code, url: 'Bad status code %d' % code
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            h = requests.head(self.url, allow_redirects=True, verify=False)
            assert h.status_code == 200, bad_status(h.status_code, url)
            if iso_url == None:
                # depot_resp = requests.get('%s' % (self.url),  auth=HTTPBasicAuth(self.user, self.password), cookies=jar, verify=False)
                depot_resp = requests.get(self.url, cookies=h.cookies, verify=False)
                cb_par = depot_resp.text
            else:
                try:
                    url = iso_url
                    tmpfile = '/tmp/%s' % url.split('/')[-1]
                    local_filename = path + '/' + url.split('/')[-1]
                    with requests.get(url, stream=True, cookies=h.cookies, verify=False) as depot_resp:
                        depot_resp.raise_for_status()
                        with open(tmpfile, 'wb') as iso_file:
                            hash = md5()
                            for chunk in depot_resp.iter_content(chunk_size=8192):
                                hash.update(chunk)
                                iso_file.write(chunk)
                        self.md5sum = hash.hexdigest()
                        os.renames(tmpfile, local_filename)
                        md5_filename = local_filename.replace('.iso', '.md5')
                        with open(md5_filename, 'w') as md5_file:
                            md5_file.write(self.md5sum)
                        cb_par = (self.md5sum, local_filename)
                except Exception as estr:
                    print('exception while downloading: %s' % depot_resp.reason)
                    pass
            assert depot_resp.status_code == 200, bad_status(depot_resp.status_code, self.url + ' ' + self.uri)
            processed = pFunction(self, cb_par, **opts)
            return (processed)

        return (depot_call)


class Image:
    def __init__(self, ):
        self.url = 'https://agile-repo.internal.secureworks.net/service/rest/repository/browse/agile-isensor-raw/ISOS'
        self.uri = ''
        self.iso_dir = ''
        self.nfs_image_dir = '/var/opt/secureworks/isos'
        self.md5sum = ''

    @Depot()
    def download_image(self, resp, **opts):
        md5sum, local_file = resp
        return (md5sum, local_file)

    @Depot()
    def get_iso_list(self, resp):
        iso_list = iso_dates = None
        iso_list = re.findall('\"https.*iso\"', resp, re.MULTILINE)
        iso_dates = re.findall('\w{3}\s+\d{1,2}\s+\d{1,2}:\d{1,2}:\d{1,2}\s+UTC\s+\d{4}', resp, re.MULTILINE)
        iso_sizes = re.findall('\d{8,}', resp, re.MULTILINE)
        iso_versions = []
        for iso in iso_list:
            version = re.findall('\d+\.\d+\.\d+\-\d+', iso)[0]
            if version not in iso_versions:
                iso_versions.append(version)
        return (iso_list, iso_dates, iso_sizes, iso_versions)

    def update_local_iso_inventory(self):
        dates_equal = lambda f, d: f.attrib['date'] == d.attrib['date']
        sizes_equal = lambda f, d: f.attrib['size'] == d.attrib['size']
        names, dates, sizes, versions = self.get_iso_list()
        xml = E.inventory()
        new_iso_images_downloaded = []
        for version in versions:
            images = E.images(version=version)
            for isoname in names:
                v = re.findall('\d+\.\d+\.\d+\-\d+', isoname)[0]
                if v != version:
                    print('version %s != %s' % (v, version))
                    continue
                x = names.index(isoname)
                url = dirname(names[x].replace('"', ''))
                file = basename(names[x].replace('"', ''))
                images.set('url', url)
                md5sum = ''
                try:
                    iso_type = re.search('internal|ktos|auto', file).group()
                except AttributeError:
                    iso_type = 'canonical'
                isonode = E.iso(E.path(), E.md5sum(), name=file, size=sizes[x], date=dates[x], state='detected',
                                type=iso_type)
                images.append(isonode)
            xml.append(images)
        with open('%s/detect_inventory.xml' % self.nfs_image_dir, 'w') as f:
            f.write(etree.tostring(xml, pretty_print=True).decode('utf-8'))

        try:
            inventory = etree.parse('%s/inventory.xml' % self.nfs_image_dir, PARSER)
        except OSError:  # the inventory doesn't exist so created it and insert what was found on the depot
            with open('%s/inventory.xml' % self.nfs_image_dir, 'w') as W:
                with open('%s/detect_inventory.xml' % self.nfs_image_dir, 'r') as R:
                    W.write(R.read())
            inventory = etree.parse('%s/inventory.xml' % self.nfs_image_dir, PARSER)

        downloading = {}
        for iso in xml.xpath('//iso'):
            founded = inventory.xpath('//iso[@name="%s"]' % iso.attrib['name'])
            version = re.findall('\d+\.\d+\.\d+\-\d+', iso.attrib['name'])[0]
            major_version = re.findall('\d+\.\d+', version)[0]
            path = self.nfs_image_dir + '/' + major_version
            pnode = iso.getparent()
            if os.path.exists(path) == False:
                os.makedirs(path)
            if len(founded) == 0:  # this is a new iso not in the inventory
                inventory_pnodes = inventory.xpath('//images[@version="%s"]' % version)
                if len(
                        inventory_pnodes) == 0:  # This is the first time this version appeared in the depot...copy the whole parent node
                    inventory.getroot().insert(0, pnode)
                found = inventory.xpath('//iso[@name="%s"]' % iso.attrib['name'])[0]
            else:
                found = founded[0]
            if found.attrib['state'] == 'deprecated':  # we've decided this is an older version we never want to update
                print('iso %s is deprecated' % found.attrib['name'])
                continue

            if dates_equal(found, iso) and sizes_equal(found, iso) and found.attrib[
                'state'] == 'downloaded':  # the image on depot is already on nfs server
                print('iso %s has already been downloaded' % found.attrib['name'])
                continue
            iso_path = path
            found.getparent().set('status', 'downloading')
            with open('%s/inventory.xml' % self.nfs_image_dir, 'w') as W:
                W.write(etree.tostring(inventory, pretty_print=True).decode('utf-8'))

            md5sum, local_path = self.download_image(pnode.attrib['url'] + '/' + iso.attrib['name'], iso_path)
            path = found.find('path')
            downloading[version] = found.getparent()
            if path != None:
                found.remove(path)
            path = E.path(local_path)
            found.insert(0, path)
            md5_node = found.find('md5sum')
            if md5_node != None:
                found.remove(md5_node)
            md5_node = E.md5sum(md5sum)
            found.insert(0, md5_node)
            found.set('state', 'downloaded')
            found.set('date', iso.attrib['date'])
            found.set('size', iso.attrib['size'])
            new_iso_images_downloaded.append(local_path)

        for downloaded in downloading.values():
            downloaded.set('status', 'downloaded')
        with open('%s/inventory.xml' % self.nfs_image_dir, 'w') as f:
            f.write(etree.tostring(inventory, pretty_print=True).decode('utf-8'))

        return (new_iso_images_downloaded)


if __name__ == '__main__':
    # from pprint import pprint
    I = Image()
    new_images = I.update_local_iso_inventory()
    print('%d images downloaded\n' % len(new_images))
    # pprint(new_images)
