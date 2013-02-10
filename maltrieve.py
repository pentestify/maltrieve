# Copyright 2013 Kyle Maxwell
# Includes code from mwcrawler, (c) 2012 Ricardo Dias. Used under license.

# Maltrieve - retrieve malware from the source

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/

import urllib2
import logging
import argparse
import tempfile
import re
import hashlib
import os
import sys
import datetime
import xml.etree.ElementTree as ET
import multiprocessing

from bs4 import BeautifulSoup

from malutil import *

NUMPROCS = 4

# main worker function
def get_malware(q,dumpdir, hashes):
    while True:
        url = q.get()
        logging.debug("Fetched URL %s from queue", url)
        mal = get_URL(url)
        if mal:
            malfile=mal.read()
            md5 = hashlib.md5(malfile).hexdigest()
            if md5 not in hashes:
                logging.info("Found file %s at URL %s", md5, url)
                # store the file and log the data
                # TODO: replace with malwarehouse or vxcage integration
                with open(os.path.join(dumpdir, md5), 'wb') as f:
                    f.write(malfile)
                hashes[md5] = True
        q.task_done()

# logging

def listener_configurer():
    root = logging.getLogger()
    h = logging.handlers.RotatingFileHandler('mptest.log', 'a', 300, 10)
    f = logging.Formatter('%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s')
    h.setFormatter(f)
    root.addHandler(h)

# preprocessing
def get_XML_list(url,q, pasturls):
    malwareurls = []
    descriptions = []

    tree = get_XML(url)
    if tree:
        descriptions = tree.findall('channel/item/description')

    for d in descriptions:
        logging.debug('Parsing description %s', d.text)
        url = d.text.split(' ')[1].rstrip(',')
        if url == '-':
            url = d.text.split(' ')[4].rstrip(',')
        url = re.sub('&amp;','&',url)
        if not re.match('http',url):
            url = 'http://'+url
        malwareurls.append(url)

    for url in malwareurls:
        push_malware_URL(url,q, pasturls)

def push_malware_URL(url,q, pasturls):
    url = url.strip()
    if url not in pasturls:
        q.put(url)

def main():
    malq = multiprocessing.JoinableQueue()
    pasturls = set()
    now = datetime.datetime.now()

    # track which hashes we've already grabbed and saved
    manager= multiprocessing.Manager()
    hashes = manager.dict()

    # logging isn't trivial anymore
    logq = multiprocessing.Queue(-1)
    listener = multiprocessing.Process(target=listener_process,
                                       args=(logq,listener_configurer))
    listener.start()

    parser = argparse.ArgumentParser()
#   parser.add_argument("-t", "--thug", help="Enable thug analysis", action="store_true")
    parser.add_argument("-p", "--proxy", 
                        help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir", 
                        help="Define dump directory for retrieved files")
    parser.add_argument("-l", "--logfile", 
                        help="Define file for logging progress")
    args = parser.parse_args()

    # TODO: make multiprocessing-safe
    if args.logfile:
        logging.basicConfig(filename=args.logfile, 
                            level=logging.DEBUG, 
                            format='%(asctime)s %(processName)s %(message)s', 
                            datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG, 
                            format='%(asctime)s %(processName)s %(message)s', 
                            datefmt='%Y-%m-%d %H:%M:%S')

    # Enable thug support 
    # https://github.com/buffer/thug
    # TODO: rewrite and test
    '''
    try:
        if args.thug:
            loadthug()
    except Exception as e:
        logging.warning('Could not enable thug (%s)', e)
    '''

    # TODO: test more thoroughly
    if args.proxy:
        proxy = urllib2.ProxyHandler({'http': args.proxy})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
        logging.info('Using proxy %s', args.proxy)
        my_ip = urllib2.urlopen('http://whatthehellismyip.com/?ipraw').read()
        logging.info('External sites see %s',my_ip)

    # define where to save the malware we grab
    # TODO: use malwarehouse or vxcage or similar
    if args.dumpdir:
        try:
            d = tempfile.mkdtemp(dir=args.dumpdir)
            dumpdir=args.dumpdir
        except Exception as e:
            logging.error('Could not open %s for writing (%s), using default', 
                          dumpdir, e)
            dumpdir = '/tmp/malware'
        else:
            os.rmdir(d)
    else:
        dumpdir = '/tmp/malware'

    logging.info('Using %s as dump directory', dumpdir)

    if os.path.exists('hashes.obj'):
        with open('hashes.obj','rb') as hashfile:
            hashes = pickle.load(hashfile)

    if os.path.exists('urls.obj'):
        with open('urls.obj', 'rb') as urlfile:
            pasturls = pickle.load(urlfile)

    for i in range(NUMPROCS):
        worker = multiprocessing.Process(target=get_malware, 
                                         args=(malq,dumpdir,hashes,))
        worker.daemon = True
        worker.start()
    
    get_XML_list('http://www.malwaredomainlist.com/hostslist/mdl.xml',
                 malq, pasturls)
    get_XML_list('http://malc0de.com/rss',malq, pasturls)
    
    # TODO: wrap these in a function
    for url in get_URL('http://vxvault.siri-urz.net/URL_List.php'):
        if re.match('http', url):
            push_malware_URL(url,malq, pasturls)
    
    sacourtext=get_URL('http://www.sacour.cn/showmal.asp?month=%d&year=%d' % 
                  (now.month, now.year)).read()
    for url in re.sub('\<[^>]*\>','\n',sacourtext).splitlines():
        push_malware_URL(url,malq, pasturls)
    
    # appears offline
    # minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
    # appears offline
    # malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
    
    malq.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
    else:
        with open('hashes.obj','wb') as hashfile:
            pickle.dump(hashfile, hashes)
    
        with open('urls.obj', 'wb') as urlfile:
            pickle.dump(urlfile, pasturls)
