#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import socket
import ssl
import csv
import re
import OpenSSL
import datetime

parser = \
    argparse.ArgumentParser(description='Welcome to Travelex SSLAuditer; Provide a CSV file with list of SSL domain and port; It will provide an CVS file as output of SSL certificate details'
                            )
parser.add_argument('--input', required=True, nargs='?',
                    type=argparse.FileType('r'),
                    help='Provide csv file with hostname and port Format:[hostname,port]'
                    )
parser.add_argument('--output', required=True, nargs='?',
                    type=argparse.FileType('wb', 0),
                    help='Provide name of the file where output will be stored'
                    )
args = parser.parse_args()


def port_safecheck(port):
    if port.isdigit():
        new_port = port
        logf.write('New Port: {0} \n'.format(new_port))
    else:
        new_port = 443  # setting default port 443
        logf.write('Setting Dafault port: {0} \n'.format(new_port))
    return new_port


def url_safecheck(host):
    new_url = re.sub('.*w\.', '', host, 1)
    logf.write('New domain: {0} \n'.format(new_url))
    return new_url


def checkdetails(host, port):
    cert = ssl.get_server_certificate((host, port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
            cert)

                # Getting all the details for domain

    enddate = datetime.datetime.strptime(x509.get_notAfter(),
            '%Y%m%d%H%M%SZ')
    startdate = datetime.datetime.strptime(x509.get_notBefore(),
            '%Y%m%d%H%M%SZ')
    issuerxml = x509.get_issuer()
    issuer = issuerxml.CN
    issuedtoxml = x509.get_subject()
    hasexpired = x509.has_expired()
    issuedto = issuedtoxml.CN
    logf.write(' Start date: {0}; End Date: {1}; Issued by: {2}; Is it still Valid: {3} \n'.format(startdate,
               enddate, issuer, hasexpired))
    print ' Start date: {0}; End Date: {1}; Issued by: {2}; Is it Expired: {3}; Issued to: {4} \n'.format(startdate,
            enddate, issuer, hasexpired, issuedto)


if __name__ == '__main__':
    with open('log.txt', 'a+') as logf:
        logf.write('''

*********Entered Main**********

''')
        reader = csv.reader(args.input)
        headers = reader.next()
        for row in reader:
            try:
                safe_domain = url_safecheck(row[0])
                safe_port = port_safecheck(row[1])
                print 'Connecting: {0}:{1}'.format(safe_domain,
                        safe_port)
                logf.write('Connecting: {0}:{1}'.format(safe_domain,
                           safe_port))
                checkdetails(safe_domain, safe_port)
            except Exception, e:
                logf.write('CSV row: {0} || Error: {1} \n'.format(row,
                           str(e)))
                print 'Some Error:{0} \n'.format(str(e))
        logf.write('''

************Exit Main**************

''')