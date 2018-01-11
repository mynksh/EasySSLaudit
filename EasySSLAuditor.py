#! /usr/bin/python
# -*- coding: utf-8 -*-
## Program: EasySSLAuditor
## Author: Mayank Sahu <mynk_sh@yahoo.co.in>
## Current Version: 1.00
## Revision History:

import argparse
import socket
import ssl
import csv
import re
import OpenSSL
import datetime
#from cryptography import x509

parser = argparse.ArgumentParser(description= "Welcome to EasySSLAuditer help section; \n\n ** Provide a CSV file with list of SSL domain and port; It will provide an CVS file as output of SSL certificate details")
parser.add_argument('--input', required=True, nargs='?', type=argparse.FileType('r'), help='Provide csv file with hostname and port Format:[hostname,port]')
parser.add_argument('--output', required=True, nargs='?', type=argparse.FileType('wb',0), help='Provide name of the file where output will be stored')
args = parser.parse_args()

def port_safecheck(port):
                if port.isdigit():
                   new_port = port
                   logf.write('New Port: {0} \n'.format(new_port))
                else:
                   new_port = 443 #default port 443
                   logf.write('Setting Dafault port: {0} \n'.format(new_port))
                return new_port

def url_safecheck(host):
                new_url = re.sub('.*w\.', '', host, 1)
                logf.write('New domain: {0} \n'.format(new_url))
                return new_url

def gather_details(host, port):
                #ssl.settimeout(3)
                try:
                    ipaddressofhost = socket.gethostbyname(host)
                    cert=ssl.get_server_certificate((host, port))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    # Getting all the details for domain
                    enddate = datetime.datetime.strptime(x509.get_notAfter(),"%Y%m%d%H%M%SZ")
                    startdate = datetime.datetime.strptime(x509.get_notBefore(),"%Y%m%d%H%M%SZ")
                    issuerxml = x509.get_issuer()
                    issuer = issuerxml.CN
                    issuedtoxml = x509.get_subject()
                    hasexpired = x509.has_expired()
                    issuedto = issuedtoxml.CN
                    certificate_details = [startdate,enddate,issuer,hasexpired,issuedto,ipaddressofhost]
                    # 0. Start Date    4. Issued to
                    # 1. End Date      5. IP address of host
                    # 2. Issuer
                    # 3. Has Expired
                    logf.write(' Start date: {0}; End Date: {1}; Issued by: {2}; Is it Expired: {3}; Issued to {4}; IP add {5} \n'.format(certificate_details[0],certificate_details[1],certificate_details[2],certificate_details[3],certificate_details[4],certificate_details[5]))
                    print(' Start date: {0}; End Date: {1}; Issued by: {2}; Is it Expired: {3}; Issued to: {4} IP Address {5} \n'.format(certificate_details[0],certificate_details[1],certificate_details[2],certificate_details[3],certificate_details[4],certificate_details[5]))
                    write_to_csv(certificate_details)
                except Exception as e:
                    print ('Something went worng in function checkdetails: {0}'.format(str(e)))
                except socket.error as err:
                    print ('Check the domain name: {0}'.format(str(err))) 

def intilize_CSV():
               try:
                   #fieldsinputput = ['Hostname','Port','IP address','Issued_by','Issued_To','Start_Date','End_Date','Remaining _days']
                   #writer = csv.DictWriter(args.output,fieldsinputput,restval = '')
                   writer.writeheader()
               except Exception as err:
                     print ('Something went worng in function intilize_CSV: {0}'.format(str(e)))

def write_to_csv(certificate_details):
               try: #trying to write CSV and headers
                   #fieldsinputput = ['Hostname','Port','IP address','Issued_by','Issued_To','Start_Date','End_Date','Remaining _days']
                   #writer = csv.DictWriter(args.output,fieldsinputput,restval = '')
                   #writer.writeheader()
                   writer.writerow({'Hostname':safe_domain,'Port':safe_port,'IP address':certificate_details[5],'Issued_by':certificate_details[2],'Issued_To':certificate_details[4],'Start_Date':certificate_details[0],'End_Date':certificate_details[1],'Remaining _days':'123'})
                   return True
               except Exception as e:
                   print ('Something went worng in function intilize_csv: {0}'.format(str(e)))
                   logf.write('Something went worng in function intilize_csv: {0} \n'.format(str(e)))
                   return False


if __name__ == "__main__":
    with open('log.txt', 'a+') as logf:
        logf.write('\n\n*********Entered Main**********\n\n');
        #print args.input.readlines()
        try:
           #Creating reader object
           reader = csv.DictReader(args.input)
           # Creating row header & writer object
           fieldsinputput = ['Hostname','Port','IP address','Issued_by','Issued_To','Start_Date','End_Date','Remaining _days']
           writer = csv.DictWriter(args.output,fieldsinputput,restval = '')
           writer.writeheader()
           #intilize_CSV
           #print reader
           headers = reader.fieldnames
           print headers
           #print unicode(headers[0])
           # Printing the headers
           #logf.write(headers)
           #with open('log.txt', 'a+') as logf:
           for row in reader:
            print 'Iterating through host file for domain names'
            try:
                safe_domain = url_safecheck(row['hostname'])
                safe_port = port_safecheck(row['port'])
                print ('Connecting to : {0}:{1}'.format(safe_domain,safe_port))
                logf.write('Connecting to : {0}:{1}'.format(safe_domain,safe_port))
                # Getting certificate details of each certificate
                gather_details(safe_domain,safe_port)
                #check_ssl(row[0])
                #print "************************\n\n"
            except Exception as e:
                 logf.write('CSV row: {0} || Error: {1} \n'.format(row, str(e)))
                 #logf.write('test')
                 print ('Some Error from 1st :{0} \n'.format(str(e)))
        except Exception as err:
              print ('Some Error from 2nd :{0} \n'.format(str(err)))
        logf.write('\n\n************Exit Main**************\n\n')
