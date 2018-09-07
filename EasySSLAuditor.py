#!/usr/bin/python
# -*- coding: utf-8 -*-
## Program: EasySSLAuditor
## Author: Mayank Sahu <mynk_sh@yahoo.co.in>
##Current Version: 1.10

import argparse
import socket
import ssl
import csv
import re
import OpenSSL
import datetime
#from cryptography import x509

parser = argparse.ArgumentParser(description= "Welcome to EasySSLAuditer help section; \n\n ** Provide a CSV file with list of SSL domain and port; It will provide an CVS file as output of SSL certificate details")
parser.add_argument('-if','--input', required=True, nargs='?', type=argparse.FileType('r'), help='Provide csv file with hostname and port Format:[hostname,port]')
parser.add_argument('-of','--output', required=True, nargs='?', type=argparse.FileType('wb',0), help='Provide name of the file where output will be stored')
parser.add_argument('-t','--timeout', required=False, nargs='?', type=int,default='4', help='Set the SSL connection wait time : Default is 4 Sec')
args = parser.parse_args()

def port_safecheck(port):
                if port.isdigit():
                   new_port = int(port)
                   logf.write('Trimmed Port: {0} \n'.format(new_port))
                else:
                   new_port = 443 #default port 443
                   logf.write('Setting Default port: {0} \n'.format(new_port))
                return new_port

def url_safecheck(host):
                new_url = re.sub('.*w\.', '', host, 1)
                logf.write('Trimmed domain: {0} \t'.format(new_url))
                return new_url

def gather_details(host,port):
              try:
                  ipaddressofhost = socket.gethostbyname(host) #getting IP of host
                  try:
                      #ipaddressofhost = socket.gethostbyname(host) #getting IP of host
                      print (" **Creating a connection socket: {0}:{1} \n".format(host,port))
                      logf.write(" **Creating a connection socket: {0}:{1} \n".format(host,port))
                      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                      sock.settimeout(args.timeout)
                      #sock.setblocking(0)
                      wrappedSocket = ssl.wrap_socket(sock)
                      wrappedSocket.connect((host,port))
                  except Exception as e:
                      print (' **Something went worng while connecting: \t{0} \n'.format(str(e)))
                      logf.write(" **Something went worng while connecting: \t{0} \n".format(str(e)))
                      writer.writerow({'Hostname':safe_domain,'Port':safe_port,'Comments':format(str(e)),'IP address':ipaddressofhost})
                      wrappedSocket.close()
                  except socket.error as err:
                    print ('Check the domain name: {0}'.format(str(err)))
                    logf.write('Check the domain name: {0}'.format(str(err)))
                    writer.writerow({'Hostname':safe_domain,'Port':safe_port,'Comments':format(str(err))})
                  except (error, timeout) as tout:
                    print ("No connection to host: {0}".format(tout))
                    logf.write("No connection to host: {0}".format(tout))
                    writer.writerow({'Hostname':safe_domain,'Port':safe_port,'Comments':format(str(tout))})
                  else:
                    #Creating cert objects
                    #cert=ssl.get_server_certificate((host, port))
                    cert= ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    # Getting all the details for domain
                    #ipaddressofhost = socket.gethostbyname(host)
                    #print x509.get_notAfter()
                    #curdate = now.strftime("%Y%m%d%H%M%SZ")
                    #print curdate
                    enddate = datetime.datetime.strptime(x509.get_notAfter(),"%Y%m%d%H%M%SZ")
                    startdate = datetime.datetime.strptime(x509.get_notBefore(),"%Y%m%d%H%M%SZ")
                    issuerxml = x509.get_issuer()
                    issuer = issuerxml.CN #fetched from above variable
                    issuedtoxml = x509.get_subject()
                    issuedto = issuedtoxml.CN #fetched from above variable
                    hasexpired = x509.has_expired()
                    #diffdays = curdate - x509.get_notAfter() #enddate
                    remaindays = 0
                    comments = ''
                    certificate_details = [startdate,enddate,issuer,hasexpired,issuedto,ipaddressofhost,remaindays,comments]
                    # 0. Start Date    4. Issued to
                    # 1. End Date      5. IP address of host
                    # 2. Issuer        6. Days Remaining
                    # 3. Has Expired
                    logf.write(' Start date: {0}; End Date: {1}; Issued by: {2}; Is it Expired: {3}; Issued to {4}; IP add {5}; Days remaining {6} \n'.format(certificate_details[0],certificate_details[1],certificate_details[2],certificate_details[3],certificate_details[4],certificate_details[5],certificate_details[6]))
                    print(' Start date: {0}; End Date: {1}; Issued by: {2}; Is it Expired: {3}; Issued to: {4} IP Address {5}; Days remaining {6} \n'.format(certificate_details[0],certificate_details[1],certificate_details[2],certificate_details[3],certificate_details[4],certificate_details[5],certificate_details[6]))
                    write_to_csv(certificate_details)
                    #wrappedSocket.close()
              except socket.error as err:
                    print ('Check the domain name: {0}'.format(str(err)))
                    logf.write('Check the domain name: {0}'.format(str(err)))
                    writer.writerow({'Hostname':safe_domain,'Port':safe_port,'Comments':format(str(err))})
              except Exception as e:
                    print ('Something went worng while gathing details: \t{0}'.format(str(e)))
                    logf.write('Something went worng while gathing details: \t{0}'.format(str(e)))
                    raise SystemExit()

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
                   writer.writerow({'Hostname':safe_domain,'Port':safe_port,'IP address':certificate_details[5],'Issued_by':certificate_details[2],'Issued_To':certificate_details[4],'Start_Date':certificate_details[0],'End_Date':certificate_details[1],'Remaining _days':certificate_details[6]})
                   return True
               except Exception as e:
                   print ('Something went worng in function intilize_csv: {0}'.format(str(e)))
                   logf.write('Something went worng in function intilize_csv: {0} \n'.format(str(e)))
                   return False


if __name__ == "__main__":
    with open('log.txt', 'a+') as logf:
        logf.write('\n\n*********SSL Verification initiated**********\n\n');
        print ("Default Timeout {0} \n".format(args.timeout))
        now = datetime.datetime.now()
        print ("\n\t\tCurrent time of the system {0} \n".format(str(now)))
        logf.write("\n\t\tCurrent time of the system {0}\n".format(str(now)))
        try:
           #Creating reader object
           reader = csv.DictReader(args.input)
           # Creating row header & writer object
           fieldsinputput = ['Hostname','Port','IP address','Issued_by','Issued_To','Start_Date','End_Date','Remaining _days', 'Comments']
           writer = csv.DictWriter(args.output,fieldsinputput,restval = '')
           writer.writeheader()
           #intilize_CSV
           #print reader
           #headers = reader.fieldnames
           #print headers
           #Printing the headers
           #logf.write(headers)
           #with open('log.txt', 'a+') as logf:
           for row in reader:
            print 'Iterating through host file for domain names \t'
	    try:
                safe_domain = url_safecheck(row['hostname'])
                safe_port = port_safecheck(row['port'])
                print ('Selected Domain and Port : {0}:{1} \n'.format(safe_domain,safe_port))
                logf.write('Selected Domain and Port : {0}:{1} \n'.format(safe_domain,safe_port))
                # Getting certificate details of each certificate
                gather_details(safe_domain,int(safe_port))
                #check_ssl(row[0])
                #print "************************\n\n"
            except Exception as e:
                 logf.write('Error while Iterating HOST File {0} \n'.format(str(e)))
                 #logf.write('test')
                 print ('Error while Iterating HOST File {0} \n'.format(str(e)))
        except Exception as err:
              print ('Some Error from 2nd :{0} \n'.format(str(err)))
        logf.write('\n\n************Exit**************\n\n')
