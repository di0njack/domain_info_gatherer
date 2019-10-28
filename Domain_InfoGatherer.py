#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DEVELOPED BY Di0nJ@ck - July 2017 - v2.0
__author__      = 'Di0nj@ck'
__version__     = 'v2.0'
__last_update__ = 'July 2017'

import sys
import socket

try:
    from ipwhois import IPWhois
except Exception as e:
    print(str(e))
    print(
    "[!] You need to install the Python WHOIS module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install ipwhois' ")
    sys.exit(0)

try:
    from pprint import pprint
except Exception as e:
    print(str(e))
    print(
    "[!] You need to install the Python Pretty Printer module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install pprint' ")
    sys.exit(0)

try:
    import dns.resolver
except Exception as e:
    print(str(e))
    print(
    "[!] You need to install the Python DNS Resolver Module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install dnspython' ")
    sys.exit(0)

try:
    import requests
except Exception as e:
    print(str(e))
    print(
    "[!] You need to install the Python Requests Module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install requests' ")
    sys.exit(0)

try:
    import bs4
except Exception as e:
    print(str(e))
    print(
    "[!] You need to install the Python Beautiful Soup 4 Module.  Install PIP (https://bootstrap.pypa.io/get-pip.py).  Then 'pip install beautifulsoup4' ")
    sys.exit(0)

 
def main():

   f_input = open("domains.txt", "r")
   f_output = open("Results.txt", "w")
   
   num_lines = sum(1 for line in open("domains.txt"))
   
   print ("\n" + "- A total of " + str(num_lines) + " domains will be resolved to an IP" + "\n")
   
   i = 1
   nslookup = dns.resolver.Resolver()

   while (i <= num_lines):
      
    domain = f_input.readline().rstrip('\n')
    domain = domain.rstrip('\r')
    print ("- Resolving domain: " + domain + "\n")
    print ("    * Performing NS Lookup..." + "\n")

    try:
        #NS LOOKUP - REGISTER A - DOMAIN TO IP
        nslookup_answer = nslookup.query(domain, "A")

    except Exception as e:   
        print (str(e))
        print ("    * ERROR. Domain can not be resolved! " + "\n")
        f_output.write(domain)
        f_output.write(";")
        f_output.write("KO-Domain-not-resolved")
        f_output.write("\n")
        break

    
    for rdata in nslookup_answer: #for each response
        #WHOIS IP LOOKUP
        print ("    * Getting IP WHOIS data from ARIN..." + "\n")
            
        try:
            whois_results = IPWhois(str(rdata.address)).lookup_whois(get_asn_description=True)

            #ORGANIZATION NAME DATA EXTRACTION FROM WHOIS RESULTS
            org_results = whois_results.get('nets')[0]

        except Exception as e:   
            print (str(e))
            print ("    * ERROR. WHOIS IP Data can not be retrieved! " + "\n")
            f_output.write(domain)
            f_output.write(";")
            f_output.write(rdata.address)
            f_output.write(";")
            f_output.write("KO-WHOIS-data-retrieval-failed")
            f_output.write("\n")
            break

        #TRY OPEN PORTS 80,443
        print ("    * Trying to connect on 80,443 ports..." + "\n")
        
        try:
            sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock1.settimeout(2)                                      #2 Second Timeout
            port_http = sock1.connect_ex((str(rdata.address),80))

            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(2)                                      #2 Second Timeout
            port_https = sock2.connect_ex((str(rdata.address),443))
            open_ports = []

            if (port_http == 0):
                open_ports.append(80)
                web_app = "HTTP is open on 80 port"
                url_prefix = "http://"

            elif (port_https == 0):
                open_ports.append(443)
                web_app = "HTTPS is open on 443 port"
                url_prefix = "https://"

            else:
                web_app = "No web app detected"

            

        except Exception as e:   
            print (str(e))
            print ("    * ERROR. TCP Socket connection on 80,443 failed! " + "\n")
            f_output.write(domain)
            f_output.write(";")
            f_output.write(rdata.address)
            f_output.write(";")
            f_output.write(whois_results.get('asn_description'))
            f_output.write(";")
            f_output.write(org_results.get('description'))
            f_output.write(";")
            f_output.write("KO-Connection-attempt-on-80,443-ports-failed")
            f_output.write("\n")
            break

        #GET HTML TITLE PAGE

        print ("    * Getting HTML Title page..." + "\n")
        for port in open_ports:
            if (port == 80):
                try:  
                    r = requests.get("http://" + domain)
                    html = bs4.BeautifulSoup(r.text)
                    web_title = html.title.text

                except Exception as e:   
                    print (str(e))
                    print ("    * ERROR. No HTML Title page found!" + "\n")
                    f_output.write(domain)
                    f_output.write(";")
                    f_output.write(rdata.address)
                    f_output.write(";")
                    f_output.write(whois_results.get('asn_description'))
                    f_output.write(";")
                    f_output.write(org_results.get('description'))
                    f_output.write(";")
                    f_output.write(web_app)
                    f_output.write(";")
                    f_output.write("KO-Connection-attempt-on-80,443-ports-failed")
                    f_output.write("\n")
                    break

            if (port == 443):
                try:  
                    r = requests.get("https://" + domain)
                    html = bs4.BeautifulSoup(r.text)
                    web_title = html.title.text

                except Exception as e:   
                    print (str(e))
                    print ("    * ERROR. No HTML Title page found!" + "\n")
                    f_output.write(domain)
                    f_output.write(";")
                    f_output.write(rdata.address)
                    f_output.write(";")
                    f_output.write(whois_results.get('asn_description'))
                    f_output.write(";")
                    f_output.write(org_results.get('description'))
                    f_output.write(";")
                    f_output.write(web_app)
                    f_output.write(";")
                    f_output.write("KO-Connection-attempt-on-80,443-ports-failed")
                    f_output.write("\n")
                    break          

            print ("    * Result: " + rdata.address + "; "  + whois_results.get('asn_description') + "; " + org_results.get('description') + "; " + web_app + "; " + web_title + "\n")
            print ("\n")
            f_output.write(domain)
            f_output.write(";")
            f_output.write(rdata.address)
            f_output.write(";")
            f_output.write(whois_results.get('asn_description'))
            f_output.write(";")
            f_output.write(org_results.get('description'))
            f_output.write(";")
            f_output.write(web_app)
            f_output.write(";")
            f_output.write(web_title)
            f_output.write("\n")
        
       
    
    i = i + 1
      
   f_input.close()
   f_output.close()



main()    