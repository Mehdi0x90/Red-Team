#################################
# Get host name
#################################

import socket

def print_machine_info():
host_name = socket.gethostname()
ip_address = socket.gethostbyname(host_name)
print "Host Name : %s" % host_name
print "IP Address : %s" % ip_address

if name == 'main' :
print_machine_info()
