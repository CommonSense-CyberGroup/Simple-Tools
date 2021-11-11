'''
Name: Basic Port Scanner

Developers:
    Some Guy they call Scooter
    Common Sense Cyber Group

Created: 6/1/2021
Updated: 11/11/2021

Version: 1.2.2

This script is meant to be a port scanner in the case NMAP (or something similar) cannot be used. It will take a list of IPs and Ports to scan, and output the results to the screen, as well as create a log file
for later review/CYA

Version Notes:
    -We set a timeout period of 5sec so we are not waiting forever on a fail
    -The port range entered will be scanned for EVERY IP that is in the range the user puts in
    -Command line arguments: (currently ony 1 can be used at a time!)
        -Argument '-r' can be used when running in order to attempt and receive the response or anything presented by the device at the other end
        -Argument '-e' can be used when running in order to output the connection response instead of OPEN, CLOSED, or REFUSED
        -Argument '-t' can be used to select the timeout period when scanning ports. Default is 5sec
        -Argument '--help' can be used to show a list of available arguments with descriptions, as well as examples

References:
    -Error codes for port response: https://www.ibm.com/support/pages/what-are-meanings-winsock-error-codes-70119320102834905

Additional Considerations:
    -This script is intended for educational use only and the developer is not responsible for any changes/misuse of the script or code.
    -The user accepts that this is a basic tool without the full functionality of an actual port-scanner such as NMAP or NetCat.

To Do:
    -Enable using multiple command line arguments at once?
    -Use ipaddress library for accepting CIDRs
    -Better create this so it is a loop until user quits with ctrl-c
    

'''
###Import Libraries
from datetime import datetime
import socket
import logging
import sys
from os.path import dirname
from colorama import Style, Fore, init

###Define Glabal Variables
project_root = dirname(__file__)    #Holds the root of the project for output
slash = '\\'
scan = False
bad_ip_list = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","`","~","!","@","#","$","%","^","&","*","(",")","_","=","+","[","{","]","}","\\","|",":",";",'"',"'","<",",",">","/","?"]
init(convert=True)

#Set up info for logging
logging_file = f'{project_root}{slash}{"port_scan.log"}'
logger = logging.getLogger('Sockets_Log')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(logging_file)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

###Functions
#Function to do the majority of the work and calling other functions for conneting
def main(argv):
    #Argument to show help menu to user
    if '--help' in argv:
        #Call function to show the help info
        show_help_menu()
        quit()

    ###Get information from the users so we can run this script
    print(Fore.LIGHTYELLOW_EX)
    print("Please follow the below instructions:")
    print(Fore.CYAN)
    print("IP Range:")
    print("\t-Cannot be larger than a /24")
    print("\t-Cannot be in CIDR Notation")
    print("\t-Can be single IP")
    print("\t-Range Example: 192.168.1.1-192.168.1.50")
    print("Port Range:")
    print("\t-Can be single Port")
    print("\t-Range Example: 22-23,80,443")
    print()
    print(Style.RESET_ALL)
    ip_range = input("IP Range   : ")
    port_range = input("Port Range : ")

    #Determine if user wants to specify timeout period
    if "-t" in argv:
        timeout = input("Timeout (s): ")
        logger.info("User set timeout to %s seconds", timeout)
    else:
        timeout = 5

    #Break up the user inputs to determine what needs to be scanned
    ip_list = []
    port_list = []

    #IP ranges
    try:
        #Look to see if there is a range of addresses
        if "-" in ip_range:
            ip_start = ip_range.split("-")[0]
            ip_end = ip_range.split("-")[1]
            ips_start = ip_start.split(".")[3]
            ips_end = ip_end.split(".")[3]

            n = int(ips_end) - int(ips_start)
            t = 0
            while t <= n:
                ip = int(ips_start) + t
                combined_ip = f'{ip_start.split(".")[0]}{"."}{ip_start.split(".")[1]}{"."}{ip_start.split(".")[2]}{"."}{ip}'
                ip_list.append(combined_ip)
                t += 1

        for char in bad_ip_list:
            if char in ip_range:
                print(Fore.RED, "IP RANGE INCORRECT!", Style.RESET_ALL)
                logger.error("Incorrect IP range entered: %s", ip_range)
                quit()

        #Append if there is not a range of IPs
        else:
            ip_list.append(ip_range.strip())

    #Error checking
    except IndexError as i_err:
        print(Fore.RED, "IP RANGE INCORRECT!", Style.RESET_ALL)
        logger.error("Incorrect IP range entered: %s", i_err)
        quit()

    #Port Ranges
    try:
        #Determine if there is a range in the ports
        for char in bad_ip_list:
            if char in port_range:
                print(Fore.RED, "IP RANGE INCORRECT!", Style.RESET_ALL)
                logger.error("Incorrect IP range entered: %s", port_range)
                quit()

        if "-" in port_range:
            port_start = port_range.split("-")[0]
            port_end = port_range.split("-")[1]
            r = int(port_end) - int(port_start)
            i = 0
            while i <= r:
                port = int(port_start) + i
                port_list.append(port)
                i += 1
        
        #Determine if there is a list in the ports
        elif "," in port_range:
            ports = port_range.split(",")
            for p in ports:
                if "-" in p:
                    port_start = port_range.split("-")[0]
                    port_end = port_range.split("-")[1]
                    r = int(port_end) - int(port_start)
                    i = 0
                    while i <= r:
                        port = int(port_start) + i
                        port_list.append(port)
                        i += 1

                port_list.append(p.strip())

    #Error checking
    except IndexError as i_err:
        print(Fore.RED, "PORT RANGE INCORRECT!", Style.RESET_ALL)
        logger.error("Incorrect port range entered: %s", i_err)
        quit()

    #Append if there is no range or list
    else:
        port_list.append(port_range.strip())

    #This section will pull any parameters in from the CLI that the user used when running
    #Arg to gather any response that the device sends back when scanning (-r for response)
    if "-r" in argv:
        #Print column info for output
        header = [["Port", "IP Address", "Status", "Response"]]
        dash = '-' * 80
        for i in range(len(header)):
            print(dash)
            print('{:<12s}{:>12s}{:>16s}{:>40s}'.format(header[i][0],header[i][1],header[i][2], header[i][3]))
            print(dash)

        #Call function to actually scan the IPs/Ports given
        for dev_ip in ip_list:
            for dev_port in port_list:
                check_port_banner(dev_ip, dev_port, timeout)
        quit()
    #Showing Error code instead of OPN, CLOSED, REFUSED
    if "-e" in argv:
        #Print column info for output
        header = [["Port", "IP Address", "Status"]]
        dash = '-' * 40
        for i in range(len(header)):
            print(dash)
            print('{:<12s}{:>12s}{:>16s}'.format(header[i][0],header[i][1],header[i][2]))
            print(dash)

        #Call function to actually scan the IPs/Ports given
        for dev_ip in ip_list:
            for dev_port in port_list:
                check_port_error(dev_ip, dev_port, timeout)
        quit()


    #Basic, no arg, port scanning
    else:
        #Print column info for output
        header = [["Port", "IP Address", "Status"]]
        dash = '-' * 40
        for i in range(len(header)):
            print(dash)
            print('{:<12s}{:>12s}{:>16s}'.format(header[i][0],header[i][1],header[i][2]))
            print(dash)

        #Call function to actually scan the IPs/Ports given
        for dev_ip in ip_list:
            for dev_port in port_list:
                check_port(dev_ip, dev_port, timeout)
        quit()
                            
#Function to check the ports for each device in the input file
def check_port(dev_ip, dev_port, timeout):
    #Set up our socket for each attempt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    #Test the IP/Port we were given and get the response
    try:
        response = s.connect_ex((dev_ip, int(dev_port)))

    #Error checking
    except socket.error as e:
        print(e)
        logger.warning("Error connecting to port %s on %s: %s", dev_port, dev_ip, e)

    #Close socket to clean up
    s.close()

    #Set up list for outputting to screen
    data = []

    #Determine what the response is and tell the user, ouputting to log as well
    #Open
    if response == 0:
        data.append([dev_port, dev_ip, "OPEN"])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is OPEN", dev_port, dev_ip)
    #Refused\Blocked
    elif response == 10061:
        data.append([dev_port, dev_ip, "REFUSED"])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is REFUSED", dev_port, dev_ip)
    #Non-Blocked?
    elif response == 10035:
        data.append([dev_port, dev_ip, "CLOSED"])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is CLOSED", dev_port, dev_ip)
    else:
        print("[!] ERROR Response: ", response)

#Function to check the ports for each device in the input file (using -r arg for Response)
def check_port_banner(dev_ip, dev_port, timeout):
    #Set variables
    banner = "N/A"
    
    #Set up our socket for each attempt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    #Test the IP/Port we were given and get the response
    try:
        #response = s.connect_ex((dev_ip, int(dev_port)))
        response = s.connect_ex((dev_ip, int(dev_port)))
        banner = s.recv(1024)
        
    #Error checking
    except socket.error as e:
        logger.warning("Error connecting to port %s on %s: %s", dev_port, dev_ip, e)

    #Close socket to clean up
    s.close()

    #Set up list for outputting to screen
    data = []

    #Determine what the response is and tell the user, ouputting to log as well
    #Open
    if response == 0:
        try:
            #Set up socket again to get banner:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(int(timeout))
            s.connect((dev_ip, int(dev_port)))
            banner = s.recv(1024)
            banner = str(banner).replace("b'", "")
            banner = banner.replace("\\r'", "")
            banner = banner.replace("\\n'", "")
            s.close()

        #Error checking
        except socket.timeout:
            logger.warning("Timed out when trying to get the banner for %s port %s", dev_ip, dev_port)
            print()
            print(Fore.LIGHTRED_EX, "Timed out when trying to grab the banner for ", dev_ip, " on port ", dev_port,". Try running without '-r'", Style.RESET_ALL)
            return

        #set up output
        data.append([dev_port, dev_ip, "OPEN", banner])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}{:>40s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2]),str(data[i][3])))
        logger.info("Port %s on %s is OPEN with response %s", dev_port, dev_ip, banner)
    #Refused\Blocked
    elif response == 10061:
        data.append([dev_port, dev_ip, "REFUSED", banner])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}{:>40s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2]),str(data[i][3])))
        logger.info("Port %s on %s is REFUSED", dev_port, dev_ip)
    #Non-Blocked?
    elif response == 10035:
        data.append([dev_port, dev_ip, "CLOSED", banner])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>14s}{:>40s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2]),str(data[i][3])))
        logger.info("Port %s on %s is CLOSED", dev_port, dev_ip)
    else:
        print("[!] ERROR Response: ", response)

#Function to check the ports for each device, but outputs the return from the connection state instead of OPEN, CLOSED, or REFUSED
def check_port_error(dev_ip, dev_port, timeout):
    #Set up our socket for each attempt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    #Test the IP/Port we were given and get the response
    try:
        response = s.connect_ex((dev_ip, int(dev_port)))

    #Error checking
    except socket.error as e:
        print(e)
        logger.warning("Error connecting to port %s on %s: %s", dev_port, dev_ip, e)

    #Close socket to clean up
    s.close()

    #Set up list for outputting to screen
    data = []

    #Determine what the response is and tell the user, ouputting to log as well
    #Open
    if response == 0:
        data.append([dev_port, dev_ip, response])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>16s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is OPEN", dev_port, dev_ip)
    #Refused\Blocked
    elif response == 10061:
        data.append([dev_port, dev_ip, response])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>16s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is REFUSED", dev_port, dev_ip)
    #Non-Blocked?
    elif response == 10035:
        data.append([dev_port, dev_ip, response])
        for i in range(len(data)):
            print('{:<12s}{:^12s}{:>16s}'.format(str(data[i][0]),str(data[i][1]),str(data[i][2])))
        logger.info("Port %s on %s is CLOSED", dev_port, dev_ip)
    else:
        print("[!] ERROR Response: ", response)

#Function to show help menu to user
def show_help_menu():
    #Show the help menu to the user
    print()
    print(Fore.LIGHTYELLOW_EX)
    print("This section outlines the available arguments while running the script as well as examples")
    print("This script is a basic port scanner using the sockets library. Read the README file located in the root directory of the script to learn more")
    print(Style.RESET_ALL)
    print("Options:")
    print(Fore.CYAN, "\t--help\t\t\t", Style.RESET_ALL, "--Displays this help menu")
    print(Fore.CYAN, "\t-r\t\t\t", Style.RESET_ALL, "--For open ports, the script will send data to the port and gather the response to show on screen")
    print(Fore.CYAN, "\t-e\t\t\t", Style.RESET_ALL, "--Shows response code for ports instead of OPEN, CLOSED, or REFUSED")
    print(Fore.CYAN, "\t-t\t\t\t", Style.RESET_ALL, "--Allows user to specify the timeout period while checking ports. In seconds")
    print()

###Do the Thing
if __name__ == '__main__':
    while True:
        try:
            main(sys.argv[1:])
            print()
        except KeyboardInterrupt:
            quit()
        except:
            print("\nUnexpected error\n" )

'''
End of script
'''
