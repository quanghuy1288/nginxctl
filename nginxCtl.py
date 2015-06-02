#!/usr/bin/env python
"""
This is a simple nginx tool.
"""
import subprocess
import re
import sys
import os
from optparse import OptionParser

class bcolors:
    """
        This class is to display differnet colour fonts
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    UNDERLINE = '\033[4m'

class nginxCtl:
    """
    A class for nginxCtl functionalities
    """
    def get_version(self):
        """
        Discovers installed nginx version 
        """
        version = "nginx -v"
        p = subprocess.Popen(
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        return err

    def get_conf_parameters(self):
        """
        Finds nginx configuration parameters
        :returns: list of nginx configuration parameters
        """
        conf = "nginx -V 2>&1 | grep 'configure arguments:'"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        output = re.sub('configure arguments:', '', output)
        dict = {}
        for item in output.split(" "):
            if len(item.split("=")) == 2:
                dict[item.split("=")[0]] = item.split("=")[1]
        return dict

    def get_nginx_conf(self):
        try:
            return self.get_conf_parameters()['--conf-path']
        except KeyError:
            print "nginx is not installed!!!"
            sys.exit()

    def get_nginx_bin(self):
        try:
            return self.get_conf_parameters()['--sbin-path']
        except:
            print "nginx is not installed!!!"
            sys.exit()

    def get_nginx_pid(self):
        try:
            return self.get_conf_parameters()['--pid-path']
        except:
            print "nginx is not installed!!!"
            sys.exit()

    def get_nginx_lock(self):
        try:
            return self.get_conf_parameters()['--lock-path']
        except:
            print "nginx is not installed!!!"
            sys.exit()

    def start_nginx(self):
        nginx_conf_path = self.get_nginx_conf()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_lock_path):
            print "nginx is already running... Nothing to be done!"
        else:
            cmd = "nginx -c " + nginx_conf_path
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, err = p.communicate()
            if not err:
                file = open(nginx_lock_path, 'w')
                file.close()
                print "Starting nginx:\t\t\t\t\t    [  " + bcolors.OKGREEN + "OK" + bcolors.ENDC + "  ]"
            else:
                print err

    def stop_nginx(self):
        nginx_pid_path = self.get_nginx_pid()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_lock_path) and os.path.exists(nginx_pid_path):
            cmd = "nginx -s quit"
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, err = p.communicate()
            if not err:
                os.remove(nginx_lock_path)
                print "Stoping nginx:\t\t\t\t\t    [  " + bcolors.OKGREEN + "OK" + bcolors.ENDC + "  ]"
            else:
                print err

    def configtest_nginx(self):
        p = subprocess.Popen(
            "nginx -t", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        print err

    def restart_nginx(self):
        self.stop_nginx()
        self.start_nginx()

    def status_nginx(self):
        nginx_pid_path = self.get_nginx_pid()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_lock_path) and os.path.exists(nginx_pid_path):
            try:
                pid_file = open(nginx_pid_path, "r")
                pid = pid_file.read().strip()
                pid_file.close()
                cmd = "ps -p " + pid + " -o comm="
                p = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                output, err = p.communicate()
                if output:
                    print "nginx (pid " + pid + ") is running ..."
            except IOError:
                print "Cannot open nginx pid file"
        elif os.path.exists(nginx_lock_path) and not os.path.exists(nginx_pid_path):
            print "nginx pid file exists"
        else:
            print "nginx is stopped"

    def get_vhosts(self):
        nginx_conf_path = self.get_nginx_conf()
        fo = open(nginx_conf_path, "r")
        file = fo.read()
        vhost_files = []
        for line in file.split("\n"):
            line = line.strip()
            if not line.startswith("#"):
                if "include" in line:
                    line.split()
                    vhost_files.append(line.split()[1])
        fo.close()
        mydict = {}
        for v in vhost_files:
            if "/*" in v:
                dir = v.split("/*", 1)[0]
                ext = v.split("/*", 1)[1].strip(";")
                for f in os.listdir(dir):
                    if f.endswith(ext):
                        file = v.split("/*", 1)[0] + "/" + f
                        # print file.strip("\n")
                        num = 0
                        domain = ""
                        port = ""
                        for l in open(file, "r"):
                            li = l.strip()
                            num = num + 1
                            if not li.startswith("#"):
                                if re.search('server_name', li):
                                    li = li.split(";",1)[0]
                                    li = li.strip(";")
                                    if li.split()[1] == "_":
                                        domain = "default_server_name"
                                    else:
                                        domain = li.split()[1]
                                    domain_num = num
                                    alias = li.split()[2:]
                                if re.search('listen', li):
                                    li = li.strip()
                                    li = li.strip(";")
                                    port = li.split()[1]
                                if domain and port:
                                    info = (domain_num, file, alias)
                                    mydict[(domain, port)] = info
                                    domain = ""
                                    port = ""

            else:
                num = 0
                domain = ""
                port = ""
                v = v.strip(";")
                for l in open(v, "r"):
                    li = l.strip()
                    num = num + 1
                    if not li.startswith("#"):
                        if re.search('server_name', li):
                            li = li.strip(";")
                            if li.split()[1] == "_":
                                domain = "default_server_name"
                            else:
                                domain = li.split()[1]
                            domain_num = num
                            alias = li.split()[2:]
                        if re.search('listen', li):
                            li = li.strip()
                            port = li.split()[1]
                        if domain and port:
                            info = (domain_num, file, alias)
                            mydict[(domain, port)] = info
                            domain = ""
                            port = ""

        print bcolors.BOLD + "nginx vhost configuration:" + bcolors.ENDC
        for key, value in mydict.iteritems():
            if re.search(':', key[1]):
                ip = key[1].split(":")[0]
                port = key[1].split(":")[1]
            else:
                ip = "*"
                port = key[1]

            print ip + ":" + port + "  " + "is a Virtualhost"
            print "\tport " + port + " " + bcolors.OKGREEN + key[0] + bcolors.ENDC + " (" + value[1] + ":" + str(value[0]) + ")"
            for i in value[2]:
                print "\t\talias  " + bcolors.CYAN + i + bcolors.ENDC
            print "\n"

        self.configtest_nginx()


def main():
    n = nginxCtl()
    parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_option('-S', '--list-vhosts', dest='list_vhosts',
                      action="store_true", help="List configured vhost")
    parser.add_option('-t', '--configtest', dest='configtest',
                      action="store_true", help="configuration test")
    parser.add_option(
        '--start', dest='start', action="store_true", help="Start nginx service")
    parser.add_option(
        '--stop',  dest='stop', action="store_true", help="Stop nginx service")
    parser.add_option(
        '--restart',  dest='restart', action="store_true", help="Restart nginx service")
    parser.add_option(
        '--status',  dest='status', action="store_true", help="nginx service status")
    (options, args) = parser.parse_args()

    if options.list_vhosts is True:
        n.get_vhosts()
    elif options.start is True:
        n.start_nginx()
    elif options.stop is True:
        n.stop_nginx()
    elif options.restart is True:
        n.restart_nginx()
    elif options.status is True:
        n.status_nginx()
    elif options.configtest is True:
        n.configtest_nginx()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
