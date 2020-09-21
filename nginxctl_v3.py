#!/usr/bin/env python
"""
This is a simple nginx tool from: https://github.com/rackerlabs/nginxctl/blob/master/nginxctl.py
python3 version: https://github.com/sjas/nginxctl/blob/master/nginxctl
"""
import subprocess
import re
import sys
import os
import urllib2
import time
from threading import Timer
from config import LOG


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
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
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
        """
        :returns: nginx configuration path location
        """
        try:
            return self.get_conf_parameters()['--conf-path']
        except KeyError:
            LOG.error("nginx is not installed!!!")
            sys.exit()

    def get_nginx_bin(self):
        """
        :returns: nginx binary location
        """
        try:
            return self.get_conf_parameters()['--sbin-path']
        except:
            LOG.error("nginx is not installed!!!")
            sys.exit()

    def get_nginx_pid(self):
        """
        :returns: nginx pid location which is required by nginx services
        """

        try:
            return self.get_conf_parameters()['--pid-path']
        except:
            LOG.error("nginx is not installed!!!")
            sys.exit()

    def get_nginx_lock(self):
        """
        :returns: nginx lock file location which is required for nginx services
        """

        try:
            return self.get_conf_parameters()['--lock-path']
        except:
            LOG.error("nginx is not installed!!!")
            sys.exit()

    def start_nginx(self):
        """
        Start nginx service if pid and socket file do not exist.
        """
        r = False
        nginx_conf_path = self.get_nginx_conf()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_lock_path):
            LOG.info("nginx is already running... Nothing to be done!")
        else:
            cmd = "nginx -c " + nginx_conf_path
            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 shell=True
                                 )
            output, err = p.communicate()
            if not err:
                file = open(nginx_lock_path, 'w')
                file.close()
                LOG.info("Starting nginx:\t\t\t\t\t    [ %sOK%s ]" % (
                    bcolors.OKGREEN,
                    bcolors.ENDC
                ))
                r = True
            else:
                LOG.info(err)
        return r

    # added
    def get_pid_number_nginx(self):
        """ get pid number via pid path
        """
        pid = None
        nginx_pid_path = self.get_nginx_pid()
        if os.path.exists(nginx_pid_path):
            try:
                pid_file = open(nginx_pid_path, "r")
                pid = int(pid_file.read().strip())
                pid_file.close()
            except IOError:
                LOG.error("Cannot open nginx pid file")
        return pid

    def stop_nginx(self):
        """
        Stop nginx service.
        """
        r = False
        nginx_pid_path = self.get_nginx_pid()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_pid_path):
            try:
                pid_file = open(nginx_pid_path, "r")
                pid = pid_file.read().strip()
                pid_file.close()
                pid_cmd = "ps -p %s -o comm=" % pid
                p = subprocess.Popen(pid_cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     shell=True
                                     )
                pid, err = p.communicate()
            except IOError:
                LOG.error("Cannot open nginx pid file")
            if pid:
                cmd = "nginx -s quit"
                p = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     shell=True
                                     )
                output, err = p.communicate()
                if not err:
                    if os.path.exists(nginx_lock_path):
                        os.remove(nginx_lock_path)
                        LOG.info("Stoping nginx:\t\t\t\t\t    [  %sOK%s  ]" % (
                            bcolors.OKGREEN,
                            bcolors.ENDC
                        ))
                        r = True
                else:
                    LOG.info(err)
        return r

    def reload_nginx(self):
        """
        Ensure there is no syntax errors are reported.
        The 'nginx -s reload' command is used for this.
        """
        LOG.info("reload_nginx")

        is_successed = False
        pid_master = self.get_pid_number_nginx()

        if pid_master is None:
            return False

        if pid_master:
            pids_childrent_current = self.get_child_processes_nginx(pid_master)

            try:
                output = subprocess.check_output(['nginx', '-s', 'reload'], stderr=subprocess.STDOUT)
                LOG.warning('subprocess code: {}'.format(output))
                '''check reload nginx successed'''
                LOG.debug('checking_reload_nginx')
                # count = 12
                # while count > 0:
                #     tick = 0
                #     pids_childrent_newest = self.get_child_processes_nginx(pid_master)
                #     LOG.debug('pid_newest: %s, pid_old %s' % (pids_childrent_newest, pids_childrent_current))
                #     for pid in pids_childrent_newest:
                #         if pid in pids_childrent_current:
                #             tick += 1
                #     if not tick:
                #         LOG.debug("YES")
                #         is_successed = True
                #         break
                #     count -= 1
                #     time.sleep(10)
            except subprocess.CalledProcessError as exc:
                LOG.error(exc.output)
            except Exception as e:
                LOG.error(e)

            # p = subprocess.Popen(
            #     "nginx -s reload",
            #     stdout=subprocess.PIPE,
            #     stderr=subprocess.PIPE,
            #     shell=True
            # )
            # output, err = p.communicate()
            # if not output:
            #     '''check reload nginx successed'''
            #     LOG.debug('checking_reload_nginx')
            #     count = 54
            #
            #     while count > 0:
            #         tick = 0
            #         pids_childrent_newest = self.get_child_processes_nginx(pid_master)
            #         LOG.debug('pid_newest: %s, pid_old %s' % (pids_childrent_newest, pids_childrent_current))
            #         for pid in pids_childrent_newest:
            #             if pid in pids_childrent_current:
            #                 tick += 1
            #         if not tick:
            #             LOG.debug("YES")
            #             is_successed = True
            #             break
            #         count -= 1
            #         time.sleep(10)
            #     LOG.debug('reload_nginx_successed')
            # else:
            #     LOG.info(err)
        return is_successed


    def __reload_nginx(self):
        """
        Ensure there is no syntax errors are reported.
        The 'nginx -s reload' command is used for this.
        """
        LOG.info("reload_nginx")

        is_successed = False
        pid_master = self.get_pid_number_nginx()

        if pid_master is None:
            return False

        if pid_master:
            kill = lambda process: process.kill()
            p = subprocess.Popen(
                "nginx -s reload",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            my_timer = Timer(180, kill, [p])
            try:
                my_timer.start()
                stdout, stderr = p.communicate()
                if not stdout:
                    '''reload nginx successed'''
                    LOG.debug('reload_nginx_successed')
                else:
                    LOG.error(stderr)
            finally:
                my_timer.cancel()
            # output, err = p.communicate()
            # if not output:
            #     '''reload nginx successed'''
            #     LOG.debug('reload_nginx_successed')
            # else:
            #     LOG.error(err)
        return True
        # return is_successed

    def get_child_processes_nginx(self, parent_pid):
        """
        get child processes of nginx
        :param parent_pid: master pid of nginx
        :return: list []
        """
        ps_command = subprocess.Popen("ps -o pid --ppid %d --noheaders" % parent_pid, shell=True,
                                      stdout=subprocess.PIPE)
        ps_output = ps_command.stdout.read()
        retcode = ps_command.wait()
        # print 'ccc %d' % retcode
        # assert retcode == 0, "ps command returned %d" % retcode
        pids = []
        if not retcode:
            for pid_str in ps_output.split("\n")[:-1]:
                pids.append(pid_str)
        return pids

    def configtest_nginx(self, file=None):
        """
        Ensure there is no syntax errors are reported.
        The 'nginx -t' command is used for this.
        """
        LOG.info("configtest_nginx")
        if file:
            p = subprocess.Popen(
                "nginx -t -c %s" % file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            output, err = p.communicate()
            LOG.debug(err)
            return err
        else:
            p = subprocess.Popen(
                "nginx -t",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            output, err = p.communicate()
            LOG.debug(err)
            return err

    def restart_nginx(self):
        """
        Restart nginx service. Stop and Start nginx functions are used.
        """
        self.stop_nginx()
        self.start_nginx()

    def full_status(self):
        """
        Checks against /server-status for server statistics
        """
        try:
            request = urllib2.urlopen('http://localhost/server-status')
            if str(request.getcode()) == "200":
                LOG.info("""
Nginx Server Status
-------------------
%s
                    """ % request.read())
            else:
                LOG.info("""
Nginx Server Status
-------------------
server-status did not return a 200 response.
                    """)
        except (urllib2.HTTPError, urllib2.URLError):
            LOG.info("""
Nginx Server Status
-------------------
Attempt to query /server-status returned an error
                """)

    def status_nginx(self):
        """
        Report nginx status based on pid and socket files.
        """
        LOG.info("=>start")
        r = False
        nginx_pid_path = self.get_nginx_pid()
        nginx_lock_path = self.get_nginx_lock()
        if os.path.exists(nginx_pid_path):
            try:
                pid_file = open(nginx_pid_path, "r")
                pid = pid_file.read().strip()
                pid_file.close()
                cmd = "ps -p %s -o comm=" % pid
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)
                output, err = p.communicate()
                if output:
                    LOG.info("nginx (pid %s) is running ..." % pid)
                    r = True
            except IOError:
                LOG.error("Cannot open nginx pid file")
        elif (os.path.exists(nginx_lock_path) and not
        os.path.exists(nginx_pid_path)):
            LOG.info("nginx pid file exists")
        else:
            LOG.error("nginx is stopped")
        LOG.info("=>end")
        return r

    def get_vhosts(self):
        """
        Discover a list of configured vhosts by parsing nginx configuration
        files and print those vhosts on commanline.
        This function parses nginx default configuration file,
        /etc/nginx/nginx.conf, and looks for keyword Include.
        It parse all files and folders referenced by Include directrive.
        """
        nginx_conf_path = self.get_nginx_conf()  # path of main nginx file
        fo = open(nginx_conf_path, "r")
        file = fo.read()
        vhost_files = []
        # Get a list of files/folders refernced with 'include' directive on
        # main nginx config
        for line in file.split("\n"):
            line = line.strip()
            if not line.startswith("#"):
                # if "include" in line:
                if re.search(r"\binclude\b", line):
                    line.split()
                    vhost_files.append(line.split()[1])
        fo.close()
        mydict = {}

        for v in vhost_files:
            # find how a folder is specified on nginx config.
            if "/*" in v:
                dir = v.split("/*", 1)[0]
                ext = v.split("/*", 1)[1].strip(";")  # find the extension.
                for f in os.listdir(dir):
                    if f.endswith(ext) or "*" in ext or not ext:
                        file = v.split("/*", 1)[0] + "/" + f
                        num = 0
                        domain = ""
                        port = ""
                        for l in open(file, "r"):
                            li = l.strip()
                            num = num + 1
                            if not li.startswith("#"):
                                if re.search('server_name', li):
                                    li = li.split(";", 1)[0]
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
                if not re.search('/', v):
                    v = "/etc/nginx/" + v
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

                LOG.info("%snginx vhost configuration:%s" % (
                    bcolors.BOLD,
                    bcolors.ENDC
                ))
        for key, value in mydict.iteritems():
            if re.search(':', key[1]):
                ip = key[1].split(":")[0]
                port = key[1].split(":")[1]
            else:
                ip = "*"
                port = key[1]

                LOG.info("%s:%s is a Virtualhost" % (
                    ip,
                    port
                ))
                LOG.info("\tport %s %s %s %s (%s:%s)" % (
                    port,
                    bcolors.OKGREEN,
                    key[0],
                    bcolors.ENDC,
                    value[1],
                    str(value[0])
                ))
            for i in value[2]:
                LOG.info("\t\talias  %s %s %s" % (
                    bcolors.CYAN,
                    i,
                    bcolors.ENDC
                ))
                LOG.info("\n")

        self.configtest_nginx()

    def _strip_line(self, path, remove=None):
        """ Removes any trailing semicolons, and all quotes from a string
        """
        if remove is None:
            remove = ['"', "'", ';']
        for c in remove:
            if c in path:
                path = path.replace(c, '')

        return path

