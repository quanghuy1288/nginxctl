#!/usr/bin/env python
"""
This is a simple nginx tool from: https://github.com/quanghuy1288/nginxctl
"""
import os
import re
import subprocess
import sys
import urllib2
from threading import Timer

from contexttimer import timer

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
            r = True
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

    def configtest_nginx(self, file=None):
        """
        Ensure there is no syntax errors are reported.
        The 'nginx -t' command is used for this.
        """
        LOG.debug("configtest_nginx")
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

    def is_valid_config(self):
        result = self.configtest_nginx()
        if 'test is successful' in result:
            return True
        return False

    def restart_nginx(self):
        """
        Restart nginx service. Stop and Start nginx functions are used.
        """
        if not self.stop_nginx():
            return False

        return self.start_nginx()

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
                LOG.warn("""
Nginx Server Status
-------------------
server-status did not return a 200 response.
                    """)
        except (urllib2.HTTPError, urllib2.URLError):
            LOG.error("""
Nginx Server Status
-------------------
Attempt to query /server-status returned an error
                """)

    def status_nginx(self):
        """
        Report nginx status based on pid and socket files.
        """
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
        return r

    def _get_vhosts(self):
        """
        get vhosts
        """
        ret = []
        for f in self._get_all_config():
            ret += self._get_vhosts_info(f)
        return ret

    def _strip_line(self, path, remove=None):
        """ Removes any trailing semicolons, and all quotes from a string
        """
        if remove is None:
            remove = ['"', "'", ';']
        for c in remove:
            if c in path:
                path = path.replace(c, '')

        return path

    def _get_full_path(self, path, root, parent=None):
        """ Returns a potentially relative path and returns an absolute one
            either relative to parent or root, whichever exists in that order
        """
        if os.path.isabs(path) and os.path.exists(path):
            return path

        if parent:
            if os.path.isfile(parent):
                parent = os.path.dirname(parent)
            candidate_path = os.path.join(parent, path)
            if os.path.isabs(candidate_path) and os.path.exists(candidate_path):
                return candidate_path

        candidate_path = os.path.join(root, path)
        if os.path.isabs(candidate_path) and os.path.exists(candidate_path):
            return candidate_path

        return path

    def _get_includes_line(self, line, parent, root):
        """ Reads a config line, starting with 'include', and returns a list
            of files this include corresponds to. Expands relative paths,
            unglobs globs etc.
        """
        path = self._strip_line(line.split()[1])
        orig_path = path
        included_from_dir = os.path.dirname(parent)

        if not os.path.isabs(path):
            """ Path is relative - first check if path is
                relative to 'current directory' """
            path = os.path.join(included_from_dir, self._strip_line(path))
            if not os.path.exists(os.path.dirname(path)) or not os.path.isfile(path):
                """ If not, it might be relative to the root """
                path = os.path.join(root, orig_path)

        if os.path.isfile(path):
            return [path]
        elif '/*' not in path and not os.path.exists(path):
            """ File doesn't actually exist - probably IncludeOptional """
            return []

        """ At this point we have an absolute path to a basedir which
            exists, which is globbed
        """
        basedir, extension = path.split('/*')
        try:
            if extension:
                return [
                    os.path.join(basedir, f) for f in os.listdir(
                        basedir) if f.endswith(extension)]

            return [os.path.join(basedir, f) for f in os.listdir(basedir)]
        except OSError:
            return []

    def _get_all_config(self, config_file=None):
        """
        Reads all config files, starting from the main one, expands all
        includes and returns all config in the correct order as a list.
        """
        config_file = "/etc/nginx/nginx.conf" if config_file is None else config_file
        ret = [config_file]

        config_data = open(config_file, 'r').readlines()

        for line in [line.strip().strip(';') for line in config_data]:
            if line.startswith('#'):
                continue
            line = line.split('#')[0]
            if line.startswith('include'):
                includes = self._get_includes_line(line,
                                                   config_file,
                                                   "/etc/nginx/")
                for include in includes:
                    try:
                        ret += self._get_all_config(include)
                    except IOError:
                        pass
        return ret

    def _get_vhosts_info(self, config_file):
        server_block_boundry = []
        server_block_boundry_list = []
        vhost_data = open(config_file, "r").readlines()
        open_brackets = 0
        found_server_block = False
        for line_number, line in enumerate(vhost_data):
            if line.startswith('#'):
                continue
            line = line.split('#')[0]
            line = line.strip().strip(';')
            if re.match(r"server.*{", line):
                server_block_boundry.append(line_number)
                found_server_block = True
            if '{' in line:
                open_brackets += 1
            if '}' in line:
                open_brackets -= 1
            if open_brackets == 0 and found_server_block:
                server_block_boundry.append(line_number)
                server_block_boundry_list.append(server_block_boundry)
                server_block_boundry = []
                found_server_block = False

        server_dict_ret = []
        for server_block in server_block_boundry_list:
            alias = []
            ip_port = []
            server_name_found = False
            server_dict = {}
            store_multiline = ''
            for line_num, li in enumerate(vhost_data, start=server_block[0]):
                l = vhost_data[line_num]
                if line_num >= server_block[1]:
                    server_dict['alias'] = alias
                    server_dict['l_num'] = server_block[0]
                    server_dict['config_file'] = config_file
                    server_dict['ip_port'] = ip_port
                    server_dict_ret.append(server_dict)
                    server_name_found = False
                    break

                if l.startswith('#'):
                    continue
                l = l.split('#')[0]

                # Continue recording directive information if the line
                # doesn't end with ';' (eg. server_name's listed on new lines)
                if not l.strip().endswith(';'):
                    if line_num != server_block[0]:
                        store_multiline += l.strip() + ' '
                    continue

                # Once the directive has been "closed" (ends with ';') and
                # multi_line_buffer is being used, proceed as if all information
                # was on a single line and reset buffer.
                if store_multiline:
                    l = store_multiline + l
                    store_multiline = ''
                l = l.strip().strip(';')

                if l.startswith('server_name') and server_name_found:
                    alias += l.split()[1:]

                if l.startswith('server_name'):
                    server_dict['servername'] = "default_server_name" if l.split()[1] == "_" else l.split()[1]
                    server_name_found = True
                    if len(l.split()) >= 2:
                        alias += l.split()[2:]
                if l.startswith('listen'):
                    ip_port.append(l.split()[1])
        return server_dict_ret

    def get_vhosts(self):
        vhosts_list = self._get_vhosts()
        LOG.info("nginx vhost configuration count: {}".format(len(vhosts_list)))
        for vhost in vhosts_list:
            LOG.info('nginx vhost: {}'.format(vhost))
            ip_ports = vhost['ip_port']
            for ip_port_x in ip_ports:
                if '[::]' in ip_port_x:
                    pattern = re.compile(r'(\[::\]):(\d{2,5})')
                    pattern_res = re.match(pattern, ip_port_x)
                    ip = pattern_res.groups()[0]
                    port = pattern_res.groups()[1]
                else:
                    ip_port = ip_port_x.split(':')
                    try:
                        ip = ip_port[0]
                        port = ip_port[1]
                    except:
                        ip = '*'
                        port = ip_port[0]
                servername = vhost.get('servername', None)
                serveralias = vhost.get('alias', None)
                line_number = vhost.get('l_num', None)
                config_file = vhost.get('config_file', None)
                LOG.debug("%s:%s is a Virtualhost" % (ip, port))
                LOG.debug("port %s namevhost %s %s %s (%s:%s)" % (port,
                                                                  bcolors.OKGREEN,
                                                                  servername,
                                                                  bcolors.ENDC,
                                                                  config_file,
                                                                  line_number))
                for alias in serveralias:
                    LOG.debug("alias %s %s %s" % (bcolors.CYAN,
                                                  alias,
                                                  bcolors.ENDC))

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

    @timer(logger=LOG)
    def reload_nginx(self):
        """
        Ensure there is no syntax errors are reported.
        The 'nginx -s reload' command is used for this.
        """
        LOG.debug("reload_nginx")

        is_successed = False
        pid_master = self.get_pid_number_nginx()

        if pid_master is None:
            LOG.error('nginx pid is not available')
            return False

        if pid_master:
            pids_children_current = self.get_child_processes_nginx(pid_master)

            try:
                output = subprocess.check_output(['nginx', '-s', 'reload'], stderr=subprocess.STDOUT)
                LOG.warning('subprocess code: {}'.format(output))
                '''check reload nginx successed'''
                LOG.debug('checking_reload_nginx')
                # count = 12
                # while count > 0:
                #     tick = 0
                #     pids_childrent_newest = self.get_child_processes_nginx(pid_master)
                #     LOG.debug('pid_newest: %s, pid_old %s' % (pids_childrent_newest, pids_children_current))
                #     for pid in pids_childrent_newest:
                #         if pid in pids_children_current:
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
            #         LOG.debug('pid_newest: %s, pid_old %s' % (pids_childrent_newest, pids_children_current))
            #         for pid in pids_childrent_newest:
            #             if pid in pids_children_current:
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

    @timer(logger=LOG)
    def reload_nginx2(self):
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
        return True

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

    def get_vhosts2(self):
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


def main():
    n = nginxCtl()

    def usage():
        print ("Usage: %s [option]" % sys.argv[0])
        print ("Example: %s -v" % sys.argv[0])
        print "\n"
        print "Available options:"
        print "\t-S list nginx vhosts"
        print "\t-t configuration test"
        print "\t-k start|stop|status|restart|fullstatus|reload"
        print "\t-v version"
        print "\t-h help"

    def version():
        print "version 1.3"

    commandsDict = {"-S": n.get_vhosts,
                    "-t": n.configtest_nginx,
                    "-k": n.restart_nginx,
                    "-v": version,
                    "-h": usage}
    subcommandsDict = {"start": n.start_nginx,
                       "stop": n.stop_nginx,
                       "restart": n.restart_nginx,
                       "status": n.status_nginx,
                       "fullstatus": n.full_status}
    allCommandsDict = {"-S": n.get_vhosts,
                       "-t": n.configtest_nginx,
                       "-k": usage,
                       "-v": version,
                       "-h": usage,
                       "start": n.start_nginx,
                       "stop": n.stop_nginx,
                       "restart": n.restart_nginx,
                       "status": n.status_nginx,
                       "reload": n.reload_nginx,
                       "reload2": n.reload_nginx2,
                       "fullstatus": n.full_status}
    commandline_args = sys.argv[1:]
    if len(commandline_args) == 1:
        for argument in commandline_args:
            if argument in allCommandsDict:
                allCommandsDict[argument]()
            else:
                usage()
    elif len(commandline_args) == 2:
        if sys.argv[1] == "-k":
            flag = sys.argv[2:]
            for f in flag:
                if f in subcommandsDict:
                    subcommandsDict[f]()
        else:
            usage()
    else:
        usage()


if __name__ == "__main__":
    main()
