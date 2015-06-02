<h1>NginxCtl</h1>

This is a small tool to manage nginx service on a server. This is similar to
apachectl and the main feature of this tool is listing all enabled vhosts on a
nginx service.

<h2>Download/Installation</h2>
```
wget https://github.rackspace.com/alex4511/nginxctl/raw/master/nginxctl.py -O
nginxctl.py 
python nginxctl.py
```

<h2>Usage</h2>
```
python nginxctl.py -h
Usage: nginxctl.py [options]

Options:
  --version          show program version number and exit
  -h, --help         show this help message and exit
  -S, --list-vhosts  List configured vhost
  -t, --configtest   configuration test
  --start            Start nginx service
  --stop             Stop nginx service
  --restart          Restart nginx service
```

Documentation can be found at: http://fooltruth.github.io/nginxctl/
