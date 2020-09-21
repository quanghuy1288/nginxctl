## NginxCtl

[![Build Status](https://travis-ci.org/rackerlabs/nginxctl.svg?branch=master)](https://travis-ci.org/rackerlabs/nginxctl) 

The nginxctl allows to control some of the functionlities of nginx daemon.
This tool is similar to apachectl and which main feature is to list
domains configured on a nginx webserver.

### Download/Installation
```
git clone https://github.com/rackerlabs/nginxctl.git 
cd nginxctl
python nginxctl.py
```

### Usage
```
Usage: nginxctl.py [option]
Example: nginxctl.py -v


Available options:
	-S list nginx vhosts
	-t configuration test
	-k start|stop|status|restart|fullstatus
	-v version
	-h help
```

Here is an example of running the option to discover virtual hosts:
```
# python nginxctl.py -S
nginx vhost configuration:
*:8080 is a Virtualhost
	port 8080 namevhost  example.com  (/etc/nginx/sites-enabled/example.com:5)
[::]:80 is a Virtualhost
	port 80 namevhost  example.com  (/etc/nginx/sites-enabled/example.com:5)
```

### Python3 version
```
python3 version: https://github.com/sjas/nginxctl/blob/master/nginxctl
```
