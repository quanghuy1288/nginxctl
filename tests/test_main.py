import pytest
import mock
import textwrap
import nginxctl

NGINXCTL_USAGE = textwrap.dedent("""\
    Usage: nginxctl.py [option]
    Example: nginxctl.py -v
    \n
    Available options:
    \t-S list nginx vhosts
    \t-t configuration test
    \t-k start|stop|status|restart|fullstatus
    \t-v version
    \t-h help
    """)


n = nginxctl.nginxCtl()


def test_usage(capsys, monkeypatch):
    mock_nginx = mock.MagicMock(spec=n)
    monkeypatch.setattr(nginxctl.sys, 'argv', ['nginxctl.py', '-h'])
    nginxctl.main()
    out, err = capsys.readouterr()
    assert str(out) == NGINXCTL_USAGE


def test_option_k(capsys, monkeypatch):
    def mockreturn_nginx_pid(get_nginx_pid):
        return '/run/nginx.pid' 
    def mockreturn_nginx_lock(get_nginx_lock):
        return '/run/lock/subsys/nginx'
    mock_nginx = mock.MagicMock(spec=n)
    monkeypatch.setattr(nginxctl.nginxCtl, 'get_nginx_pid', mockreturn_nginx_pid)
    monkeypatch.setattr(nginxctl.nginxCtl, 'get_nginx_lock', mockreturn_nginx_lock)
    monkeypatch.setattr(nginxctl.sys, 'argv', ['nginxctl.py', '-k', 'status'])
    nginxctl.main()
    out, err = capsys.readouterr()
    assert str(out) == 'nginx is stopped\n'


def test_nginxctl(monkeypatch):
    mock_nginx = mock.MagicMock(spec=n)
    monkeypatch.setattr(nginxctl.sys, 'argv', ['nginxctl.py', '-S'])
    monkeypatch.setattr(nginxctl, 'nginxCtl', mock_nginx)
    nginxctl.nginxCtl()
    mock_nginx.assert_called()
