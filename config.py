import logging.config
import os

_CURRENT_FILE = os.path.abspath(__file__)
SRC_DIR = os.path.dirname(_CURRENT_FILE)
ROOT_DIR = os.path.dirname(SRC_DIR)
config_path = os.path.join("/etc/samplemod2/", "logging.ini")
config_path = os.path.join(SRC_DIR, "conf", "logging.ini")

logging.config.fileConfig(config_path, defaults={'logfilename': 'temp.log'})
LOG = logging.getLogger('sLogger')
