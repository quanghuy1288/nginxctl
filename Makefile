# working with centos7 os

SERVICE=nginx-agent
DEPLOY_DIR=/opt/$(SERVICE)
CONFIG_DIR=/etc/$(SERVICE)
SERVICE_PATH=/etc/systemd/system/$(SERVICE).service
SERVICE_ENV_PATH=$(SERVICE_PATH).d/
PIPENV_PIPFILE=$(DEPLOY_DIR)/Pipfile

BACKUP_TIME=$(shell date +'%y_%m_%d__%H_%M_%S')
BACKUP_DIR=$(DEPLOY_DIR)_bak_$(BACKUP_TIME)


guide:
	@echo "======================= guide ======================="
	@echo "Call 'make staging' for deploy staging mode"
	@echo "Call 'make product' for deploy product mode"
	@echo "Call 'make backup' for backup before deploy new version"
	@echo "Call 'make env' for install pyenv and pipenv only"
	@echo "Call 'make run' for test run"

install: env deploy
	@echo "install finished"

env:
	@echo "======================= install env ======================="
	@if ! hash /root/.pyenv/bin/pyenv; then\
		@echo "pyenv not found. prepare to install pyenv";\
		curl https://pyenv.run | bash ;\
		export PATH="/root/.pyenv/bin:$PATH" ;\
	else \
		echo "pyenv is installed already!";\
	fi

	@if ! hash pipenv; then\
		@echo "pipenv not found. prepare to install pipenv";\
		yum install -y python;\
		curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py";\
		python get-pip.py;\
		pip install pipenv;\
	else \
		echo "pipenv is installed already!";\
	fi

	@if [[ ! -f /usr/local/bin/pipenv ]]; then\
		ln -s /bin/pipenv /usr/local/bin/pipenv;\
	fi

deploy:
	yum install -y rsync

	@echo "=======================deploy agent======================="
	rm -Rf $(DEPLOY_DIR)/*
	mkdir -p $(DEPLOY_DIR)
	rsync -av ./ $(DEPLOY_DIR)/ --exclude=Makefile --exclude=.*

	@echo "=======================install lib dependence by pipenv======================="
	#PIPENV_PIPFILE=$(PIPENV_PIPFILE) pipenv --rm
	#PIPENV_PIPFILE=$(PIPENV_PIPFILE) pipenv sync
	pipenv --rm
	pipenv sync

	@echo "=======================prepare dir for config======================="
	mkdir -p $(CONFIG_DIR)


backup:
	@echo "======================= backup ======================="
	@if [ -d $(DEPLOY_DIR) ]; then\
		mkdir -p "$(BACKUP_DIR)/service";\
		mkdir -p "$(BACKUP_DIR)/config";\
		cp -Rf $(DEPLOY_DIR) $(BACKUP_DIR)/ ;\
 		cp -Rf $(CONFIG_DIR)/* $(BACKUP_DIR)/config ;\
		cp -Rf $(SERVICE_PATH) $(BACKUP_DIR)/service/ ;\
	fi

run:
	PIPENV_PIPFILE=$(PIPENV_PIPFILE) pipenv run python main.py

staging: install service
	@echo "======================= copy staging config ======================="
	\cp ./conf/logging.ini $(CONFIG_DIR)/logging.ini

product: install service
	@echo "======================= copy product config ======================="
	\cp ./conf/logging.ini $(CONFIG_DIR)/logging.ini


service:
	@echo "======================= copy systemd service file ======================="

