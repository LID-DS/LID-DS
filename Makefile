.PHONY: help prepare-dev test lint run doc

VENV_NAME?=.env
VENV_ACTIVATE=. $(VENV_NAME)/bin/activate
PYTHON=${VENV_NAME}/bin/python3

.DEFAULT: help

help:
	@echo "make precommit"
	@echo "       versioning, sorting, cleanup, changelog"
	@echo "make prepare-dev"
	@echo "       prepare development environment, use only once"
	@echo "make test"
	@echo "       run tests"
	@echo "make lint"
	@echo "       run pylint and mypy"
	@echo "make doc"
	@echo "       build html documentation"


prepare-dev:
	python3 -m pip install virtualenv
	make venv

# Requirements are in setup.py, so whenever setup.py is changed, re-run installation of dependencies.
venv: $(VENV_NAME)/bin/activate
$(VENV_NAME)/bin/activate: setup.py
	test -d $(VENV_NAME) || virtualenv -p python3 $(VENV_NAME)
	${PYTHON} -m pip install -U pip
	${PYTHON} -m pip install -r dev-requirements.txt
	${PYTHON} -m pip install -r requirements.txt
	${PYTHON} -m pip install -e .
	touch $(VENV_NAME)/bin/activate

test: venv
	${PYTHON} -m pytest

lint: venv
	${PYTHON} -m pylint lid_ds
	${PYTHON} -m pylint test

doc: venv
	$(VENV_ACTIVATE) && cd docs; make html