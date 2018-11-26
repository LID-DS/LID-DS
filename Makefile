clean:
	rm -rf lid.egg-info && rm -rf dist && rm -rf build

build: *.py lidds/*.py clean
	source ./scripts/updateVersionBuild.sh && python3 setup.py sdist bdist_wheel