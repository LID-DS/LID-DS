from setuptools import setup

setup(name='lidds',
      version='0.1.28',
      description='Leipzig Intrusion Detection Data Set Framework',
      url='https://github.com/LID-DS/LID-DS',
      packages=['lidds'],
      platforms=['linux_x86_64'],
      install_requires=[
          'argparse',
          'promise',
          'docker',
          'pyyaml',
          'mock',
          'pexpect'
      ],
      zip_safe=True
)