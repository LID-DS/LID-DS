"""
Leipzig Intrusion Detection Dataset (LID-DS)
Leipzig Intrusion Detection Dataset (LID-DS) Copyright (C) 2021 Martin Grimmer, Felix Nirsberger, Tim Kaelble,
Toni Rucks, Martin Max Röhling, Dennis Kreußel and Simon Ganz.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from setuptools import setup

setup(name='lid_ds',
      version='2.2.0',
      description='Leipzig Intrusion Detection Data Set Framework',
      url='https://github.com/LID-DS/LID-DS',
      packages=[
        'lid_ds',
        'lid_ds.analysis',
        'lid_ds.core',
        'lid_ds.core.collector',
        'lid_ds.data_models',
        'lid_ds.export',
        'lid_ds.helpers',
        'lid_ds.sim',
        'lid_ds.utils',
        'lid_ds.vis',
        'algorithms',
        'dataloader',
        'tools',
      ],
      platforms=['linux_x86_64'],
      install_requires=[
          'huepy',
          'docker',
          'numpy',
          'pexpect',
          'terminaltables',
          'docopt'
      ],
      entry_points={
        'console_scripts': ['lid_ds_analysis=lid_ds.analysis.main:main'],
      },
      zip_safe=True
)
