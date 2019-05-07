LID-DS
******


.. raw:: html
   <p align="center">
   <img src="https://raw.githubusercontent.com/LID-DS/LID-DS/master/lidds-logo-300.png">
   </p>


.. image:: https://travis-ci.org/LID-DS/LID-DS.svg?branch=master
    :target: https://travis-ci.org/LID-DS/LID-DS

The LID-DS package presents a lightweight framework for simulating attack/non-attack scenarios in a host intrusion detection context. This package handles the timing of events like:

* Container Initialization
* Starting Normal Behaviour
* Warmup Phase
* Recording via Sysdig_
* Executing the exploit dependend on the fact if the scenario is an attack scenario or not

LID-DS manages docker containers on which the scenarios are modeled. The result of such a simulation should be a scap file expressing the system calls executed by the docker container during the scenario.


Installation
------------

.. code-block:: bash

   pip3 install git+https://github.com/LID-DS/LID-DS


Requirements
------------

* Sysdig_
* Docker_

.. _Sysdig: https://sysdig.com/opensource
.. _Docker: https://www.docker.com

Links
-----

* Documentation_
* Code_
* `Issue Tracker`_

.. _Documentation: https://lid-ds.github.io/LID-DS/html/index.html](https://lid-ds.github.io/LID-DS/html/index.html
.. _Code: https://github.com/LID-DS/LID-DS](https://github.com/LID-DS/LID-DS
.. _Issue Tracker: https://github.com/LID-DS/LID-DS/issues](https://github.com/LID-DS/LID-DS/issues
Contribution
------------

For guidance on setting up a development environment and how to make a contribution to LID-DS, see the contribution guidelines.

License
-------

Leipzig Intrusion Detection Dataset (LID-DS)
Copyright (C) 2018 Martin Grimmer, Martin Max Röhling, Dennis Kreußel and Simon Ganz

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

Contact
-------

Leipzig University, Martin Grimmer (grimmer@informatik.uni-leipzig.de) and Martin Max Röhling (roehling@wifa.uni-leipzig.de).

Acknowledgements
----------------

This work was partly funded by the German Federal Ministry of Education and Research within the project `Explicit Privacy-Preserving Host Intrusion Detection System (EXPLOIDS)`_ (BMBF 16KIS0522K) and `Competence Center for Scalable Data Services and Solutions (ScaDS) Dresden/Leipzig`_ (BMBF 01IS14014B).

.. _Explicit Privacy-Preserving Host Intrusion Detection System (EXPLOIDS): http://www.exploids.de
.. _Competence Center for Scalable Data Services and Solutions (ScaDS) Dresden/Leipzig: http://www.scads.de
