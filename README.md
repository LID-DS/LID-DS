# LID-DS
The LID-DS package presents a lightweight framework for simulating attack/non-attack scenarios in a host intrusion detection context. This package handles the timing of events like:
* Container Initialization
* Starting Normal Behaviour
* Warmup Phase
* Recording via Sysdig
* Executing the exploit dependend on the fact if the scenario is an attack scenario or not

LID-DS manages docker containers on which the scenarios are modeled. The result of such a simulation should be a pcap file expressing the system calls executed by the docker container during the scenario.

## Structure
The package contains the LID-LD library and a example scenario.
...

## Installation
...

## Usage
...

## License
Leipzig Intrusion Detection Dataset (LID-DS) 
Copyright (C) 2018 Martin Grimmer und Martin Max Röhling

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

## Contact
Leipzig University, Martin Grimmer (grimmer@informatik.uni-leipzig.de) and Martin Max Röhling (roehling@wifa.uni-leipzig.de).

## Acknowledgements
This work was partly funded by the German Federal Ministry of Education and Research within the project [Explicit Privacy-Preserving Host Intrusion Detection System](http://www.exploids.de) (EXPLOIDS) (BMBF 16KIS0522K) and [Competence Center for Scalable Data Services and Solutions (ScaDS) Dresden/Leipzig](http://www.scads.de) (BMBF 01IS14014B).
