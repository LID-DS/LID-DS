#!/usr/bin/python

# Leipzig Intrusion Detection Dataset (LID-DS)
# Copyright (C) 2018 Martin Grimmer, Martin Max Röhling, Dennis Kreußel and Simon Ganz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# The Scheduler provides functions that provide an option to let specific functions get called
# appropriate to an probabilistic time model.
from math import exp

MIN_K = .77
MAX_K = .91

MIN_ALPHA = .58
MAX_ALPHA = .9

MIN_THETA = exp(4.4)
MAX_THETA = exp(4.6)

INTER_COEFFICIENT = .5
INTER_SCALE = 1.5