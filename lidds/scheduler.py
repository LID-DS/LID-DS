"""
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


The Scheduler provides functions that provide an option to let specific functions get called
appropriate to an probabilistic time model.
"""
import numpy as np
import threading
from threading import Timer
import time
from .scheduler_constants import MIN_K, MAX_K, MIN_ALPHA, MAX_ALPHA, MIN_THETA, MAX_THETA

__all__ = ['scheduler', 'scheduler_sync']


def uniform_K():
    """
    Returns a uniformly chosen k-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=MIN_K,
        high=MAX_K
    )


def uniform_ALPHA():
    """
    Returns a uniformly chosen α-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=MIN_ALPHA,
        high=MAX_ALPHA
    )


def uniform_THETA():
    """
    Returns a uniformly chosen θ-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=MIN_THETA,
        high=MAX_THETA
    )


def scheduler(fn):
    """
    create weibull distributied timestamps and create on-time 
    """
    # print('on time start')
    off_time = np.random.pareto(0.9)
    on_time_scale, on_time_coefficient = uniform_THETA(), uniform_K()
    on_time = on_time_scale * (np.random.weibull(on_time_coefficient))

    # print(threading.active_count())
    inter_time_scheduler(on_time, fn)
    # print("{}s until next ON TIME block!".format(off_time))
    Timer(on_time + off_time, scheduler, (fn,)).start()


def inter_time_scheduler(on_time, fn):
    """
    create weibull distributied timestamps and call the function at them
    """
    timers = []
    while (True):
        inter_time = 1.5 * np.random.weibull(0.5)
        if sum(map(float, timers)) + inter_time > on_time:
            break
        else:
            timers.append(inter_time)

    for idx, timer in enumerate(timers):
        Timer(timer, fn, (idx,)).start()


def scheduler_sync(fn):
    """
    synchronous scheduler -> waits until fn returns before calling the next one
    """

    while True:
        """
        block duration: weibul
        next block: pareto
        """
        on_time_scale, on_time_coefficient = uniform_THETA(), uniform_K()
        block_duration = on_time_scale * (np.random.weibull(on_time_coefficient))
        block_start_time = time.time()
        block_end_time = block_start_time + block_duration
        off_time = np.random.pareto(0.9)
        next_inner_time = block_start_time
        while True:
            # call fn with the current timestamp
            fn(time.time())
            # get the next inner block event timestamp
            next_inner_time = 1.5 * np.random.weibull(0.5) + next_inner_time
            # now wait until the next inner event time
            current_time = time.time()
            inner_sleep_time = next_inner_time - current_time
            # check for block end
            if current_time > block_end_time:
                break
            # check for next event time
            # do not sleep if it will end after the block end
            if inner_sleep_time > 0:
                if current_time + inner_sleep_time > block_end_time:
                    break
                time.sleep(inner_sleep_time)

        # sleep off time
        sleep_until = block_end_time + off_time
        time_to_sleep = sleep_until - time.time()
        time.sleep(time_to_sleep)


if __name__ == "__main__":
    scheduler(lambda x: print("hi: {}".format(x)))
