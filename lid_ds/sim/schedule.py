import numpy as np
from .schedule_constants import MIN_K, MAX_K, MIN_ALPHA, MAX_ALPHA, MIN_THETA, MAX_THETA


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


def gen_schedule_wait_times(total_duration):
    """
    generates wait times according to the model of >>Empirical Model of WWW Document Arrivals at Access Link<<
    All wait times summed up are <= total_duration!
    :param total_duration: max sum of all wait times in seconds
    :return: a list of wait times which sum is at most total_duration (seconds)
    """
    on_time_scale, on_time_coefficient = uniform_THETA(), uniform_K()
    all_wait_times = []
    while sum(map(float, all_wait_times)) < total_duration:
        block_duration = on_time_scale * (np.random.weibull(on_time_coefficient))
        off_time = np.random.pareto(0.9)
        block_wait_times = []
        while sum(map(float, block_wait_times)) < block_duration:
            next_inner_block_time = 1.5 * np.random.weibull(0.5)
            block_wait_times.append(next_inner_block_time)
            if sum(map(float, all_wait_times)) + sum(map(float, block_wait_times)) > total_duration:
                break
        for inner_block_time in block_wait_times:
            all_wait_times.append(inner_block_time)
        if sum(map(float, all_wait_times)) + off_time < total_duration:
            all_wait_times.append(off_time)
    # finally remove all times from the end of the list which will result in a waiting time > total_duration
    # all_wait_times.pop()
    while sum(map(float, all_wait_times)) > total_duration:
        all_wait_times.pop()

    return all_wait_times
