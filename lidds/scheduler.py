import numpy as np
import scheduler_constants
import threading
from threading import Timer

__all__ = ['scheduler']

def uniform_K():
    """
    Returns a uniformly chosen k-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=scheduler_constants.MIN_K, 
        high=scheduler_constants.MAX_K
    )

def uniform_ALPHA():
    """
    Returns a uniformly chosen α-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=scheduler_constants.MIN_ALPHA, 
        high=scheduler_constants.MAX_ALPHA
    )

def uniform_THETA():
    """
    Returns a uniformly chosen θ-parameter value from the Values recommended from
    >>Empirical Model of WWW Document Arrivals at Access Link<<
    """
    return np.random.uniform(
        low=scheduler_constants.MIN_THETA, 
        high=scheduler_constants.MAX_THETA
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
    while(True):
        inter_time = 1.5 * np.random.weibull(0.5)
        if sum(map(float,timers)) + inter_time > on_time:
            break
        else:
            timers.append(inter_time)
    
    for idx, timer in enumerate(timers):
        Timer(timer, fn, (idx,)).start()

if __name__ == "__main__":
    scheduler(lambda x: print("hi: {}".format(x)))