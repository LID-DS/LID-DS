import sched, time
from lid_ds.sim import gen_schedule_wait_times

class Behaviour:
    def __init__(self, actions, total_duration):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.actions = actions
        self.wait_times = gen_schedule_wait_times(total_duration)

    def __call__(self, *args, **kwargs):
        if len(self.actions) == len(self.wait_times):
            for i in range(len(min([self.actions, self.wait_times], key=len))):
                time.sleep(wait_times[i])
                actions[i]()