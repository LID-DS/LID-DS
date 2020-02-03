import sched, time
from lid_ds.sim import gen_schedule_wait_times, sampler

class Behaviour:
    def __init__(self, actions, total_duration):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.actions = actions
        self.wait_times = gen_schedule_wait_times(total_duration)

    def __call__(self, *args, **kwargs):
        if len(self.actions) == len(self.wait_times):
            for i in range(len(min([self.actions, self.wait_times], key=len))):
                time.sleep(self.wait_times[i])
                self.actions[i]()


class GeneratedBehaviour:
    def __init__(self, actions, total_duration):
        self.sample = sampler.generate_sample_real_data(total_duration)
        self.actions = actions
        self.wait_times = sampler.convert_sample_to_wait_times(self.sample)
        sampler.visualize_sample(self.sample, total_duration)

    def __call__(self, *args, **kwargs):
        if len(self.actions) == len(self.wait_times):
            for i in range(len(min([self.actions, self.wait_times], key=len))):
                time.sleep(self.wait_times[i])
                self.actions[i]()
