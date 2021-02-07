import logging
import logging.handlers
import os

from lid_ds.core.objects.environment import ScenarioEnvironment

logger_name = "lidds_logger"


def _init_logger():
    formatter_stream = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(container)s - %(message)s')
    formatter_file = logging.Formatter(fmt='%(levelname)s - %(container)s - %(message)s')

    fh = logging.FileHandler(os.path.join(ScenarioEnvironment().out_dir, 'runs.log'))
    fh.setFormatter(formatter_file)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter_stream)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(fh)
    return logger


def print_logs():
    queue = ScenarioEnvironment().logging_queue
    logger = _init_logger()
    while True:
        try:
            record = queue.get()
            if record is None:
                break
            logger.handle(record)
        except:
            pass


def stop():
    # lock.acquire()
    queue = ScenarioEnvironment().logging_queue
    queue.put_nowait(None)
    # lock.release()


def get_logger(name, queue):
    return ContainerLogger(name, queue)


class ContainerLogger:
    def __init__(self, name, queue):
        self.logger = logging.getLogger(logger_name + "_" + name)
        queue_handler = logging.handlers.QueueHandler(queue)
        self.logger.addHandler(queue_handler)
        self.logger.setLevel(logging.DEBUG)  # log all messages to queue
        self.name = name

    def info(self, message):
        self.logger.info(message, extra={'container': self.name})

    def debug(self, message):
        self.logger.debug(message, extra={'container': self.name})


