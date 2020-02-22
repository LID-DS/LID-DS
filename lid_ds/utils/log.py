import logging
import logging.handlers
import multiprocessing
import time
from enum import Enum

logger_name = "lidds_logger"


def _init_logger():
    formatter = logging.Formatter(fmt='%(levelname)s - %(container)s - %(message)s')

    fh = logging.FileHandler('spam.log')
    fh.setFormatter(formatter)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(fh)
    return logger


def print_logs(queue):
    logger = _init_logger()
    while True:
        try:
            record = queue.get()
            if record is None:
                break
            logger.handle(record)
        except Exception as e:
            print('Whoops! Problem:', e)


def stop(queue):
    # lock.acquire()
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


