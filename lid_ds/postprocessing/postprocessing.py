import os

from lid_ds.core.collector.collector import Collector
from lid_ds.core.image import ChainImage
from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.utils import log
from .matcher import PostprocessingMatcher


def optimize_attack_time(image: ChainImage):
    env = ScenarioEnvironment()
    logger = log.get_logger("postprocessing", env.logging_queue)

    scap = os.path.join(env.out_dir, f'{env.recording_name}.scap')
    pcap = os.path.join(env.out_dir, f'{env.recording_name}.pcap')
    ip = Collector().attacker_ip

    logger.info(f"Starting postprocessing")

    matcher = PostprocessingMatcher(pcap, scap, ip)

    for command in image.commands:
        optimized_time = matcher.get_exact_attack_time(command.after_packet)
        Collector().set_exploit_time(command.name, optimized_time)

    logger.info(f"Finished postprocessing")
