import os
from concurrent.futures.thread import ThreadPoolExecutor

from lid_ds.core.collector.collector import Collector
from lid_ds.core.image import ChainImage, ExecCommand
from lid_ds.core.objects.environment import ScenarioEnvironment
from lid_ds.postprocessing.tcpdump import TCPPacketPartsMatcher
from lid_ds.utils import log
from lid_ds.postprocessing.matcher import PostprocessingMatcher


def optimize_attack_time(image: ChainImage):
    env = ScenarioEnvironment()
    logger = log.get_logger("postprocessing", env.logging_queue)

    scap = os.path.join(env.out_dir, f'{env.recording_name}.scap')
    pcap = os.path.join(env.out_dir, f'{env.recording_name}.pcap')
    ip = Collector().attacker_ip
    logger.info(f"Starting postprocessing for attacker {ip}")

    matcher = PostprocessingMatcher(pcap, scap, ip)

    for command in image.commands:
        optimized_time, source = matcher.get_exact_attack_time(command.after_packet)
        Collector().set_exploit_time(command.name, optimized_time, source)

    logger.info(f"Finished postprocessing")


if __name__ == '__main__':
    portscan = ExecCommand("sh /app/nmap.sh ${victim}", name="port-scan")
    bruteforce = ExecCommand("sh /app/hydra.sh ${victim}", name="brute-force",
                             after_packet=TCPPacketPartsMatcher(["GET /", "User-Agent: curl"],
                                                                forbidden_parts=["Authorization"]))
    privilege_escalation = ExecCommand("python3 /app/attacker.py ${victim}:5984", name="privilege-escalation",
                                       after_packet=TCPPacketPartsMatcher(["GET /_all_dbs", "User-Agent: curl",
                                                                           "Authorization"]))
    remote_code = ExecCommand("python3 /app/reverse-shell.py ${victim}:5984", name="remote-code",
                              after_packet=TCPPacketPartsMatcher(["GET /_users/_all_docs",
                                                                  "Authorization"]))

    exploit_full = ChainImage("exploit_couchdb",
                              commands=[portscan, bruteforce, privilege_escalation, remote_code])

    ScenarioEnvironment().out_dir = "../../couchdb_example/runs"
    ScenarioEnvironment().recording_name = "young_franklin_9218"
    Collector().add_container("x", "attacker", "192.168.224.3")
    optimize_attack_time(exploit_full)
