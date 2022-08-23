from dataloader.syscall_2019 import Syscall2019

def build_fake_syscall_2019(
        path="fakepath",
        cpu="1",
        timestamp="00:08:15.12345678",
        user_id="1",
        process_id="999",
        process_name="test_process",
        thread_id="1",
        direction=">",
        name="test_syscall",
        params="res=3 data=...") -> Syscall2019:
    
    syscall_string = f"{timestamp} {cpu} {user_id} {process_id} {process_name} {thread_id} {direction} {name} {params}"
    return Syscall2019(path,syscall_string,-1)
