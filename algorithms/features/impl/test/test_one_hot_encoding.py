from algorithms.features.impl.one_hot_encoding import OneHotEncoding
from algorithms.features.impl.syscall_name import SyscallName
from algorithms.features.impl.test.helper import build_fake_syscall_2019
from dataloader.syscall_2019 import Syscall2019



def test_OneHotEncoding():

    training_input = ["a","b","c","d"]
    
    ohe = OneHotEncoding(SyscallName())

    print("OHE training...")
    for element in training_input:
        syscall = build_fake_syscall_2019(name=element)
        ohe.train_on(syscall)
    ohe.fit()

    print("checking size of learned embedding")
    assert ohe.get_embedding_size() == len(training_input) + 1

    print("check the learned embeddings")
    syscall = build_fake_syscall_2019(name="a")
    assert ohe.get_result(syscall) == (1,0,0,0,0)
    syscall = build_fake_syscall_2019(name="d")
    assert ohe.get_result(syscall) == (0,0,0,1,0)
    syscall = build_fake_syscall_2019(name="unknown")
    assert ohe.get_result(syscall) == (0,0,0,0,1)
