import pydot


def decode_graph(dot_string: str):
    graph = pydot.graph_from_dot_data(dot_string)
    print(graph)


if __name__ == '__main__':
    decode_graph("strict digraph  {"StreamSum(0x7f5bfb3607f0, {'thread_aware': False, 'window_length': 10})" -> "AE(0x7f5bfc249048, {'mode': <AEMode.LOSS: 1>, 'batch_size': 256, 'max_training_time': 600, 'early_stopping_epochs': 50})"; "AE(0x7f5bfc249048, {'mode': <AEMode.LOSS: 1>, 'batch_size': 256, 'max_training_time': 600, 'early_stopping_epochs': 50})" -> "Ngram(0x7f5bfc2490f0, {'thread_aware': True, 'ngram_length': 7})"; "Ngram(0x7f5bfc2490f0, {'thread_aware': True, 'ngram_length': 7})" -> "OneHotEncoding(0x7f5bfc249080)";"OneHotEncoding(0x7f5bfc249080)" -> "SyscallName(0x7f5d1d893748)";}")
