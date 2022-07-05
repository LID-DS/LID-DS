import pytest
from algorithms.features.impl.random_value import RandomValue


def test_random_value():
    rnd_1 = RandomValue(scale=1.0, size=1)
    print(rnd_1.get_result(None))
    assert type(rnd_1.get_result(None)) is float # scalar random value

    rnd_2 = RandomValue(scale=1.0, size=2) 
    print(rnd_2.get_result(None))
    assert len(rnd_2.get_result(None)) == 2 # 2 random values as tuple

    rnd_3 = RandomValue(scale=1.0, size=3) 
    print(rnd_3.get_result(None))
    assert len(rnd_3.get_result(None)) == 3 # 3 random values as tuple


    # generate 100 values betwee -10 and 10
    # than check if at least one is bigger as 1 and one is smaler than -1
    rnd_4 = RandomValue(scale=10.0, size=100) 
    values = rnd_4.get_result(None)
    print(values)
    min = 11
    max = -11
    for v in values:
        if v < min:
            min = v
        if v > max:
            max = v
    assert min < -1 and max > 1

test_random_value()