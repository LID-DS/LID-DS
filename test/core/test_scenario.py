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
    class DerivedScenario(Scenario):
        """
        a custom scenario with all required hooks
        """
        def exploit(self):
            """
            a sample exploit hook doing nothing
            """
    DerivedScenario()
