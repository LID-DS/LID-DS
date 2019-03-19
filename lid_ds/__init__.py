"""
The lid_ds module provides a framework for simulating
and analysing security related attack scenarios and
normal system behaviour.
"""

#from sys import version_info, platform
#pylint: disable=E0611
#from huepy import bad, red


#To this date only python3 is supported
#if version_info < (3, 0, 0):
#    print(bad(red('To this date only Python 3 is supported.')))
#    exit(1)

"""
# sysdig needs to be found by the shell
if which("sysdig") is None:
    print(bad(red("The LID-DS framework depends on the sysdig system visibility tool.")))
    print(bad(red("To install sysdig execute the following command:")))
    #pylint: disable=C0301
    print(bad(red("curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash")))
    print(bad(red("Or refer to:")))
    #pylint: disable=C0301
    print(bad(red("https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux#user-content-automatic-installation")))
    exit(1)

# To this date only linux is supported for sysdig recording
if platform != "linux":
    print(bad(red("To this date the recording feature of sysdig is only supported on Linux!")))
    exit(1)

"""