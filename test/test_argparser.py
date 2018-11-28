import sys

from lidds import LIDArgparser

try:
  # python 3.4+ should use builtin unittest.mock not mock package
  from unittest.mock import patch
except ImportError:
  from mock import patch

def test_argparser_defaults():
  testargs = ["main.py","-wt", "1500", "-rt", "5000"]
  with patch.object(sys, 'argv', testargs):
      args = LIDArgparser().parse_args()
      assert(hasattr(args, 'recording_time'))
      assert(hasattr(args, 'warmup_time'))
      if hasattr(args, 'execute_exploit'):
        assert(hasattr(args, 'execute_exploit'))
        assert(hasattr(args, 'wait_before_exploit'))