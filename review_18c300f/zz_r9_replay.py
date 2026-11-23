import pytest
from hypothesis import HealthCheck, reproduce_failure, settings
from hypothesis.stateful import get_state_machine_test
from tests.test_sync_state_machine import SyncMachine, TeamLogMachine, loopback_server  # noqa
CASES = [
  (SyncMachine, b'AXicXY7BCsIwEERn41EvIhQqRWjV2oNIKfoB7/9/ymRTk2I27MzA7uyIiZnATcRSwYaTYcZBMuVn/ulYRySxloldpnFFRYijbfY3nKs78OKTYCSI/V+EN4N+t1rjWcQjYUitDpy9L1FcnHX0NZ67xWyZVaN7Dv8FpNIaYw=='),
  (SyncMachine, b'AXicY3DUcDRwZHJUYXAEQgY4LeYozOjIyOjIw8DAyAABjGDkKOMIVWIAJEBMBSifwdEURKg6MgIAeu4IwQ=='),
  (TeamLogMachine, b'AXicjZLrSsNAEIXnJLVeaqoI8V5Rqa2KilWK+fs9ly/vTLapjSFS2GQ3A9+Zs2difLPkXtzyJZP5kuJptrTHO9VExgjDjAVTYeJjO27ASVBLZpZ4R+OUBd5oeu2JSzFeazaqteIfSUOxjGtexURuqM2lz1+ucVLi9zDOGK28fDIX55x2+UagG4H3fgunruUKD6KK48A4EmXo7hh7tb0XRe3RyAPa5z0Sn/X1amqpWruNlCLtY0+bagP8h9vlLplcUPBMps2c3W3h5uZbelhrZVzV+4UYRmSV+gbV4nPGqe+hgipWXH/OG30V/SYRuv8XB51+7f/CT1TeamjOxn1vIrEyBpNbzMpnoB9ZPy6c'),
  (TeamLogMachine, b'AXicjZJtSwJBFIXv0YJkQcIoSzPCwtSU8g0DPz2/qz/fvTtN65ZKMDuze9nn3HNmxvhkw1A8spXJfEjx5CWtMaeaaFBgmLHgWZhY/o87oxPUhpEl3tF4awSeNb02oSfaP5pZtVT8JWkohnHPXAzkhupc+qy47OQaz2F0Kb69rHgRt9z85bNAPUoIeO9+6aDFnXgNA6ddJ7jFmGb0vBRTtzDdo+ots1LiCj5SU496JWbi4TSZZs7pB9UUT2In3vynQxGrmu3vkeda+N1gcnxrVO2QJ2s75+ney4NZxd1a0z0G15qKC0ZxHl/Y0SRs'),
  (TeamLogMachine, b'AXicjZDXCsJAEEXnWhALgoIFC4iI5cEHDYng2/kuf94d19UYEYTNTjJwbolxI2ctVlxksnAkf9KI0++4EzW6GGac2AgT5/+4BkOncrYW+YD6W83xpBl2B2ai/9JMqg/FiqQhP8aCo1gqBPrk4uebS0lGhB7GhO4zS8ZOTBl/80mg7Ntk7lAwHIgW7RJVMWUf9UPnus8WV3ENZj990tJeBQv/R56vJ6+ZPdifEeNNh8I7ojuinRth'),
  (TeamLogMachine, b'AXicjY/LCgIxDEXvHVw54ELwgSiIiDILFyqD6/Nd/ryJtT43QtqkgXOSiis9G7PmYlkRdp6aSs679ExDi5A4sjUyp/+4AeOkenYqfKBZNYlXZ/Q6Fmb0dFbr3filFM4QSw5m5VjokyvPF1c3mRD/EDPaxy5n9mbO9Jevgve5ZpiTu0BvKogSlA=='),
]
@pytest.mark.parametrize('i', range(len(CASES)))
def test_replay(loopback_server, i):
    M, blob = CASES[i]
    M.server = loopback_server
    t = get_state_machine_test(M, settings=settings(max_examples=300, stateful_step_count=25, deadline=None, derandomize=False, database=None, suppress_health_check=list(HealthCheck), print_blob=True))
    reproduce_failure('6.170.15', blob)(t)()
