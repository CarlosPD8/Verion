# Load-bearing for TWO suites: tests/integration/test_semgrep_adapter.py runs a real
# Semgrep over this directory, and tests/unit/test_route_extraction.py reads this file
# as its route-free miss case. Adding a route decorator here fails the second.
def run_user_input(user_input):
    return eval(user_input)
