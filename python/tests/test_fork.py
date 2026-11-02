"""After os.fork() a child can keep using what the parent loaded, and load
more: the parallel loops run on a pool the child rebuilds (rayon's global
pool would leave it waiting forever on threads that don't exist there), and
file reads don't share a seek offset with the parent."""

import os
import signal
import sys
import time
import warnings

import pytest

import androguard_rs
import fixture_apk as fx

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")

DEADLINE = 60


@pytest.fixture(scope="module")
def apk_path(tmp_path_factory):
    return str(fx.build_apk(tmp_path_factory.mktemp("fork") / "fixture.apk"))


def queries(apk):
    """Calls that each run a parallel loop natively."""
    return (
        apk.const_strings(include_jumbo=True),
        sorted(apk.methods_using_string("a")),
        apk.search_instruction_text(["const-string", "invoke"]),
        apk.classes(),
    )


def in_child(fn):
    """Run fn() in a forked child; fail if it raises, disagrees or hangs."""
    with warnings.catch_warnings():
        # 3.12+ warns that forking a process with threads may deadlock;
        # that is what this checks doesn't happen.
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        code = 1
        try:
            code = 0 if fn() else 2
        except BaseException as e:
            print(f"child: {e!r}", file=sys.stderr)
        finally:
            os._exit(code)
    wait(pid)


def wait(pid):
    """Wait for a forked child to exit 0; kill it and fail if it hangs."""
    t = time.monotonic()
    while time.monotonic() - t < DEADLINE:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            assert os.waitstatus_to_exitcode(status) == 0
            return
        time.sleep(0.02)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    pytest.fail(f"forked child still running after {DEADLINE}s (deadlocked)")


def test_child_uses_parents_apk(apk_path):
    apk = androguard_rs.Apk(apk_path)
    want = queries(apk)
    in_child(lambda: queries(apk) == want)


def test_child_loads_and_queries(apk_path):
    apk = androguard_rs.Apk(apk_path)
    want = queries(apk)
    in_child(lambda: queries(androguard_rs.Apk(apk_path)) == want)


def test_parent_and_child_read_the_same_file_together(apk_path):
    # Both keep loading from the inherited descriptor's file at once; with
    # a shared seek offset their reads would land in each other's places.
    apk = androguard_rs.Apk(apk_path)
    want = queries(apk)

    def child():
        return all(queries(androguard_rs.Apk(apk_path)) == want for _ in range(20))

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        os._exit(0 if child() else 2)
    try:
        for _ in range(20):
            assert queries(androguard_rs.Apk(apk_path)) == want
    finally:
        wait(pid)


def test_grandchild(apk_path):
    apk = androguard_rs.Apk(apk_path)
    want = queries(apk)

    def child():
        if queries(apk) != want:
            return False
        in_child(lambda: queries(apk) == want and queries(androguard_rs.Apk(apk_path)) == want)
        return True

    in_child(child)
