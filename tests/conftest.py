import subprocess
import os
import pytest

TESTS_DIR = os.path.dirname(__file__)
TEST_BINARY_SRC = os.path.join(TESTS_DIR, "test_binary.c")
TEST_BINARY = os.path.join(TESTS_DIR, "test_binary")


@pytest.fixture(scope="session", autouse=True)
def compile_test_binary():
    """Compile the test C binary with debug symbols."""
    subprocess.check_call(
        ["gcc", "-g", "-O0", "-o", TEST_BINARY, TEST_BINARY_SRC]
    )
    yield
    if os.path.exists(TEST_BINARY):
        os.remove(TEST_BINARY)


@pytest.fixture()
def binary_path():
    return TEST_BINARY
