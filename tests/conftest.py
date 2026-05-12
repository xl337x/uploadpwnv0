import socket, threading, time, sys, os, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mock_target, hard_target, discovery_target, multi_target


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]; s.close()
    return port


def _wait(port):
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)


@pytest.fixture(scope="session")
def target():
    port = _free_port()
    t = threading.Thread(target=mock_target.run, args=(port,), daemon=True)
    t.start()
    _wait(port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="session")
def hard():
    port = _free_port()
    t = threading.Thread(target=hard_target.run, args=(port,), daemon=True)
    t.start()
    _wait(port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="session")
def disco():
    port = _free_port()
    t = threading.Thread(target=discovery_target.run, args=(port,), daemon=True)
    t.start()
    _wait(port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="session")
def multi():
    port = _free_port()
    t = threading.Thread(target=multi_target.run, args=(port,), daemon=True)
    t.start()
    _wait(port)
    return f"http://127.0.0.1:{port}"
