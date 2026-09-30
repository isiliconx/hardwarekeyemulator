import os
import sys
import threading

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(SRC))

import lab_server


def test_update_db_serializes_read_modify_write(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_server, "DB_PATH", str(tmp_path / "users.json"))
    barrier = threading.Barrier(8)

    def worker(index):
        barrier.wait()
        lab_server.update_db(lambda db: db.__setitem__(str(index), {"id": index}))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert lab_server.load_db() == {
        str(index): {"id": index} for index in range(8)
    }


def test_challenge_is_consumed_once():
    with lab_server.app.test_request_context("/"):
        encoded = lab_server.challenge()
        first = lab_server.consume_challenge()
        assert first
        assert encoded
        try:
            lab_server.consume_challenge()
        except lab_server.RpError as exc:
            assert "already-consumed" in str(exc)
        else:
            raise AssertionError("challenge replay was accepted")


def test_replaying_signed_session_cookie_cannot_restore_consumed_challenge():
    import pytest
    from flask import session
    with lab_server.app.test_request_context("/"):
        value = lab_server.challenge()
        lab_server.consume_challenge()
    with lab_server.app.test_request_context("/"):
        session["challenge"] = value  # Flask restores the old signed cookie unchanged.
        with pytest.raises(lab_server.RpError):
            lab_server.consume_challenge()
