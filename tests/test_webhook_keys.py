from pantomath.alerts.webhook_keys import hash_key, mask_url, new_salt, verify_key


def test_hash_key_is_deterministic_for_the_same_salt():
    salt = new_salt()
    assert hash_key("hunter2", salt) == hash_key("hunter2", salt)


def test_hash_key_differs_for_different_salts():
    key = "hunter2"
    assert hash_key(key, new_salt()) != hash_key(key, new_salt())


def test_verify_key_accepts_the_correct_key():
    salt = new_salt()
    row = {"key_hash": hash_key("correct-horse", salt), "key_salt": salt.hex()}
    assert verify_key(row, "correct-horse") is True


def test_verify_key_rejects_an_incorrect_key():
    salt = new_salt()
    row = {"key_hash": hash_key("correct-horse", salt), "key_salt": salt.hex()}
    assert verify_key(row, "wrong-guess") is False


def test_verify_key_rejects_when_row_has_no_key_set():
    assert verify_key({"key_hash": None, "key_salt": None}, "anything") is False


def test_mask_url_keeps_scheme_and_host_hides_path():
    masked = mask_url("https://hooks.slack.com/services/T000/B000/verysecrettoken1234")
    assert masked.startswith("https://hooks.slack.com/")
    assert "verysecrettoken1234" not in masked
    assert masked.endswith("1234")  # last 4 chars kept, to help identify which webhook this is
