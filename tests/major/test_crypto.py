"""Tests for UrsaCrypto AEAD encryption layer."""

import pytest

from major.crypto import (
    FRAME_MAGIC,
    NONCE_SIZE,
    TAG_SIZE,
    UrsaCrypto,
    derive_key,
    generate_session_key,
)


class TestEncryptDecryptRoundTrip:

    def test_short_string(self, crypto_instance):
        ct = crypto_instance.encrypt(b"hello")
        assert crypto_instance.decrypt(ct) == b"hello"

    def test_string_input(self, crypto_instance):
        ct = crypto_instance.encrypt("hello string")
        assert crypto_instance.decrypt(ct) == b"hello string"

    def test_exact_block_size(self, crypto_instance):
        plaintext = b"A" * 16
        ct = crypto_instance.encrypt(plaintext)
        assert crypto_instance.decrypt(ct) == plaintext

    def test_multi_block(self, crypto_instance):
        plaintext = b"B" * 100
        ct = crypto_instance.encrypt(plaintext)
        assert crypto_instance.decrypt(ct) == plaintext

    def test_empty_bytes(self, crypto_instance):
        ct = crypto_instance.encrypt(b"")
        assert crypto_instance.decrypt(ct) == b""

    def test_binary_data(self, crypto_instance):
        plaintext = bytes(range(256))
        ct = crypto_instance.encrypt(plaintext)
        assert crypto_instance.decrypt(ct) == plaintext


class TestMessageFormat:

    def test_minimum_output_size(self, crypto_instance):
        ct = crypto_instance.encrypt(b"")
        # 4-byte frame magic + 12-byte nonce + 16-byte AES-GCM tag.
        assert len(ct) == len(FRAME_MAGIC) + NONCE_SIZE + TAG_SIZE

    def test_frame_prefix_and_nonce_size(self, crypto_instance):
        ct = crypto_instance.encrypt(b"framed")
        assert ct.startswith(FRAME_MAGIC)
        nonce = ct[len(FRAME_MAGIC):len(FRAME_MAGIC) + NONCE_SIZE]
        assert len(nonce) == NONCE_SIZE

    def test_output_size_scales(self, crypto_instance):
        ct_short = crypto_instance.encrypt(b"a")
        ct_long = crypto_instance.encrypt(b"a" * 100)
        assert len(ct_long) > len(ct_short)

    def test_different_ivs_per_call(self, crypto_instance):
        ct1 = crypto_instance.encrypt(b"same")
        ct2 = crypto_instance.encrypt(b"same")
        assert ct1 != ct2

    def test_known_answer_frame(self):
        crypto = UrsaCrypto(bytes(range(32)))
        nonce = bytes(range(NONCE_SIZE))
        ct = crypto.encrypt(b"Ursa AES-GCM known answer", nonce=nonce)
        assert ct.hex() == (
            "55525332000102030405060708090a0b1270a57ae5a48748a006d4c691821602f"
            "4b8a7559e0828194a485d9866b03cffc622048b7ac93e2486"
        )
        assert crypto.decrypt(ct) == b"Ursa AES-GCM known answer"


class TestIntegrity:

    def test_tampered_ciphertext_raises(self, crypto_instance):
        ct = crypto_instance.encrypt(b"secret data")
        tampered = bytearray(ct)
        tampered[20] ^= 0xFF
        with pytest.raises(ValueError, match="authentication"):
            crypto_instance.decrypt(bytes(tampered))

    def test_wrong_key_raises(self):
        c1 = UrsaCrypto(b"key-one-aaaa-bbbb")
        c2 = UrsaCrypto(b"key-two-cccc-dddd")
        ct = c1.encrypt(b"data for key one")
        with pytest.raises(ValueError, match="authentication"):
            c2.decrypt(ct)

    def test_data_too_short_raises(self, crypto_instance):
        with pytest.raises(ValueError, match="too short"):
            crypto_instance.decrypt(b"short")

    def test_legacy_frame_rejected(self, crypto_instance):
        old_ctr_hmac_shape = (b"\x00" * 16) + b"ciphertext" + (b"\x00" * 32)
        with pytest.raises(ValueError, match="legacy"):
            crypto_instance.decrypt(old_ctr_hmac_shape)


class TestJsonEncryption:

    def test_dict_roundtrip(self, crypto_instance):
        obj = {"session": "abc123", "tasks": [1, 2, 3]}
        encrypted_str = crypto_instance.encrypt_json(obj)
        assert isinstance(encrypted_str, str)
        assert crypto_instance.decrypt_json(encrypted_str) == obj

    def test_list_roundtrip(self, crypto_instance):
        obj = [1, "two", None, True]
        assert crypto_instance.decrypt_json(crypto_instance.encrypt_json(obj)) == obj


class TestBeaconInterop:

    def test_python_beacon_encrypts_for_server_crypto(self):
        from implants.beacon import UrsaBeacon

        key_hex = bytes(range(32)).hex()
        beacon = UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False, amsi_bypass=False)
        beacon.session_key = key_hex

        payload = {"result": "uid=0(root)", "error": ""}
        assert UrsaCrypto(key_hex).decrypt_json(beacon._encrypt_json(payload)) == payload

    def test_python_beacon_decrypts_server_crypto(self):
        from implants.beacon import UrsaBeacon

        key_hex = bytes(range(32)).hex()
        beacon = UrsaBeacon("http://127.0.0.1:6708", sandbox_check=False, amsi_bypass=False)
        beacon.session_key = key_hex

        payload = {"tasks": [{"id": "t1", "type": "whoami", "args": {}}]}
        assert beacon._decrypt_json(UrsaCrypto(key_hex).encrypt_json(payload)) == payload


class TestHelperFunctions:

    def test_generate_session_key_length(self):
        key = generate_session_key()
        assert len(key) == 64  # 32 bytes = 64 hex chars

    def test_generate_session_key_uniqueness(self):
        keys = {generate_session_key() for _ in range(100)}
        assert len(keys) == 100

    def test_derive_key_deterministic_with_salt(self):
        k1, salt = derive_key("password123")
        k2, _ = derive_key("password123", salt=salt)
        assert k1 == k2

    def test_derive_key_different_passwords(self):
        k1, salt = derive_key("password1")
        k2, _ = derive_key("password2", salt=salt)
        assert k1 != k2

    def test_derive_key_returns_correct_sizes(self):
        k, salt = derive_key("test")
        assert len(k) == 32
        assert len(salt) == 16
