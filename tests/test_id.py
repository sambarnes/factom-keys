import unittest

from factom_keys.id import IDPrivateKey, IDPublicKey, generate_id_pairs


class TestIDKeys(unittest.TestCase):
    def test_generate_key_pairs(self):
        pairs = generate_id_pairs()

        assert len(pairs) == 4

        for pair in pairs:
            private_key, public_key = pair
            assert isinstance(private_key, IDPrivateKey)
            assert isinstance(public_key, IDPublicKey)

    def test_key_string_validity_checkers(self):
        # All zeros private key
        private_keys = [
            "sk11pz4AG9XgB1eNVkbppYAWsgyg7sftDXqBASsagKJqvVRKYodCU",
            "sk229KM7j76STogyvuoDSWn8rvT6bRB1VoSMHgC5KD8W88E26iQM3",
            "sk32Tee5C4fCkbjbN4zc4VPkr9vX4xg8n53XQuWZx6xAKm2cAP7gv",
            "sk42myw2f2Dy3PnCoEBzgU1NqPPwYWBG4LehY8q4azmpXPqGY6Bqu",
        ]

        public_keys = [
            "id12HQxrj9A4ESYVWqKDx7UC1gJfXpUJDVWt6wHem4fjyNyUKVUx2",
            "id22bkFpC6ipXEb6wzWca65ozun61MyRVm84EAc9PxVQB1n9T9KhD",
            "id32v5Ymf4Hap2diP9i1C4hRz9FWUuUYn2jEMPve2rK4NeajXGoUh",
            "id43EQqj81rM6pgKpJuPp3K3yNivxSyg4JLQUdF8fk8iaHPTTdSdA",
        ]

        for k, p in zip(private_keys, public_keys):
            assert IDPrivateKey.is_valid(k)
            assert IDPublicKey.is_valid(p)

        # Bad prefixes
        private = "sk51pz4AG9XgB1eNVkbppYAWsgyg7sftDXqBASsagKJqvVRKYodCU"
        public = "ie11qFJ7fe26N29hrY3f1gUQC7UYArUg2GEy1rpPp2ExbnJdSj3mN"
        assert not IDPrivateKey.is_valid(private)
        assert not IDPublicKey.is_valid(public)

        # Bad bodies
        private = "sk11pz4AG9XgB1eNVkbppYYYYgyg7sftDXqBASsagKJqvVRKYodCU"
        public = "id11qFJ7fe26N29hrY3f1gYYY7UYArUg2GEy1rpPp2ExbnJdSj3mN"
        assert not IDPrivateKey.is_valid(private)
        assert not IDPublicKey.is_valid(public)

        # Bad checksums
        private = "sk11pz4AG9XgB1eNVkbppYAWsgyg7sftDXqBASsagKJqvVRKYodCT"
        public = "id11qFJ7fe26N29hrY3f1gUQC7UYArUg2GEy1rpPp2ExbnJdSj3mP"
        assert not IDPrivateKey.is_valid(private)
        assert not IDPublicKey.is_valid(public)

        # Bad base58
        private = "sk11pz4AG9XgB1eNVkbpp+++sgyg7sftDXqBASsagKJqvVRKYodCU"
        public = "id11qFJ7fe26N29hrY3f1g0007UYArUg2GEy1rpPp2ExbnJdSj3mN"
        assert not IDPrivateKey.is_valid(private)
        assert not IDPublicKey.is_valid(public)

    def test_key_imports_and_exports(self):
        private_bytes = b"\x00" * 32
        private_string = "sk11pz4AG9XgB1eNVkbppYAWsgyg7sftDXqBASsagKJqvVRKYodCU"
        public_string = "id12HQxrj9A4ESYVWqKDx7UC1gJfXpUJDVWt6wHem4fjyNyUKVUx2"

        private_from_bytes = IDPrivateKey(seed_bytes=private_bytes)
        private_from_string = IDPrivateKey(key_string=private_string)
        assert private_from_bytes.key_bytes == private_bytes
        assert private_from_string.key_bytes == private_bytes
        assert private_from_bytes.to_string(1) == private_string
        assert private_from_string.to_string(1) == private_string

        public_from_private = private_from_string.get_public_key()
        public_from_string = IDPublicKey(key_string=public_string)
        assert public_from_private.key_bytes == public_from_string.key_bytes
        assert public_from_private.to_string(1) == public_string
        assert public_from_string.to_string(1) == public_string

    def test_sign_message(self):
        message = b"test message"
        signature = (
            b'h\xc4\xcc,\xb0x\xe1\x80/C\xf5\xd2\xf7A\xc9B"\x9f\xd9 \xaf\xe0\x0e\x0c\x1f'
            b"\xe7S\xa0\xd6z\xfaD\xfa\xcb!\x8f\xb8\r\xf7\x8c\xb9\x19z\x19\xfd\xc3Sf\xf0"
            b"\xff\x1e\x15l\xf9M\xb8$H\t\xc61\x0cD\x08"
        )
        private_string = "sk11pz4AG9XgB1eNVkbppYAWsgyg7sftDXqBASsagKJqvVRKYodCU"
        private_key = IDPrivateKey(key_string=private_string)

        assert private_key.sign(message) == signature

    def test_verify_message(self):
        message = b"test message"
        signature = (
            b'h\xc4\xcc,\xb0x\xe1\x80/C\xf5\xd2\xf7A\xc9B"\x9f\xd9 \xaf\xe0\x0e\x0c\x1f'
            b"\xe7S\xa0\xd6z\xfaD\xfa\xcb!\x8f\xb8\r\xf7\x8c\xb9\x19z\x19\xfd\xc3Sf\xf0"
            b"\xff\x1e\x15l\xf9M\xb8$H\t\xc61\x0cD\x08"
        )
        public_string = "id12HQxrj9A4ESYVWqKDx7UC1gJfXpUJDVWt6wHem4fjyNyUKVUx2"
        public_key = IDPublicKey(key_string=public_string)

        assert public_key.verify(signature, message)


if __name__ == "__main__":
    unittest.main()
