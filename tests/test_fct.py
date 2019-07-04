import unittest

from factom_keys.fct import FactoidPrivateKey, FactoidAddress, generate_key_pair


class TestFactoidKeys(unittest.TestCase):

    def test_generate_key_pair(self):
        private_key, public_key = generate_key_pair()
        assert isinstance(private_key, FactoidPrivateKey)
        assert isinstance(public_key, FactoidAddress)

    def test_key_string_validity_checkers(self):
        # Valid pair. All zeros private key
        private = 'Fs1KWJrpLdfucvmYwN2nWrwepLn8ercpMbzXshd1g8zyhKXLVLWj'
        public = 'FA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MC'
        assert FactoidPrivateKey.is_valid(private)
        assert FactoidAddress.is_valid(public)

        # Bad prefix
        private = 'Xs1KWJrpLdfucvmYwN2nWrwepLn8ercpMbzXshd1g8zyhKXLVLWj'
        public = 'XA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MC'
        assert not FactoidAddress.is_valid(private)
        assert not FactoidAddress.is_valid(public)

        # Bad body
        private = 'Fs1KWJrpLdfucvmYwN2nWXXXpLn8ercpMbzXshd1g8zyhKXLVLWj'
        public = 'FA1zT4aFpEvcnPqPCigB3fXXX4Q4mTXY22iiuV69DqE1pNhdF2MC'
        assert not FactoidPrivateKey.is_valid(private)
        assert not FactoidAddress.is_valid(public)

        # Bad checksums
        private = 'Fs1KWJrpLdfucvmYwN2nWrwepLn8ercpMbzXshd1g8zyhKXLVLWX'
        public = 'FA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MX'
        assert not FactoidPrivateKey.is_valid(private)
        assert not FactoidAddress.is_valid(public)

    def test_key_imports_and_exports(self):
        private_bytes = b'\0' * 32
        private_string = 'Fs1KWJrpLdfucvmYwN2nWrwepLn8ercpMbzXshd1g8zyhKXLVLWj'
        public_string = 'FA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MC'

        private_from_bytes = FactoidPrivateKey(seed_bytes=private_bytes)
        private_from_string = FactoidPrivateKey(key_string=private_string)
        assert private_from_bytes.key_bytes == private_bytes
        assert private_from_string.key_bytes == private_bytes
        assert private_from_bytes.to_string() == private_string
        assert private_from_string.to_string() == private_string

        public_from_private = private_from_string.get_factoid_address()
        public_from_string = FactoidAddress(address_string=public_string)
        assert public_from_private.key_bytes is not None
        assert public_from_string.key_bytes is None
        assert public_from_private.rcd_hash == public_from_string.rcd_hash
        assert public_from_private.to_string() == public_string
        assert public_from_string.to_string() == public_string


if __name__ == '__main__':
    unittest.main()
