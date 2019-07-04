import unittest

from factom_keys.ec import ECPrivateKey, ECAddress, generate_key_pair


class TestECKeys(unittest.TestCase):

    def test_generate_key_pair(self):
        private_key, public_key = generate_key_pair()
        assert isinstance(private_key, ECPrivateKey)
        assert isinstance(public_key, ECAddress)

    def test_key_string_validity_checkers(self):
        # Valid pair. All zeros private key
        private = 'Es2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG'
        public = 'EC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r'
        assert ECPrivateKey.is_valid(private)
        assert ECAddress.is_valid(public)

        # Bad prefix
        private = 'Xs2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG'
        public = 'XC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r'
        assert not ECPrivateKey.is_valid(private)
        assert not ECAddress.is_valid(public)

        # Bad body
        private = 'Es2Rf7iM6PdsqfXXX3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG'
        public = 'EC2DKSYyRcNWf7RXXX3VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r'
        assert not ECPrivateKey.is_valid(private)
        assert not ECAddress.is_valid(public)

        # Bad checksums
        private = 'Es2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eX'
        public = 'EC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2X'
        assert not ECPrivateKey.is_valid(private)
        assert not ECAddress.is_valid(public)

    def test_key_imports_and_exports(self):
        private_bytes = b'\0' * 32
        private_string = 'Es2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG'
        public_string = 'EC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r'

        private_from_bytes = ECPrivateKey(seed_bytes=private_bytes)
        private_from_string = ECPrivateKey(key_string=private_string)
        assert private_from_bytes.key_bytes == private_bytes
        assert private_from_string.key_bytes == private_bytes
        assert private_from_bytes.to_string() == private_string
        assert private_from_string.to_string() == private_string

        public_from_private = private_from_string.get_ec_address()
        public_from_string = ECAddress(key_string=public_string)
        assert public_from_private.key_bytes == public_from_string.key_bytes
        assert public_from_private.to_string() == public_string
        assert public_from_string.to_string() == public_string


if __name__ == '__main__':
    unittest.main()
