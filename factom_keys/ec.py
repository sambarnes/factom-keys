import ed25519
from bitcoin import base58
from hashlib import sha256

PREFIX_LENGTH = 2
CHECKSUM_LENGTH = 4
BODY_LENGTH = 34
TOTAL_LENGTH = 38


def generate_key_pair():
    """
    :return: a tuple containing a random (ECPrivateKey, ECAddress)
    """
    signer, verifier = ed25519.create_keypair()
    return ECPrivateKey(signer.to_seed()), ECAddress(verifier.to_bytes())


def _to_base58_string(prefixed_key: bytes):
    """
    Convert prefixed_key bytes into Es/EC strings with a checksum

    :param prefixed_key: the EC private key or EC address prefixed with the appropriate bytes
    :return: a EC private key string or EC address
    """
    prefix = prefixed_key[:PREFIX_LENGTH]
    assert prefix == ECAddress.PREFIX or prefix == ECPrivateKey.PREFIX, 'Invalid key prefix.'
    temp_hash = sha256(prefixed_key[:BODY_LENGTH]).digest()
    checksum = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]
    return base58.encode(prefixed_key + checksum)


class BadKeyStringError(Exception):
    pass


class ECPrivateKey(object):

    PREFIX = b']\xb6'  # 0x5db6

    def __init__(self, seed_bytes=None, key_string=None):
        assert (seed_bytes and not key_string) or (not seed_bytes and key_string), \
            "Only provide one of seed_bytes or key_string, not both"

        if key_string:
            if not ECPrivateKey.is_valid(key_string):
                raise BadKeyStringError()
            decoded = base58.decode(key_string)
            seed_bytes = decoded[PREFIX_LENGTH:BODY_LENGTH]

        assert isinstance(seed_bytes, bytes)
        assert len(seed_bytes) == 32
        self.__signer = ed25519.SigningKey(seed_bytes)

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw private key
        """
        return self.__signer.to_seed()

    def to_string(self):
        """
        :return: the EC private key as a human-readable string in Es format
        """
        secret_body = ECPrivateKey.PREFIX + self.key_bytes
        return _to_base58_string(secret_body)

    def get_ec_address(self):
        """
        Derive and return the corresponding ECAddress

        :return: the ECAddress corresponding to this ECPrivateKey
        """
        public_bytes = self.__signer.get_verifying_key().to_bytes()
        return ECAddress(public_bytes)

    def sign(self, message):
        """
        :param message: the bytes to sign
        :return: the 64 byte signature of the message
        """
        return self.__signer.sign(message)

    @classmethod
    def is_valid(cls, key_string: str):
        """
        :param key_string: the EC private key string to be checked
        :return: `True` if `address` is a valid EC private key string in Es format, `False` otherwise
        """
        if not isinstance(key_string, str):
            return False
        try:
            decoded = base58.decode(key_string)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] != ECPrivateKey.PREFIX:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed


class ECAddress(object):

    PREFIX = b'Y*'  # 0x592a

    def __init__(self, key_bytes=None, key_string=None):
        assert (key_bytes and not key_string) or (not key_bytes and key_string), \
            "Only provide one of key_bytes or key_string, not both"

        if key_string:
            if not ECAddress.is_valid(key_string):
                raise BadKeyStringError()
            decoded = base58.decode(key_string)
            key_bytes = decoded[PREFIX_LENGTH:BODY_LENGTH]

        assert isinstance(key_bytes, bytes)
        assert len(key_bytes) == 32
        self.__verifier = ed25519.VerifyingKey(key_bytes)

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw public key
        """
        return self.__verifier.to_bytes()

    def to_string(self):
        """
        :return: the EC address as a human-readable string in EC format
        """
        public_body = ECAddress.PREFIX + self.key_bytes
        return _to_base58_string(public_body)

    def verify(self, signature, message):
        """
        Verifies a given signature and message with this public key

        :param signature: 64 byte signature of the provided message
        :param message: the message covered by the provided signature
        :return: `True` if this public key successfully verifies the signature for the given message, `False` otherwise
        """
        try:
            self.__verifier.verify(signature, message)
            return True
        except ed25519.BadSignatureError:
            return False

    @classmethod
    def is_valid(cls, address: str):
        """
        :param address: the EC address string to be checked
        :return: `True` if `address` is a valid EC Address string in EC format, `False` otherwise
        """
        if not isinstance(address, str):
            return False
        try:
            decoded = base58.decode(address)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] != ECAddress.PREFIX:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed
