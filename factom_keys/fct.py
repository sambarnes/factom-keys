import ed25519
from bitcoin import base58
from hashlib import sha256

PREFIX_LENGTH = 2
CHECKSUM_LENGTH = 4
BODY_LENGTH = 34
TOTAL_LENGTH = 38


def generate_key_pair():
    """
    :return: a tuple containing a random (FactoidPrivateKey, FactoidAddress)
    """
    signer, verifier = ed25519.create_keypair()
    return FactoidPrivateKey(signer.to_seed()), FactoidAddress(verifier.to_bytes())


def _to_base58_string(prefixed_key: bytes):
    """
    Convert prefixed_key bytes into Fs/FA strings with a checksum

    :param prefixed_key: the Factoid private key or Factoid address prefixed with the appropriate bytes
    :return: a Factoid private key string or Factoid address
    """
    prefix = prefixed_key[:PREFIX_LENGTH]
    assert prefix == FactoidAddress.PREFIX or prefix == FactoidPrivateKey.PREFIX, 'Invalid key prefix.'
    temp_hash = sha256(prefixed_key[:BODY_LENGTH]).digest()
    checksum = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]
    return base58.encode(prefixed_key + checksum)


class BadKeyStringError(Exception):
    pass


class RCDMismatchError(Exception):
    pass


class FactoidPrivateKey(object):

    PREFIX = b'dx'  # 0x6478

    def __init__(self, seed_bytes=None, key_string=None):
        assert (seed_bytes and not key_string) or (not seed_bytes and key_string), \
            "Only provide one of seed_bytes or key_string, not both"

        if key_string:
            if not FactoidPrivateKey.is_valid(key_string):
                raise BadKeyStringError()
            decoded = base58.decode(key_string)
            seed_bytes = decoded[PREFIX_LENGTH:BODY_LENGTH]

        assert isinstance(seed_bytes, bytes)
        assert len(seed_bytes) == 32
        self._signer = ed25519.SigningKey(seed_bytes)

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw private key
        """
        return self._signer.to_seed()

    def to_string(self):
        """
        :return: the factoid private key as a human-readable string in Fs format
        """
        secret_body = FactoidPrivateKey.PREFIX + self._signer.to_seed()
        return _to_base58_string(secret_body)

    def get_factoid_address(self):
        """
        Derive and return the corresponding FactoidAddress

        :return: the FactoidAddress corresponding to this FactoidPrivateKey
        """
        public_bytes = self._signer.get_verifying_key().to_bytes()
        return FactoidAddress(public_bytes)

    def sign(self, message: bytes):
        """
        :param message: the bytes to sign
        :return: the 64 byte signature of the message
        """
        return self._signer.sign(message)

    @classmethod
    def is_valid(cls, key_string: str):
        """
        :param key_string: the factoid private key string to be checked
        :return: `True` if `address` is a valid Factoid private key string in Fs format, `False` otherwise
        """
        if not isinstance(key_string, str):
            return False
        try:
            decoded = base58.decode(key_string)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] != FactoidPrivateKey.PREFIX:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed


class FactoidAddress(object):

    PREFIX = b'_\xb1'  # 0x5fb1

    def __init__(self, key_bytes=None, address_string=None):
        assert key_bytes or address_string, "Must provide key_bytes, address_string, or both"

        self._verifier = None
        self.rcd_hash = None

        if key_bytes:
            assert isinstance(key_bytes, bytes)
            assert len(key_bytes) == 32
            self._verifier = ed25519.VerifyingKey(key_bytes)
            temp_hash = sha256(b'\x01' + key_bytes).digest()
            self.rcd_hash = sha256(temp_hash).digest()

        if address_string:
            if not FactoidAddress.is_valid(address_string):
                raise BadKeyStringError()
            decoded = base58.decode(address_string)
            rcd_hash = decoded[PREFIX_LENGTH:BODY_LENGTH]
            if self.rcd_hash is None:
                self.rcd_hash = rcd_hash
            elif self.rcd_hash != rcd_hash:
                raise RCDMismatchError

    def _has_public_key(self):
        return self._verifier is not None

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw public key, or `None` if not available
        """
        return self._verifier.to_bytes() if self._has_public_key() else None

    def to_string(self):
        """
        :return: the factoid address as a human-readable string in FA format
        """
        public_body = FactoidAddress.PREFIX + self.rcd_hash
        return _to_base58_string(public_body)

    def verify(self, signature: bytes, message: bytes):
        """
        Verifies a given signature and message with this public key

        :param signature: 64 byte signature of the provided message
        :param message: the message covered by the provided signature
        :return: `True` if this public key successfully verifies the signature for the given message, `False` otherwise
        """
        if not self._has_public_key():
            return False
        try:
            self._verifier.verify(signature, message)
            return True
        except ed25519.BadSignatureError:
            return False

    @classmethod
    def is_valid(cls, address: str):
        """
        :param address: the factoid address string to be checked
        :return: `True` if `address` is a valid Factoid Address string in FA format, `False` otherwise
        """
        if not isinstance(address, str):
            return False
        try:
            decoded = base58.decode(address)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] != FactoidAddress.PREFIX:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed
