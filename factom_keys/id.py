import ed25519
from bitcoin import base58
from hashlib import sha256

PREFIX_LENGTH = 3
CHECKSUM_LENGTH = 4
BODY_LENGTH = 35
TOTAL_LENGTH = 39


def generate_id_pairs():
    """
    Generate a set of Factom ID keypairs, sk1-sk4 and id1-id4.

    :return: a list of tuples containing a random id key pair: (IDPrivateKey, IDPublicKey)
    """
    pairs = []

    for i in range(0, 4):
        signer, verifier = ed25519.create_keypair()
        pair = (IDPrivateKey(signer.to_seed()), IDPublicKey(verifier.to_bytes()))
        pairs.append(pair)

    return pairs


def _to_base58_string(prefixed_key: bytes):
    """
    Convert prefixed_key bytes into sk1/id strings with a checksum.

    :param prefixed_key: the sk1 private key or id public key prefixed with the appropriate bytes
    :return: a sk1 private key string or id public key string
    """
    prefix = prefixed_key[:PREFIX_LENGTH]
    assert prefix in IDPublicKey.PREFIXES or prefix in IDPrivateKey.PREFIXES, 'Invalid key prefix.'
    temp_hash = sha256(prefixed_key[:BODY_LENGTH]).digest()
    checksum = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]
    return base58.encode(prefixed_key + checksum)


class BadKeyStringError(Exception):
    pass


class IDPrivateKey:

    # Prefixes for sk1 - sk4.
    PREFIXES = [b'\x4d\xb6\xc9', b'\x4d\xb6\xe7',  b'\x4d\xb7\x05', b'\x4d\xb7\x23']

    def __init__(self, seed_bytes=None, key_string=None):
        assert (seed_bytes and not key_string) or (not seed_bytes and key_string), \
            "Only provide one of seed_bytes or key_string, not both"

        if key_string:
            if not IDPrivateKey.is_valid(key_string):
                raise BadKeyStringError
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

    def to_string(self, key_num: int):
        """
        :param key_num: the number of the ID key pair: x in (skx, idx) where 0 < x < 5
        :return: the ID private key as a human-readable string in skx format
        """
        # Key number must be 1-4 for sk1-sk4
        assert 0 < key_num < 5, "Key number must be 1-4 for keys sk1-sk4."

        secret_body = IDPrivateKey.PREFIXES[key_num - 1] + self.key_bytes
        return _to_base58_string(secret_body)

    def get_public_key(self):
        """
        Derive and return the corresponding IDPublicKey

        :return: the IDPublicKey corresponding to this IDPrivateKey
        """
        public_bytes = self.__signer.get_verifying_key().to_bytes()
        return IDPublicKey(public_bytes)

    def sign(self, message):
        """
        :param message: the bytes to sign
        :return: the 64 byte signature of the message
        """
        return self.__signer.sign(message)

    @classmethod
    def is_valid(cls, key_string: str):
        """
        :param key_string: the ID private key string to be checked
        :return: `True` if `key_string` is a valid ID private key string; `False` otherwise
        """
        if not isinstance(key_string, str):
            return False

        try:
            decoded = base58.decode(key_string)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] not in IDPrivateKey.PREFIXES:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed


class IDPublicKey:

    # Prefixes for id1 - id4
    PREFIXES = [b'\x3f\xbe\xba', b'\x3f\xbe\xd8', b'\x3f\xbe\xf6', b'\x3f\xbf\x14']

    def __init__(self, key_bytes=None, key_string=None):
        assert (key_bytes and not key_string) or (not key_bytes and key_string), \
            "Only provide one of key_bytes or key_string, not both"

        if key_string:
            if not IDPublicKey.is_valid(key_string):
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

    def to_string(self, key_num: int):
        """
        :param key_num: the number of the ID key pair: x in (skx, idx) where 0 < x < 5
        :return: the ID public key as a human-readable string in idx format
        """

        # Key number must be 1-4 for id1-id4
        assert 0 < key_num < 5, "Key number must be 1-4 for keys id1-id4"

        public_body = IDPublicKey.PREFIXES[key_num - 1] + self.key_bytes
        return _to_base58_string(public_body)

    def verify(self, signature, message):
        """
        Verifies a given signature and message with this public key.

        :param signature: 64 byte signature of the provided message
        :param message: the message covered by the provided signature
        :return: `True` if this public key successfully verifies the signature for the given
            message, `False` otherwise
        """
        try:
            self.__verifier.verify(signature, message)
            return True
        except ed25519.BadKeyStringError:
            return False

    @classmethod
    def is_valid(cls, pub_key: str):
        """
        :param pub_key: the ID public key to be checked
        :return: `True` if `pub_key` is a valid ID public key in string format; `False` otherwise
        """
        if not isinstance(pub_key, str):
            return False
        try:
            decoded = base58.decode(pub_key)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] not in IDPublicKey.PREFIXES:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed
