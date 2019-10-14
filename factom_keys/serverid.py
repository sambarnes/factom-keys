import ed25519
from bitcoin import base58
from hashlib import sha256

PREFIX_LENGTH = 3
CHECKSUM_LENGTH = 4
BODY_LENGTH = 35
TOTAL_LENGTH = 39


def generate_id_key_set():
    """
    Generate a set of Factom Server Identity keypairs, sk1-sk4 and id1-id4.
    :return: a list of tuples containing a random id key pair in string format: [(sk1..., id1...), (sk2..., id2...)]
    """
    pairs = []

    for i in range(1, 5):
        signer, verifier = ed25519.create_keypair()
        k = ServerIDPrivateKey(signer.to_seed())
        p = ServerIDPublicKey(verifier.to_bytes())
        k.key_level = i
        p.key_level = i
        pairs.append((k.to_string(), p.to_string()))

    return pairs


def generate_key_pair(key_level: int):
    """
    Generate a Factom ServerID keypair at the specified level: 1-4 for (sk1, id1) - (sk4, id4).

    :param key_level: the key_level as an integer, 1-4
    :return: a tuple containing a random id key pair: (ServerIDPrivateKey, ServerIDIPublicKey)
    """
    signer, verifier = ed25519.create_keypair()
    k = ServerIDPrivateKey(signer.to_seed())
    k.key_level = key_level
    p = ServerIDPublicKey(verifier.to_bytes())
    p.key_level = key_level
    return (k, p)


def _to_base58_string(prefixed_key: bytes):
    """
    Convert prefixed_key bytes into sk1/id strings with a checksum.

    :param prefixed_key: the sk1 private key or id public key prefixed with the appropriate bytes
    :return: a sk1 private key string or id public key string
    """
    prefix = prefixed_key[:PREFIX_LENGTH]
    if not (
        prefix in ServerIDPublicKey.PREFIXES or prefix in ServerIDPrivateKey.PREFIXES
    ):
        raise InvalidPrefixError
    temp_hash = sha256(prefixed_key[:BODY_LENGTH]).digest()
    checksum = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]
    return base58.encode(prefixed_key + checksum)


class BadKeyStringError(ValueError):
    pass


class BadKeyBytesError(ValueError):
    pass


class InvalidKeyLevelError(ValueError):
    pass


class InvalidPrefixError(ValueError):
    pass


class InvalidParamsError(ValueError):
    pass


class ServerIDPrivateKey:

    # Prefixes for sk1 - sk4.
    PREFIXES = [b"\x4d\xb6\xc9", b"\x4d\xb6\xe7", b"\x4d\xb7\x05", b"\x4d\xb7\x23"]

    def __init__(self, seed_bytes=None, key_string=None):
        # Check that we only get one of the two params
        if not ((seed_bytes and not key_string) or (
            not seed_bytes and key_string
        )):
            raise InvalidParamsError("Only provide one of seed bytes or key_string, not both.")
        # Default to lowest key level.
        self.key_level = 4

        if key_string:
            if not ServerIDPrivateKey.is_valid(key_string):
                raise BadKeyStringError

            # Get level from third character
            self.key_level = int(key_string[2])

            decoded = base58.decode(key_string)
            seed_bytes = decoded[PREFIX_LENGTH:BODY_LENGTH]

        if not isinstance(seed_bytes, bytes) and len(seed_bytes) == 32:
            raise BadKeyBytesError

        self.__signer = ed25519.SigningKey(seed_bytes)

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw private key
        """
        return self.__signer.to_seed()

    @property
    def key_level(self):
        """
        :return: the current key_level integer value.
        """
        return self._key_level

    @key_level.setter
    def key_level(self, key_level: int):
        """
        Validate key_level and set property to value.

        :param key_level: desired key level as an integer: 1-4
        """
        # Key number must be 1-4 for sk1-sk4
        if not 0 < key_level < 5:
            raise InvalidKeyLevelError
        self._key_level = key_level

    def to_string(self):
        """
        :return: the ServerID private key as a human-readable string in skx format
        """
        secret_body = ServerIDPrivateKey.PREFIXES[self.key_level - 1] + self.key_bytes
        return _to_base58_string(secret_body)

    def get_public_key(self):
        """
        Derive and return the corresponding ServerIDPublicKey

        :return: the ServerIDPublicKey corresponding to this ServerIDPrivateKey
        """
        public_bytes = self.__signer.get_verifying_key().to_bytes()
        public_key = ServerIDPublicKey(public_bytes)

        # Set the public key level to match the private key's level.
        public_key.key_level = self.key_level
        return public_key

    def sign(self, message):
        """
        :param message: the bytes to sign
        :return: the 64 byte signature of the message
        """
        return self.__signer.sign(message)

    @classmethod
    def is_valid(cls, key_string: str):
        """
        :param key_string: the ServerID private key string to be checked
        :return: `True` if `key_string` is a valid ServerID private key string; `False` otherwise
        """
        if not isinstance(key_string, str):
            return False

        try:
            decoded = base58.decode(key_string)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] not in ServerIDPrivateKey.PREFIXES:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed


class ServerIDPublicKey:

    # Prefixes for id1 - id4
    PREFIXES = [b"\x3f\xbe\xba", b"\x3f\xbe\xd8", b"\x3f\xbe\xf6", b"\x3f\xbf\x14"]

    def __init__(self, key_bytes=None, key_string=None):
        # Check that we only get one of the two params
        if not ((key_bytes and not key_string) or (
            not key_bytes and key_string
        )):
            raise InvalidParamsError("Only provide one of seed bytes or key_string, not both.")
        # Set default to lowest key level.
        self.key_level = 4

        if key_string:
            if not ServerIDPublicKey.is_valid(key_string):
                raise BadKeyStringError

            self.key_level = int(key_string[2])

            decoded = base58.decode(key_string)
            key_bytes = decoded[PREFIX_LENGTH:BODY_LENGTH]

        if not isinstance(key_bytes, bytes) and len(key_bytes) == 32:
            raise BadKeyBytesError
        self.__verifier = ed25519.VerifyingKey(key_bytes)

    @property
    def key_bytes(self):
        """
        :return: the 32 byte raw public key
        """
        return self.__verifier.to_bytes()

    @property
    def key_level(self):
        """
        :return: the current key_level integer value.
        """
        return self._key_level

    @key_level.setter
    def key_level(self, key_level: int):
        """
        Validate key_level and set property to value.

        :param key_level: desired key level as an integer: 1-4
        """
        # Key number must be 1-4 for sk1-sk4
        if not 0 < key_level < 5:
            raise InvalidKeyLevelError

        self._key_level = key_level

    def to_string(self):
        """
        :return: the ServerID public key as a human-readable string in idx format
        """
        public_body = ServerIDPublicKey.PREFIXES[self.key_level - 1] + self.key_bytes
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
        :param pub_key: the ServerID public key to be checked
        :return: `True` if `pub_key` is a valid ServerID public key in string format; `False` otherwise
        """
        if not isinstance(pub_key, str):
            return False

        try:
            decoded = base58.decode(pub_key)
        except base58.InvalidBase58Error:
            return False

        if len(decoded) != TOTAL_LENGTH or decoded[:PREFIX_LENGTH] not in ServerIDPublicKey.PREFIXES:
            return False

        checksum_claimed = decoded[BODY_LENGTH:]
        temp_hash = sha256(decoded[:BODY_LENGTH]).digest()
        checksum_actual = sha256(temp_hash).digest()[:CHECKSUM_LENGTH]

        return checksum_actual == checksum_claimed
