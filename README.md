# factom-keys

A small library for using Factom's factoid and entry-credit keys

## Usage
To install this module from pypi, run the following:
```$ pip3 install factom-keys```

### Entry Credit Keys

Example key pair for the private key of all zeros:
- `Es2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG EC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r`

Generating a new random key pair:
```python
>>> import factom_keys.ec as ec
>>> ec_private, ec_public = ec.generate_key_pair()
>>> print(ec_private.to_string(), ec_public.to_string())
Es4M9ydZkdnMiHQp9oFaoGHQGESSeSd2KsZGtdJrWD55zoZUJZ6Z EC2ieEsA8cB4fmNe4v97nNv2pmBJnCZA2eGmG3xidDQ2t9vsEcPu
>>> print(ec_private.key_bytes.hex(), ec_public.key_bytes.hex())
fd2b3f4d7702ebe1a7e611a9095eaa2056e1ac0c47b8c3aad0fce35ce29346a1 7dffa7b87844b1db1bf114952d81f549a743c285ec60c0dc638564680a951ae4

```

Signing a message and then verifying the signature:
```python
message = b'hello'
>>> signature = private_key.sign(message)
>>> signature = ec_private.sign(message)
print(ec_public.verify(signature, message))
True
>>> print(ec_public.verify(signature, b'bad message'))
False
```

Checking if a given address or key string is valid:
```python
>>> ECPrivateKey.is_valid("Es2Rf7iM6PdsqfYCo3D1tnAR65SkLENyWJG1deUzpRMQmbh9F3eG")
True
>>> ECAddress.is_valid("EC2DKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r")
True
>>> ECAddress.is_valid("BADKSYyRcNWf7RS963VFYgMExoHRYLHVeCfQ9PGPmNzwrcmgm2r")
False
```

### Factoid Keys

Example key pair for the private key of all zeros:
- `Fs1KWJrpLdfucvmYwN2nWrwepLn8ercpMbzXshd1g8zyhKXLVLWj FA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MC`

Factoid private keys work exactly like EC private keys. Factoid addresses, on the other hand, are slightly different since they operate as an RCD (redeem condition datastructure). The details can be read [here](https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#redeem-condition-datastructure-rcd), but the main point is that a given factoid address doesn't encode it's public key bytes, but rather a hash of the RCD version concatenated with the public key bytes. This allows for users to keep their public keys hidden until they actually spend from the address (when they "redeem" the coins to be used).

With that in mind, a `FactoidAddress` object will always have a `rcd_hash` attribute that is used in constructing the `FA...` address string. However, it's `key_bytes` attribute will be `None` unless it was explicitly passed in to the constructor or if the object was generated from a `FactoidPrivateKey` object's `get_factoid_address()` function. If only the `rcd_hash` is available, no signatures can be verified using the address, so the `verify(signature, message)` function will always return `False`.
