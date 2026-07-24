from abc import ABC, abstractmethod

from cbor_diag import cbor2diag
import logging
from typing import Callable, Optional
import unittest
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm
from cryptography.hazmat.primitives.ciphers.algorithms import AES128, AES256
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import CoseMessage, Mac0Message
from pycose.exceptions import CoseException, CoseInvalidKey


class _CMAC(algorithms.CoseAlgorithm, ABC):
    cipher_cls: Optional[Callable[[bytes], BlockCipherAlgorithm]] = None
    """ Derived class overrides with block cipher constructor """

    @classmethod
    @abstractmethod
    def get_key_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_tag_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    def compute_tag(cls, key: "SymmetricKey", data: bytes) -> bytes:
        if cls.cipher_cls is None:
            raise CoseException
        if len(key.k) != cls.get_key_length():
            raise CoseInvalidKey

        h = CMAC(cls.cipher_cls(key.k))
        h.update(data)
        full_tag = h.finalize()

        return full_tag[: cls.get_tag_length()]

    @classmethod
    def verify_tag(cls, key: "SymmetricKey", tag: bytes, data: bytes) -> bool:
        computed_tag = cls.compute_tag(key, data)

        if tag == computed_tag:
            return True
        else:
            return False


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC128_96(_CMAC):
    identifier = 35
    fullname = "AES_CMAC_128_96"

    cipher_cls = AES128

    @classmethod
    def get_key_length(cls) -> int:
        return 16

    @classmethod
    def get_tag_length(cls) -> int:
        return 12


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC256_96(_CMAC):
    identifier = 36
    fullname = "AES_CMAC_256_96"

    cipher_cls = AES256

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 12


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC128_128(_CMAC):
    identifier = 37
    fullname = "AES_CMAC_128_128"

    cipher_cls = AES128

    @classmethod
    def get_key_length(cls) -> int:
        return 16

    @classmethod
    def get_tag_length(cls) -> int:
        return 16


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC256_128(_CMAC):
    identifier = 38
    fullname = "AES_CMAC_256_128"

    cipher_cls = AES256

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 16


LOGGER = logging.getLogger(__name__)


class TestExample(unittest.TestCase):
    def test_CMAC128(self):
        for alg in {AESCMAC128_96, AESCMAC128_128}:
            with self.subTest(str(alg)):
                LOGGER.info("Using alg %s", alg.fullname)
                # Augmented from RFC 9172 example
                # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-02.json
                key = SymmetricKey(
                    k=bytes.fromhex("849B57219DAE48DE646D07DBB533566E"),
                    optional_params={
                        keyparam.KpKid: b"secret128",
                        keyparam.KpAlg: alg,
                        keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
                    },
                )
                LOGGER.info("Key: %s", cbor2diag(key.encode()))

                msg_obj = Mac0Message(
                    phdr={
                        headers.Algorithm: key.alg,
                    },
                    uhdr={
                        headers.KID: key.kid,
                    },
                    payload=b"This is the content.",
                    # Non-encoded parameters
                    external_aad=b"",
                )
                msg_obj.key = key

                # COSE internal structure
                cose_struct_enc = msg_obj._mac_structure
                LOGGER.info("COSE Structure: %s", cbor2diag(cose_struct_enc))
                LOGGER.info("Encoded: %s", cose_struct_enc.hex())

                # Encoded message
                message_enc = msg_obj.encode(tag=True)
                LOGGER.info("Message: %s", cbor2diag(message_enc))
                LOGGER.info("Encoded: %s", message_enc.hex())

                # Verify from endoded form
                msg_back = CoseMessage.decode(message_enc)
                self.assertIsInstance(msg_back, Mac0Message)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()

    def test_CMAC256(self):
        for alg in {AESCMAC256_96, AESCMAC256_128}:
            with self.subTest(str(alg)):
                LOGGER.info("Using alg %s", alg.fullname)
                # Augmented from RFC 9172 example
                # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-04.json
                key = SymmetricKey(
                    k=bytes.fromhex(
                        "849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188"
                    ),
                    optional_params={
                        keyparam.KpKid: b"secret256",
                        keyparam.KpAlg: alg,
                        keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
                    },
                )
                LOGGER.info("Key: %s", cbor2diag(key.encode()))

                msg_obj = Mac0Message(
                    phdr={
                        headers.Algorithm: key.alg,
                    },
                    uhdr={
                        headers.KID: key.kid,
                    },
                    payload=b"This is the content.",
                    # Non-encoded parameters
                    external_aad=b"",
                )
                msg_obj.key = key

                # COSE internal structure
                cose_struct_enc = msg_obj._mac_structure
                LOGGER.info("COSE Structure: %s", cbor2diag(cose_struct_enc))
                LOGGER.info("Encoded: %s", cose_struct_enc.hex())

                # Encoded message
                message_enc = msg_obj.encode(tag=True)
                LOGGER.info("Message: %s", cbor2diag(message_enc))
                LOGGER.info("Encoded: %s", message_enc.hex())

                # Verify from endoded form
                msg_back = CoseMessage.decode(message_enc)
                self.assertIsInstance(msg_back, Mac0Message)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()
