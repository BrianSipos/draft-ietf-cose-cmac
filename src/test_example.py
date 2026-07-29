import logging
from typing import cast
import unittest

from cbor_diag import cbor2diag
from pycose import headers
from pycose.algorithms import (
    AESCMAC128_96,
    AESCMAC128_128,
    AESCMAC256_96,
    AESCMAC256_128,
    DirectHKDFSHA512,
)
from pycose.exceptions import CoseException
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import CoseMessage, Mac0Message, MacMessage
from pycose.messages.recipient import DirectEncryption

LOGGER = logging.getLogger(__name__)


class TestExample(unittest.TestCase):
    def test_CMAC128(self):
        for alg in {AESCMAC128_96, AESCMAC128_128}:
            with self.subTest(str(alg)):
                LOGGER.info("Using alg %s", alg.fullname)
                # Augmented from RFC 9052 example
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
                msg_back = cast(Mac0Message, msg_back)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()

    def test_CMAC256(self):
        for alg in {AESCMAC256_96, AESCMAC256_128}:
            with self.subTest(str(alg)):
                LOGGER.info("Using alg %s", alg.fullname)
                # Augmented from RFC 9052 example
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
                msg_back = cast(Mac0Message, msg_back)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()

    def test_CMAC256_KDF(self):
        kdk = SymmetricKey(
            k=bytes.fromhex(
                "5e1047c9b428ee26d2c1059737301756effbeec673f283cff992f132d6a3cb8a"
            ),
            optional_params={
                keyparam.KpKid: b"ExampleA.2",
                keyparam.KpAlg: DirectHKDFSHA512,
                keyparam.KpKeyOps: [keyops.DeriveKeyOp],
            },
        )
        LOGGER.info("KDK: %s", cbor2diag(kdk.encode()))

        msg_obj = MacMessage(
            phdr={
                headers.Algorithm: AESCMAC256_128,
            },
            payload=b"This is the content.",
            recipients=[
                DirectEncryption(
                    phdr={
                        headers.Algorithm: kdk.alg,
                    },
                    uhdr={
                        headers.KID: kdk.kid,
                        headers.Salt: bytes.fromhex("673b4e76"),
                    },
                )
            ],
            # Non-encoded parameters
            external_aad=b"",
        )
        self.assertIsInstance(msg_obj.recipients, list)
        msg_obj.recipients[0].key = kdk

        # COSE internal structure
        cose_struct_enc = msg_obj._mac_structure
        LOGGER.info("COSE Structure: %s", cbor2diag(cose_struct_enc))
        LOGGER.info("Encoded: %s", cose_struct_enc.hex())

        # Encoded message
        message_enc = msg_obj.encode(tag=True)
        LOGGER.info("Message: %s", cbor2diag(message_enc))
        LOGGER.info("Encoded: %s", message_enc.hex())

        kdf_context_enc = (
            msg_obj.recipients[0]
            .get_kdf_context(msg_obj.get_attr(headers.Algorithm))
            .encode()
        )
        LOGGER.info("KDF Context: %s", cbor2diag(kdf_context_enc))
        LOGGER.info("Encoded: %s", kdf_context_enc.hex())
        LOGGER.info("Content key: %s", cbor2diag(msg_obj.key.encode()))

        # Verify from endoded form
        msg_back = CoseMessage.decode(message_enc)
        self.assertIsInstance(msg_back, MacMessage)
        msg_back = cast(MacMessage, msg_back)
        self.assertEqual(1, len(msg_back.recipients))
        recip = msg_back.recipients[0]
        with self.assertRaises(AttributeError):
            msg_back.verify_tag(recip)
        recip.key = kdk
        msg_back.verify_tag(recip)
