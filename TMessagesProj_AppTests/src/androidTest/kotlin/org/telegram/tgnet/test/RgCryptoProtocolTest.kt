package org.telegram.tgnet.test

import org.junit.BeforeClass
import org.junit.Test
import org.telegram.messenger.partisan.rgcrypto.RgCrypto
import org.telegram.messenger.partisan.rgcrypto.RgCryptoDecryptResult
import org.telegram.messenger.partisan.rgcrypto.RgCryptoBase64
import org.telegram.messenger.partisan.rgcrypto.RgCryptoEnvelope
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys
import org.telegram.messenger.partisan.rgcrypto.RgCryptoTextCodec
import kotlin.test.assertEquals

class RgCryptoProtocolTest {
    companion object {
        @JvmStatic
        @BeforeClass
        fun initialize() {
            RgCrypto.initialize()
        }
    }

    @Test
    fun textEnvelopeRejectsTamperingAndWrongScope() {
        val senderSigning = RgCryptoKeys.generateSigningKeyset()
        val recipient = RgCryptoKeys.generateHpkeKeyset()
        val recipientPublic = RgCryptoKeys.recipientFromPrivateKeyset(recipient)
        val senderId = "sender-1"
        val scope = "u:100:200"
        val transport = RgCryptoTextCodec.packText(
            "contract message",
            scope,
            senderId,
            senderSigning,
            listOf(recipientPublic)
        )

        val verified = RgCryptoTextCodec.unpackText(
            transport,
            scope,
            recipient,
            { id, kid -> if (id == senderId && kid == RgCryptoKeys.kidFromKeyset(senderSigning.publicKeysetHandle)) senderSigning.publicKeysetHandle else null }
        )
        assertEquals(RgCryptoDecryptResult.Status.OK, verified.status)
        assertEquals(RgCryptoDecryptResult.SignatureState.VERIFIED, verified.signatureState)
        assertEquals("contract message", verified.plaintext)

        val envelope = RgCryptoEnvelope.decodeFromTransport(transport)
        val tamperedCiphertext = RgCryptoBase64.decode(envelope.ciphertext)
        tamperedCiphertext[0] = (tamperedCiphertext[0].toInt() xor 1).toByte()
        envelope.ciphertext = RgCryptoBase64.encode(tamperedCiphertext)
        val badHash = RgCryptoTextCodec.unpackEnvelope(
            envelope,
            scope,
            recipient,
            { _, _ -> senderSigning.publicKeysetHandle }
        )
        assertEquals(RgCryptoDecryptResult.Status.BAD_HASH, badHash.status)

        val signatureEnvelope = RgCryptoEnvelope.decodeFromTransport(transport)
        val signature = RgCryptoBase64.decode(signatureEnvelope.signature)
        signature[0] = (signature[0].toInt() xor 1).toByte()
        signatureEnvelope.signature = RgCryptoBase64.encode(signature)
        val badSignature = RgCryptoTextCodec.unpackEnvelope(
            signatureEnvelope,
            scope,
            recipient,
            { _, _ -> senderSigning.publicKeysetHandle }
        )
        assertEquals(RgCryptoDecryptResult.Status.BAD_SIGNATURE, badSignature.status)

        val wrongScope = RgCryptoTextCodec.unpackText(
            transport,
            "g:999",
            recipient,
            { _, _ -> senderSigning.publicKeysetHandle }
        )
        assertEquals(RgCryptoDecryptResult.Status.PARSE_FAIL, wrongScope.status)

        val differentRecipient = RgCryptoKeys.generateHpkeKeyset()
        val missingRecipient = RgCryptoTextCodec.unpackText(
            transport,
            scope,
            differentRecipient,
            { _, _ -> senderSigning.publicKeysetHandle }
        )
        assertEquals(RgCryptoDecryptResult.Status.NEED_KEY, missingRecipient.status)
    }

}
