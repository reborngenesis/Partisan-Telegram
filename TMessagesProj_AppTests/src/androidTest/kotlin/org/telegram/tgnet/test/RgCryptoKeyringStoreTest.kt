package org.telegram.tgnet.test

import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoStorageTestFixture
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.telegram.messenger.partisan.rgcrypto.RgCrypto
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeyCard
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys
import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoKeyringStore
import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoSignatureState
import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoTrustState
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
class RgCryptoKeyringStoreTest {

    private lateinit var store: RgCryptoKeyringStore
    private lateinit var fixture: RgCryptoStorageTestFixture
    private val peerId = "rgcrypto-test-peer"

    @Before
    fun setUp() {
        RgCrypto.initialize()
        fixture = RgCryptoStorageTestFixture()
        store = fixture.store
    }

    @After
    fun tearDown() {
        if (::fixture.isInitialized) fixture.close()
    }

    @Test
    fun importedTrustRevocationAndInvalidSignatureFollowContract() {
        val signing = RgCryptoKeys.generateSigningKeyset()
        val encryption = RgCryptoKeys.generateHpkeKeyset()
        val card = RgCryptoKeyCard.create(signing, encryption, " device-under-test ")
        val json = card.toJson()

        val imported = store.importKeyCard(peerId, json, RgCryptoTrustState.UNTRUSTED, false)
        assertEquals(RgCryptoTrustState.UNTRUSTED, imported.entry.trustState)
        assertEquals(RgCryptoSignatureState.VALID, imported.entry.signatureValid)
        assertTrue(store.trustedRecipients(peerId).isEmpty())

        store.updateTrustState(peerId, imported.entry.deviceId, imported.entry.signingKeyId,
                imported.entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
        assertEquals(1, store.trustedRecipients(peerId).size)

        store.updateTrustState(peerId, imported.entry.deviceId, imported.entry.signingKeyId,
                imported.entry.encryptionKeyId, RgCryptoTrustState.REVOKED)
        assertTrue(store.trustedRecipients(peerId).isEmpty())

        val restored = store.getByKeyIds(peerId, imported.entry.deviceId,
                imported.entry.signingKeyId, imported.entry.encryptionKeyId)
        assertEquals(RgCryptoTrustState.REVOKED, restored.trustState)
        store.updateTrustState(peerId, restored.deviceId, restored.signingKeyId,
                restored.encryptionKeyId, RgCryptoTrustState.UNTRUSTED)
        assertEquals(RgCryptoTrustState.UNTRUSTED, store.getByKeyIds(peerId,
                restored.deviceId, restored.signingKeyId, restored.encryptionKeyId).trustState)
        assertTrue(store.trustedRecipients(peerId).isEmpty())

        val invalidCard = RgCryptoKeyCard.fromJson(json)
        invalidCard.signature = if (invalidCard.signature[0] == 'A') {
            "B" + invalidCard.signature.substring(1)
        } else {
            "A" + invalidCard.signature.substring(1)
        }
        val invalid = store.importKeyCard(peerId, invalidCard.toJson(), RgCryptoTrustState.TRUSTED, false)
        assertEquals(RgCryptoSignatureState.INVALID, invalid.entry.signatureValid)
        assertEquals(RgCryptoTrustState.UNTRUSTED, invalid.entry.trustState)
        assertTrue(store.trustedRecipients(peerId).isEmpty())
        assertFailsWith<IllegalStateException> {
            store.updateTrustState(peerId, invalid.entry.deviceId, invalid.entry.signingKeyId,
                    invalid.entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
        }
        assertTrue(store.trustedRecipients(peerId).isEmpty())
    }

    @Test
    fun trustRequestedDuringImportStillRequiresExplicitPromotion() {
        val card = RgCryptoKeyCard.create(RgCryptoKeys.generateSigningKeyset(),
                RgCryptoKeys.generateHpkeKeyset(), "device")
        val entry = store.importKeyCard(peerId, card.toJson(), RgCryptoTrustState.TRUSTED, false).entry
        assertEquals(RgCryptoTrustState.UNTRUSTED, entry.trustState)
        assertTrue(store.trustedRecipients(peerId).isEmpty())
        store.updateTrustState(peerId, entry.deviceId, entry.signingKeyId,
                entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
        assertEquals(1, store.trustedRecipients(peerId).size)
        store.deleteByKeyIds(peerId, entry.deviceId, entry.signingKeyId, entry.encryptionKeyId)
        assertFailsWith<IllegalStateException> {
            store.updateTrustState(peerId, entry.deviceId, entry.signingKeyId,
                    entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
        }
    }
}
