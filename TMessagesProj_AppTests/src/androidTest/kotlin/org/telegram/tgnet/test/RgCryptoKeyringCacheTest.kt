package org.telegram.tgnet.test

import android.os.Looper
import org.junit.Test
import org.telegram.messenger.partisan.rgcrypto.RgCrypto
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeyCard
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys
import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoStorageTestFixture
import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoTrustState
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RgCryptoKeyringCacheTest {
    @Test
    fun refreshRemovesDeletedKeysAndInvalidatesRecipientsOnFailure() {
        RgCrypto.initialize()
        RgCryptoStorageTestFixture().use { fixture ->
            val peer = "cache-test-peer"
            val peers = listOf(peer)
            val card = RgCryptoKeyCard.create(RgCryptoKeys.generateSigningKeyset(),
                    RgCryptoKeys.generateHpkeKeyset(), "device")
            val entry = fixture.store.importKeyCard(peer, card.toJson(), RgCryptoTrustState.UNTRUSTED, false).entry

            fun refresh(expectSuccess: Boolean) {
                val done = CountDownLatch(1)
                val succeeded = AtomicBoolean(false)
                val failed = AtomicBoolean(false)
                val onUiThread = AtomicBoolean(false)
                fixture.cache.refreshForPeers(peers, {
                    succeeded.set(true)
                    onUiThread.set(Looper.myLooper() == Looper.getMainLooper())
                    done.countDown()
                }, {
                    failed.set(true)
                    onUiThread.set(Looper.myLooper() == Looper.getMainLooper())
                    done.countDown()
                })
                assertTrue(done.await(10, TimeUnit.SECONDS), "Refresh callback timed out")
                assertEquals(expectSuccess, succeeded.get())
                assertEquals(!expectSuccess, failed.get())
                assertTrue(onUiThread.get())
            }

            refresh(true)
            assertTrue(fixture.cache.getRecipientsForPeers(peers).isEmpty())
            fixture.store.updateTrustState(peer, entry.deviceId, entry.signingKeyId,
                    entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
            refresh(true)
            assertEquals(1, fixture.cache.getRecipientsForPeers(peers).size)

            fixture.store.deleteByKeyIds(peer, entry.deviceId, entry.signingKeyId, entry.encryptionKeyId)
            refresh(true)
            assertTrue(fixture.cache.getRecipientsForPeers(peers).isEmpty())
            assertNull(fixture.cache.getSigningKeyset(peer, entry.signingKid))
            assertFalse(fixture.cache.hasAnySigningKeys(peer))
            assertEquals(RgCryptoTrustState.UNKNOWN, fixture.cache.getTrustState(peer, entry.signingKid, entry.encryptionKid))

            fixture.store.importKeyCard(peer, card.toJson(), RgCryptoTrustState.UNTRUSTED, false)
            fixture.store.updateTrustState(peer, entry.deviceId, entry.signingKeyId,
                    entry.encryptionKeyId, RgCryptoTrustState.TRUSTED)
            refresh(true)
            assertEquals(1, fixture.cache.getRecipientsForPeers(peers).size)
            fixture.store.updateTrustState(peer, entry.deviceId, entry.signingKeyId,
                    entry.encryptionKeyId, RgCryptoTrustState.REVOKED)
            fixture.failRefresh = true
            refresh(false)
            assertTrue(fixture.cache.getRecipientsForPeers(peers).isEmpty())
            assertNull(fixture.cache.getSigningKeyset(peer, entry.signingKid))
            assertEquals(RgCryptoTrustState.UNKNOWN, fixture.cache.getTrustState(peer, entry.signingKid, entry.encryptionKid))
        }
    }
}
