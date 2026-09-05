package org.telegram.messenger.partisan.rgcrypto.storage

import androidx.room.Room
import org.telegram.messenger.ApplicationLoader

/** No account singleton or persistent keyring is opened by these tests. */
class RgCryptoStorageTestFixture : AutoCloseable {
    private val database = Room.inMemoryDatabaseBuilder(
        ApplicationLoader.applicationContext, RgCryptoKeyringDatabase::class.java
    ).build()

    val store = RgCryptoKeyringStore(database.keyringDao())

    @Volatile
    var failRefresh = false

    val cache = RgCryptoKeyringCache {
        check(!failRefresh) { "Injected keyring refresh failure" }
        store
    }

    override fun close() {
        database.close()
    }
}
