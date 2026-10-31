package dev.androvia.runtime

import android.content.Context
import androidx.room.Room
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import java.util.UUID
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayConfigInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val dbName = "migration-test-" + UUID.randomUUID() + ".db"

    @After fun tearDown() {
        context.deleteDatabase(dbName)
    }

    @Test fun relayConfigRoundTripsAndStartsEmpty() = runBlocking {
        val db = Room.inMemoryDatabaseBuilder(context, AndroviaDatabase::class.java).build()
        try {
            val dao = db.relayConfigDao()
            assertNull("no relay is configured by default", dao.observe().first())
            dao.upsert(RelayConfigEntity(url = "wss://relay.example.com", enabled = true))
            assertEquals(RelayConfigEntity(1, "wss://relay.example.com", true), dao.observe().first())
            dao.upsert(RelayConfigEntity(url = "wss://other.example.com", enabled = false)) // single row: replaced, not added
            assertEquals(RelayConfigEntity(1, "wss://other.example.com", false), dao.observe().first())
        } finally {
            db.close()
        }
    }

    /** Builds a genuine version-1 database file (the schema shipped in Phase 1), then opens it with the current code. */
    @Test fun upgradingFromVersion1KeepsTheUsersCapabilityChoicesAndAddsRelayConfig() = runBlocking {
        val v1 = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(dbName)
                .callback(object : SupportSQLiteOpenHelper.Callback(1) {
                    override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                        db.execSQL("CREATE TABLE IF NOT EXISTS `runtime_state` (`id` INTEGER NOT NULL, `serviceRunning` INTEGER NOT NULL, `updatedAtEpochMs` INTEGER NOT NULL, PRIMARY KEY(`id`))")
                        db.execSQL("CREATE TABLE IF NOT EXISTS `capability_config` (`capabilityId` TEXT NOT NULL, `enabled` INTEGER NOT NULL, PRIMARY KEY(`capabilityId`))")
                    }

                    override fun onUpgrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
                })
                .build(),
        )
        v1.writableDatabase.apply {
            execSQL("INSERT INTO capability_config VALUES ('device.info', 1)")
            execSQL("INSERT INTO runtime_state VALUES (1, 0, 12345)")
            close()
        }

        val db = Room.databaseBuilder(context, AndroviaDatabase::class.java, dbName)
            .addMigrations(*RuntimeMigrations.ALL)
            .build()
        try {
            assertEquals("the user's choice survived the upgrade", listOf("device.info"), db.capabilityConfigDao().enabledIds())
            assertFalse(db.runtimeStateDao().observe().first()!!.serviceRunning)
            assertNull(db.relayConfigDao().observe().first())
            db.relayConfigDao().upsert(RelayConfigEntity(url = "wss://relay.example.com", enabled = false))
            assertTrue(db.relayConfigDao().observe().first() != null)
        } finally {
            db.close()
        }
    }
}
