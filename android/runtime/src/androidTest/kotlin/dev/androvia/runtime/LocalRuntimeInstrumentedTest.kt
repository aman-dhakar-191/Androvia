package dev.androvia.runtime

import android.content.Context
import android.os.Build
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import dev.androvia.authentication.AndroidKeystoreDeviceKeys
import dev.androvia.capabilities.DeviceInfoCapability
import dev.androvia.core.CapabilityRegistry
import dev.androvia.core.Envelope
import dev.androvia.core.MessageType
import java.time.Clock
import java.util.UUID
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** End-to-end through the real Keystore, real Room (in memory) and the real dispatcher, with no mocks. */
class LocalRuntimeInstrumentedTest {
    private lateinit var db: AndroviaDatabase
    private lateinit var keys: AndroidKeystoreDeviceKeys
    private lateinit var runtime: LocalRuntime

    @Before fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AndroviaDatabase::class.java).build()
        keys = AndroidKeystoreDeviceKeys("androvia.test." + UUID.randomUUID())
        runtime = LocalRuntime(
            keys,
            CapabilityRegistry(listOf(DeviceInfoCapability(AndroidDeviceInfoSource))),
            roomPolicy(db.capabilityConfigDao()),
            Clock.systemUTC(),
        )
    }

    @After fun tearDown() {
        db.close()
        keys.deleteKey()
    }

    private fun code(e: Envelope) = e.payload["code"]?.jsonPrimitive?.content

    @Test fun deniedByDefaultThenAllowedWhenEnabledThenDeniedAgain() = runBlocking {
        val dao = db.capabilityConfigDao()

        val denied = runtime.dispatch(runtime.buildLocalCommand("device.info"))
        assertEquals(MessageType.ERROR, denied.type)
        assertEquals("permission_denied", code(denied))

        dao.upsert(CapabilityConfigEntity("device.info", true))
        val ok = runtime.dispatch(runtime.buildLocalCommand("device.info"))
        assertEquals(MessageType.RESULT, ok.type)
        val data = ok.payload["data"] as kotlinx.serialization.json.JsonObject
        assertEquals(Build.VERSION.SDK_INT.toString(), data["sdk_int"]!!.jsonPrimitive.content)

        dao.upsert(CapabilityConfigEntity("device.info", false))
        assertEquals("permission_denied", code(runtime.dispatch(runtime.buildLocalCommand("device.info"))))
    }

    @Test fun unknownCapabilityAndForeignDeviceAreRejected() = runBlocking {
        db.capabilityConfigDao().upsert(CapabilityConfigEntity("device.info", true))
        assertEquals("unknown_capability", code(runtime.dispatch(runtime.buildLocalCommand("shell.exec"))))

        val foreign = runtime.buildLocalCommand("device.info").replace(runtime.identity().deviceId, "f".repeat(64))
        assertEquals("permission_denied", code(runtime.dispatch(foreign)))
    }

    @Test fun replayedCommandIsRejected() = runBlocking {
        db.capabilityConfigDao().upsert(CapabilityConfigEntity("device.info", true))
        val cmd = runtime.buildLocalCommand("device.info")
        assertEquals(MessageType.RESULT, runtime.dispatch(cmd).type)
        assertEquals("replayed", code(runtime.dispatch(cmd)))
    }

    @Test fun runtimeStatePersists() = runBlocking {
        val store = RuntimeStateStore(db.runtimeStateDao(), Clock.systemUTC())
        assertFalse(store.serviceRunning.first())
        store.setServiceRunning(true)
        assertTrue(store.serviceRunning.first())
        store.setServiceRunning(false)
        assertFalse(store.serviceRunning.first())
    }
}
