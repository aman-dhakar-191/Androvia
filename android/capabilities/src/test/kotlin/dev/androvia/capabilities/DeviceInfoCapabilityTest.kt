package dev.androvia.capabilities

import dev.androvia.core.Availability
import dev.androvia.core.CapabilityResult
import dev.androvia.core.Sensitivity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

class DeviceInfoCapabilityTest {
    private val info = DeviceInfo("Acme", "Phone 1", "16", 36, "2026-10-01", listOf("arm64-v8a"))
    private val cap = DeviceInfoCapability { info }

    @Test fun `declares low sensitivity, a scope and no permissions`() {
        val d = cap.descriptor
        assertEquals("device.info", d.id)
        assertEquals(Sensitivity.LOW, d.sensitivity)
        assertTrue(d.scopes.isNotEmpty())
        assertTrue(d.requiredAndroidPermissions.isEmpty())
        assertEquals(Availability.Available, cap.availability())
    }

    @Test fun `returns build info`() = runTest {
        val r = cap.execute(JsonObject(emptyMap()))
        assertIs<CapabilityResult.Ok>(r)
        assertEquals("Acme", r.data["manufacturer"]!!.jsonPrimitive.content)
        assertEquals("36", r.data["sdk_int"]!!.jsonPrimitive.content)
    }

    @Test fun `omits security patch when unknown`() = runTest {
        val r = DeviceInfoCapability { info.copy(securityPatch = null) }.execute(JsonObject(emptyMap()))
        assertIs<CapabilityResult.Ok>(r)
        assertTrue("security_patch" !in r.data)
    }

    @Test fun `schema accepts no arguments`() {
        assertEquals(null, cap.descriptor.argsSchema.validate(JsonObject(emptyMap())))
    }
}
