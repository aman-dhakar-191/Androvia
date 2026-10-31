package dev.androvia.core

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BackoffTest {
    @Test fun `stays within bounds, grows, and never reaches zero`() {
        val b = ExponentialBackoff(Duration.ofSeconds(1), Duration.ofSeconds(60), Random(1))
        repeat(200) { attempt ->
            val d = b.delayFor(attempt % 80)
            assertTrue(d >= Duration.ofMillis(500), "too small: $d")
            assertTrue(d <= Duration.ofSeconds(60), "too large: $d")
        }
        assertTrue(b.delayFor(0) <= Duration.ofSeconds(1))
        assertTrue(b.delayFor(3) >= Duration.ofSeconds(4)) // ceiling 8s, floor half
    }

    @Test fun `huge or negative attempts do not overflow`() {
        val b = ExponentialBackoff()
        assertTrue(b.delayFor(Int.MAX_VALUE) <= Duration.ofSeconds(60))
        assertTrue(b.delayFor(-5) <= Duration.ofSeconds(1))
    }

    @Test fun `invalid bounds are rejected`() {
        assertFailsWith<IllegalArgumentException> { ExponentialBackoff(Duration.ofSeconds(10), Duration.ofSeconds(1)) }
        assertFailsWith<IllegalArgumentException> { ExponentialBackoff(Duration.ZERO) }
    }
}

class ReplayGuardTest {
    private class MutableClock(var now: Instant) : Clock() {
        override fun getZone() = ZoneOffset.UTC
        override fun withZone(zone: java.time.ZoneId?) = this
        override fun instant() = now
    }

    @Test fun `expired entries are evicted so the table does not stay full`() {
        val clock = MutableClock(Instant.parse("2026-10-31T12:00:00Z"))
        val g = ReplayGuard(clock, maxEntries = 4)
        repeat(4) { assertEquals(ReplayGuard.Result.ACCEPTED, g.checkAndRecord("id$it", clock.now.plusSeconds(10))) }
        assertEquals(ReplayGuard.Result.FULL, g.checkAndRecord("x", clock.now.plusSeconds(10)))
        clock.now = clock.now.plusSeconds(11)
        assertEquals(ReplayGuard.Result.ACCEPTED, g.checkAndRecord("x", clock.now.plusSeconds(10)))
    }

    @Test fun `duplicate within window is replayed`() {
        val clock = MutableClock(Instant.parse("2026-10-31T12:00:00Z"))
        val g = ReplayGuard(clock)
        assertEquals(ReplayGuard.Result.ACCEPTED, g.checkAndRecord("a", clock.now.plusSeconds(10)))
        assertEquals(ReplayGuard.Result.REPLAYED, g.checkAndRecord("a", clock.now.plusSeconds(10)))
    }
}

class DeviceIdAndStatusTest {
    @Test fun `device id is sha256 hex of the key`() {
        // SHA-256("abc")
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            DeviceId.fromPublicKeyDer("abc".toByteArray()),
        )
    }

    @Test fun `status resolution`() {
        val r = RuntimeStatusResolver::resolve
        assertEquals(RuntimeStatus.STOPPED, r(false, true, RelayState.CONNECTED))
        assertEquals(RuntimeStatus.PERMISSION_LIMITED, r(true, false, RelayState.CONNECTED))
        assertEquals(RuntimeStatus.OFFLINE, r(true, true, RelayState.NOT_CONFIGURED))
        assertEquals(RuntimeStatus.RECONNECTING, r(true, true, RelayState.RECONNECTING))
        assertEquals(RuntimeStatus.CONNECTED, r(true, true, RelayState.CONNECTED))
    }
}

class RegistryAndSchemaTest {
    private fun cap(id: String, scopes: Set<String> = setOf("s:r")) = object : Capability {
        override val descriptor = CapabilityDescriptor(
            id = id, version = 1, description = "", scopes = scopes, sensitivity = Sensitivity.LOW, outputDescription = "",
        )
        override fun availability() = Availability.Available
        override suspend fun execute(args: JsonObject) = CapabilityResult.Ok(JsonObject(emptyMap()))
    }

    @Test fun `duplicate ids are rejected`() {
        assertFailsWith<IllegalArgumentException> { CapabilityRegistry(listOf(cap("a.b"), cap("a.b"))) }
    }

    @Test fun `bad ids and empty scopes are rejected`() {
        assertFailsWith<IllegalArgumentException> { CapabilityRegistry(listOf(cap("NoDots"))) }
        assertFailsWith<IllegalArgumentException> { CapabilityRegistry(listOf(cap("a.b", emptySet()))) }
    }

    @Test fun `lookup only finds registered`() {
        val r = CapabilityRegistry(listOf(cap("a.b")))
        assertTrue(r["a.b"] != null)
        assertEquals(null, r["a.c"])
    }

    @Test fun `schema checks types and lengths`() {
        val s = ObjectSchema(
            mapOf(
                "s" to FieldSpec(FieldType.STRING, maxLength = 3),
                "b" to FieldSpec(FieldType.BOOLEAN),
            ),
        )
        assertEquals(null, s.validate(JsonObject(mapOf("s" to JsonPrimitive("abc"), "b" to JsonPrimitive(true)))))
        assertTrue(s.validate(JsonObject(mapOf("s" to JsonPrimitive("abcd")))) != null)
        assertTrue(s.validate(JsonObject(mapOf("b" to JsonPrimitive("true")))) != null)
        assertTrue(s.validate(JsonObject(mapOf("s" to JsonPrimitive(1)))) != null)
    }
}
