package dev.androvia.core

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

private val SELF = "a".repeat(64)
private val OTHER = "b".repeat(64)
private val NOW: Instant = Instant.parse("2026-10-31T12:00:00Z")

private class FakeCapability(
    id: String = "test.echo",
    version: Int = 1,
    sensitivity: Sensitivity = Sensitivity.LOW,
    schema: ObjectSchema = ObjectSchema(),
    timeout: Duration = Duration.ofSeconds(5),
    var avail: Availability = Availability.Available,
    var body: suspend (JsonObject) -> CapabilityResult = { CapabilityResult.Ok(buildJsonObject { put("x", 1) }) },
) : Capability {
    var calls = 0
    override val descriptor = CapabilityDescriptor(
        id = id, version = version, description = "t", scopes = setOf("test:read"), sensitivity = sensitivity,
        argsSchema = schema, outputDescription = "x", timeout = timeout,
    )
    override fun availability() = avail
    override suspend fun execute(args: JsonObject): CapabilityResult {
        calls++
        return body(args)
    }
}

class DispatcherTest {
    private val clock = Clock.fixed(NOW, ZoneOffset.UTC)
    private val cap = FakeCapability()

    private fun dispatcher(
        c: Capability = cap,
        policy: LocalPolicy = LocalPolicy { PolicyDecision.Allow },
        guard: ReplayGuard = ReplayGuard(clock),
    ) = CommandDispatcher(CapabilityRegistry(listOf(c)), policy, guard, clock) { SELF }

    private fun command(
        id: String = UUID.randomUUID().toString(),
        device: String = SELF,
        ts: Instant = NOW,
        exp: Instant = NOW.plusSeconds(30),
        capability: String = "test.echo",
        version: Int = 1,
        args: String = "{}",
        extra: String = "",
    ) = """{"v":1,"type":"command","id":"$id","device":"$device","ts":"$ts","exp":"$exp",
        "payload":{"capability":"$capability","version":$version,"args":$args$extra}}"""

    private fun code(e: Envelope): String? =
        if (e.type == MessageType.ERROR) e.payload["code"]!!.jsonPrimitive.content else null

    @Test fun `valid command runs and is correlated`() = runTest {
        val id = UUID.randomUUID().toString()
        val r = dispatcher().dispatch(command(id = id))
        assertEquals(MessageType.RESULT, r.type)
        assertEquals(id, r.corr)
        assertEquals("ok", r.payload["status"]!!.jsonPrimitive.content)
        assertEquals(1, cap.calls)
    }

    @Test fun `response is valid JSON envelope`() = runTest {
        val r = dispatcher().dispatch(command())
        Json.parseToJsonElement(r.toJson()).jsonObject
        assertEquals(SELF, r.device)
    }

    // ---- malformed input ----
    @Test fun `non-json is malformed`() = runTest { assertEquals("malformed", code(dispatcher().dispatch("nope"))) }
    @Test fun `json array is malformed`() = runTest { assertEquals("malformed", code(dispatcher().dispatch("[]"))) }
    @Test fun `unknown top-level field is rejected`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command().replaceFirst("{", """{"evil":1,"""))))
    }
    @Test fun `unknown payload field is rejected`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(extra = ""","admin":true"""))))
        assertEquals(0, cap.calls)
    }
    @Test fun `non-uuid id is malformed`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(id = "not-a-uuid"))))
    }
    @Test fun `oversized message is too_large`() = runTest {
        val big = command(args = """{"a":"${"x".repeat(70_000)}"}""")
        assertEquals("too_large", code(dispatcher().dispatch(big)))
        assertEquals(0, cap.calls)
    }
    @Test fun `wrong protocol version`() = runTest {
        assertEquals("unsupported_version", code(dispatcher().dispatch(command().replace("\"v\":1", "\"v\":2"))))
    }
    @Test fun `unknown message type`() = runTest {
        assertEquals("unsupported_message", code(dispatcher().dispatch(command().replace("\"command\"", "\"shell\""))))
    }
    @Test fun `non command type is not handled`() = runTest {
        val hb = """{"v":1,"type":"heartbeat","id":"${UUID.randomUUID()}","device":"$SELF","payload":{}}"""
        assertEquals("unsupported_message", code(dispatcher().dispatch(hb)))
    }
    @Test fun `command carrying corr is malformed`() = runTest {
        val c = command().replaceFirst("\"device\"", "\"corr\":\"${UUID.randomUUID()}\",\"device\"")
        assertEquals("malformed", code(dispatcher().dispatch(c)))
    }
    @Test fun `bad device format is malformed`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(device = "short"))))
    }

    // ---- authorization / targeting ----
    @Test fun `command for another device is denied`() = runTest {
        assertEquals("permission_denied", code(dispatcher().dispatch(command(device = OTHER))))
        assertEquals(0, cap.calls)
    }
    @Test fun `deny-all policy blocks execution`() = runTest {
        assertEquals("permission_denied", code(dispatcher(policy = DenyAllPolicy).dispatch(command())))
        assertEquals(0, cap.calls)
    }
    @Test fun `claimed scopes do not grant access`() = runTest {
        val c = command(extra = ""","scopes_claimed":["test:read","admin"]""")
        assertEquals("permission_denied", code(dispatcher(policy = DenyAllPolicy).dispatch(c)))
        assertEquals(0, cap.calls)
    }
    @Test fun `enabled-set policy requires explicit enablement`() = runTest {
        val off = dispatcher(policy = EnabledSetPolicy { emptySet() })
        assertEquals("permission_denied", code(off.dispatch(command())))
        val on = dispatcher(policy = EnabledSetPolicy { setOf("test.echo") })
        assertEquals(MessageType.RESULT, on.dispatch(command()).type)
    }
    @Test fun `sensitive capability fails closed even when enabled`() = runTest {
        val s = FakeCapability(sensitivity = Sensitivity.SENSITIVE)
        val d = dispatcher(c = s, policy = EnabledSetPolicy { setOf("test.echo") })
        assertEquals("permission_denied", code(d.dispatch(command())))
        assertEquals(0, s.calls)
    }

    // ---- time window and replay ----
    @Test fun `expired command`() = runTest {
        val c = command(ts = NOW.minusSeconds(40), exp = NOW.minusSeconds(10))
        assertEquals("expired", code(dispatcher().dispatch(c)))
    }
    @Test fun `command from the far future`() = runTest {
        val c = command(ts = NOW.plusSeconds(120), exp = NOW.plusSeconds(150))
        assertEquals("expired", code(dispatcher().dispatch(c)))
    }
    @Test fun `window longer than 60s is rejected`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(exp = NOW.plusSeconds(61)))))
    }
    @Test fun `exp before ts is rejected`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(ts = NOW, exp = NOW.minusSeconds(1)))))
    }
    @Test fun `missing ts is malformed`() = runTest {
        val c = command().replace(Regex("\"ts\":\"[^\"]*\","), "")
        assertEquals("malformed", code(dispatcher().dispatch(c)))
    }
    @Test fun `replayed id is rejected and not executed twice`() = runTest {
        val d = dispatcher()
        val c = command(id = UUID.randomUUID().toString())
        assertEquals(MessageType.RESULT, d.dispatch(c).type)
        assertEquals("replayed", code(d.dispatch(c)))
        assertEquals(1, cap.calls)
    }
    @Test fun `replay table full is rate limited`() = runTest {
        val d = dispatcher(guard = ReplayGuard(clock, maxEntries = 2))
        d.dispatch(command()); d.dispatch(command())
        assertEquals("rate_limited", code(d.dispatch(command())))
    }

    // ---- capability resolution ----
    @Test fun `unknown capability`() = runTest {
        assertEquals("unknown_capability", code(dispatcher().dispatch(command(capability = "shell.exec"))))
    }
    @Test fun `version mismatch`() = runTest {
        assertEquals("unknown_capability", code(dispatcher().dispatch(command(version = 2))))
    }
    @Test fun `unavailable capability is reported not faked`() = runTest {
        val c = FakeCapability(avail = Availability.Unavailable("not on this OS"))
        val r = dispatcher(c).dispatch(command())
        assertEquals("capability_unavailable", code(r))
        assertEquals(0, c.calls)
    }
    @Test fun `missing android permission is reported`() = runTest {
        val c = FakeCapability(avail = Availability.PermissionRequired(setOf("android.permission.X")))
        assertEquals("permission_required", code(dispatcher(c).dispatch(command())))
        assertEquals(0, c.calls)
    }

    // ---- arguments ----
    @Test fun `unexpected args rejected`() = runTest {
        assertEquals("invalid_args", code(dispatcher().dispatch(command(args = """{"cmd":"rm"}"""))))
        assertEquals(0, cap.calls)
    }
    @Test fun `args must be object`() = runTest {
        assertEquals("malformed", code(dispatcher().dispatch(command(args = "[1]"))))
    }
    @Test fun `required arg enforced and typed`() = runTest {
        val c = FakeCapability(schema = ObjectSchema(mapOf("n" to FieldSpec(FieldType.INTEGER, required = true, min = 1, max = 5))))
        val d = dispatcher(c)
        assertEquals("invalid_args", code(d.dispatch(command(args = "{}"))))
        assertEquals("invalid_args", code(d.dispatch(command(args = """{"n":"3"}"""))))
        assertEquals("invalid_args", code(d.dispatch(command(args = """{"n":9}"""))))
        assertEquals(MessageType.RESULT, d.dispatch(command(args = """{"n":3}""")).type)
    }

    // ---- execution failures ----
    @Test fun `capability timeout`() = runTest {
        val c = FakeCapability(timeout = Duration.ofMillis(50), body = { delay(10_000); CapabilityResult.Ok(JsonObject(emptyMap())) })
        assertEquals("timeout", code(dispatcher(c).dispatch(command())))
    }
    @Test fun `capability exception does not leak details`() = runTest {
        val c = FakeCapability(body = { error("secret-token-123") })
        val r = dispatcher(c).dispatch(command())
        assertEquals("internal", code(r))
        assertFalse(r.toJson().contains("secret-token-123"))
    }
    @Test fun `capability failure is propagated`() = runTest {
        val c = FakeCapability(body = { CapabilityResult.Failure(ErrorCode.CAPABILITY_UNAVAILABLE, "gone") })
        assertEquals("capability_unavailable", code(dispatcher(c).dispatch(command())))
    }
    @Test fun `oversized result becomes internal error`() = runTest {
        val c = FakeCapability(body = { CapabilityResult.Ok(buildJsonObject { put("big", "x".repeat(70_000)) }) })
        assertEquals("internal", code(dispatcher(c).dispatch(command())))
    }
    @Test fun `caller cancellation is not swallowed`() = runTest {
        val started = CompletableDeferred<Unit>()
        val c = FakeCapability(body = { started.complete(Unit); delay(10_000); CapabilityResult.Ok(JsonObject(emptyMap())) })
        val job = launch(start = CoroutineStart.UNDISPATCHED) {
            dispatcher(c).dispatch(command())
        }
        started.await()
        job.cancel()
        job.join()
        assertTrue(job.isCancelled)
    }

    @Test fun `errors for unparsable input still carry device id`() = runTest {
        val r = dispatcher().dispatch("{")
        assertEquals(SELF, r.device)
        assertNotNull(r.payload["message"])
    }
}
