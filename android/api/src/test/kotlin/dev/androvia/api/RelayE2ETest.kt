package dev.androvia.api

import dev.androvia.core.ExponentialBackoff
import dev.androvia.core.RelayEndpoint
import dev.androvia.core.RelayState
import java.net.URI
import java.net.http.HttpClient as JdkHttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Clock
import java.time.Duration
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Kotlin client against the REAL Go relay. This is the cross-implementation check: if the two sides disagree on the
 * envelope, the signed bytes or the close codes, it fails here. It runs only when RELAY_E2E_URL and
 * RELAY_E2E_ADMIN_TOKEN are set (CI sets them and fails the build if this class was skipped).
 *
 * The relay must be started with RELAY_PUBLIC_ORIGIN=ws://<same host:port> and RELAY_ALLOW_INSECURE_HTTP=true.
 */
class RelayE2ETest {
    private val baseUrl: String? = System.getenv("RELAY_E2E_URL")?.trimEnd('/')
    private val token: String? = System.getenv("RELAY_E2E_ADMIN_TOKEN")

    private val http = JdkHttpClient.newHttpClient()
    private val scope = CoroutineScope(Dispatchers.Default + Job())
    private val clients = mutableListOf<io.ktor.client.HttpClient>()

    private fun endpoint() = RelayEndpoint.parse(baseUrl!!.replaceFirst("http", "ws"), allowInsecure = true)

    @AfterTest fun cleanup() {
        runBlocking { scope.coroutineContext[Job]?.children?.forEach { it.cancelAndJoin() } }
        clients.forEach { it.close() }
        // java.net.http.HttpClient has no close() before JDK 21 (CI uses 17); it is released by GC.
    }

    private fun requireRelay() = assumeTrue(baseUrl != null && token != null, "RELAY_E2E_URL / RELAY_E2E_ADMIN_TOKEN not set")

    private fun call(method: String, path: String, body: JsonObject? = null, auth: Boolean = true): Pair<Int, JsonObject> {
        val b = HttpRequest.newBuilder(URI.create(baseUrl + path))
        if (auth) b.header("Authorization", "Bearer $token")
        b.header("Content-Type", "application/json")
        b.method(method, if (body == null) HttpRequest.BodyPublishers.noBody() else HttpRequest.BodyPublishers.ofString(body.toString()))
        val resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString())
        val json = runCatching { Json.parseToJsonElement(resp.body()).jsonObject }.getOrDefault(JsonObject(emptyMap()))
        return resp.statusCode() to json
    }

    private fun register(d: TestDevice) {
        val (code, out) = call("POST", "/v1/devices", buildJsonObject {
            put("label", "e2e")
            put("public_key", d.publicKeyB64)
        })
        assertEquals(201, code, out.toString())
        assertEquals(d.id, out["id"]!!.jsonPrimitive.content, "relay and device disagree on the device id")
    }

    private fun command(d: TestDevice, capability: String = "device.info"): Pair<Int, JsonObject> =
        call("POST", "/v1/devices/${d.id}/commands", buildJsonObject {
            put("capability", capability)
            put("version", 1)
            put("timeout_ms", 5000)
        })

    private fun newClient(d: TestDevice, enabled: Set<String>): RelayClient {
        val h = createRelayHttpClient().also { clients += it }
        return RelayClient(
            h, d.signer, d.dispatcher(enabled), Clock.systemUTC(),
            ExponentialBackoff(Duration.ofMillis(50), Duration.ofMillis(200), Random(1)),
            RelayClientConfig(heartbeatInterval = Duration.ofMillis(300), appVersion = "e2e"),
        )
    }

    private fun start(c: RelayClient): Job = scope.launch { c.run(endpoint()) }

    private suspend fun RelayClient.await(ms: Long = 10_000, p: (RelayConnectionState) -> Boolean) = withTimeout(ms) { state.first(p) }

    @Test fun `a device registered with its key connects to the real relay and runs a command`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val c = newClient(d, setOf("device.info"))
        start(c)
        c.await { it.relay == RelayState.CONNECTED }

        val (g, dev) = call("GET", "/v1/devices/${d.id}")
        assertEquals(200, g)
        assertEquals(true, (dev["online"] as JsonPrimitive).content.toBoolean(), dev.toString())

        val (code, out) = command(d)
        assertEquals(200, code, out.toString())
        assertEquals("ok", out["status"]!!.jsonPrimitive.content)
        val data = out["result"]!!.jsonObject["data"]!!.jsonObject
        assertEquals("Acme", data["manufacturer"]!!.jsonPrimitive.content)
        assertEquals("36", data["sdk_int"]!!.jsonPrimitive.content)
    }

    @Test fun `the device's own policy refuses a capability the user has not enabled`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val c = newClient(d, emptySet())
        start(c)
        c.await { it.relay == RelayState.CONNECTED }
        val (code, out) = command(d)
        assertEquals(422, code, out.toString())
        val err = out["error"]!!.jsonObject
        assertEquals("permission_denied", err["code"]!!.jsonPrimitive.content)
        assertEquals("device", err["source"]!!.jsonPrimitive.content)
    }

    @Test fun `an unknown capability is refused by the device and reported`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val c = newClient(d, setOf("device.info"))
        start(c)
        c.await { it.relay == RelayState.CONNECTED }
        val (code, out) = command(d, "files.read")
        assertEquals(422, code, out.toString())
        assertEquals("unknown_capability", out["error"]!!.jsonObject["code"]!!.jsonPrimitive.content)
    }

    @Test fun `a device that was never registered is rejected and keeps retrying`() = runBlocking {
        requireRelay()
        val d = TestDevice() // not registered
        val c = newClient(d, setOf("device.info"))
        start(c)
        val st = c.await { it.relay == RelayState.RECONNECTING && it.detail?.contains("rejected") == true }
        assertFalse(st.terminal)
    }

    @Test fun `a device cannot sign in with someone else's key`() = runBlocking {
        requireRelay()
        val victim = TestDevice()
        register(victim)
        val attacker = TestDevice()
        val impostor = object : RelaySigner {
            override suspend fun deviceId() = victim.id
            override suspend fun sign(data: ByteArray) = attacker.signer.sign(data)
        }
        val h = createRelayHttpClient().also { clients += it }
        val c = RelayClient(h, impostor, attacker.dispatcher(setOf("device.info")), Clock.systemUTC(),
            ExponentialBackoff(Duration.ofMillis(50), Duration.ofMillis(200), Random(1)), RelayClientConfig(heartbeatInterval = Duration.ofMillis(300)))
        start(c)
        c.await { it.detail?.contains("rejected") == true }
        assertEquals(409, command(victim).first, "the victim must still be offline")
    }

    @Test fun `revoking the device on the relay stops the client for good`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val c = newClient(d, setOf("device.info"))
        val job = start(c)
        c.await { it.relay == RelayState.CONNECTED }
        assertEquals(200, call("POST", "/v1/devices/${d.id}/revoke").first)
        val st = c.await { it.terminal }
        assertEquals(RelayState.FAILED, st.relay)
        assertTrue(st.detail!!.contains("revoked"), st.detail)
        withTimeout(5000) { job.join() }
    }

    @Test fun `a second connection from the same device replaces the first, which stops instead of fighting`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val first = newClient(d, setOf("device.info"))
        val firstJob = start(first)
        first.await { it.relay == RelayState.CONNECTED }
        val second = newClient(d, setOf("device.info"))
        start(second)
        second.await { it.relay == RelayState.CONNECTED }
        val st = first.await { it.terminal }
        assertTrue(st.detail!!.contains("replaced"), st.detail)
        withTimeout(5000) { firstJob.join() }
        assertEquals(RelayState.CONNECTED, second.state.value.relay)
        assertEquals(200, command(d).first) // the newer connection serves commands
    }

    @Test fun `after the client stops the relay reports the device offline`() = runBlocking {
        requireRelay()
        val d = TestDevice()
        register(d)
        val c = newClient(d, setOf("device.info"))
        val job = start(c)
        c.await { it.relay == RelayState.CONNECTED }
        job.cancelAndJoin()
        withTimeout(5000) {
            while (true) {
                val (code, out) = command(d)
                if (code == 409 && out["error"]!!.jsonObject["code"]!!.jsonPrimitive.content == "device_offline") break
                delay(100)
            }
        }
        assertNotNull(c.state.value)
    }
}
