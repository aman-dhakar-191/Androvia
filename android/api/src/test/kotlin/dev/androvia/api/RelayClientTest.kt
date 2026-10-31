package dev.androvia.api

import dev.androvia.core.Envelope
import dev.androvia.core.ErrorCode
import dev.androvia.core.ExponentialBackoff
import dev.androvia.core.MessageType
import dev.androvia.core.RelayEndpoint
import dev.androvia.core.RelayState
import io.ktor.client.HttpClient
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import java.time.Clock
import java.time.Duration
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonPrimitive

class RelayClientTest {
    private val device = TestDevice()
    private val stranger = TestDevice()
    private val relays = mutableListOf<FakeRelay>()
    private val clients = mutableListOf<HttpClient>()
    private val scope = CoroutineScope(Dispatchers.Default + Job())

    // The fake relay hands each authenticated server-side session to the test so it can push frames to the device.
    private val sessions = java.util.concurrent.ConcurrentHashMap<FakeRelay, DefaultWebSocketServerSession>()

    private fun relay(registered: Boolean = true): FakeRelay {
        val r = FakeRelay(if (registered) mapOf(device.id to device.spki) else emptyMap())
        r.onAuthenticated = { sessions[r] = this }
        relays += r
        return r
    }

    private val fastBackoff = ExponentialBackoff(Duration.ofMillis(20), Duration.ofMillis(60), Random(1))

    private fun client(
        handler: suspend (String) -> Envelope = device.dispatcher(setOf("device.info")),
        config: RelayClientConfig = RelayClientConfig(heartbeatInterval = Duration.ofMillis(100), silenceTimeout = Duration.ofSeconds(5), handshakeTimeout = Duration.ofSeconds(3)),
    ): RelayClient {
        val http = createRelayHttpClient().also { clients += it }
        return RelayClient(http, device.signer, handler, Clock.systemUTC(), fastBackoff, config)
    }

    private fun start(c: RelayClient, r: FakeRelay): Job = scope.launch { c.run(RelayEndpoint.parse(r.origin, allowInsecure = true)) }

    @AfterTest fun cleanup() {
        runBlocking { scope.coroutineContext[Job]?.let { it.children.forEach { c -> c.cancelAndJoin() } } }
        clients.forEach { it.close() }
        relays.forEach { it.close() }
    }

    private suspend fun RelayClient.await(timeoutMs: Long = 8000, pred: (RelayConnectionState) -> Boolean): RelayConnectionState =
        withTimeout(timeoutMs) { state.first(pred) }

    private suspend fun <T> poll(timeoutMs: Long = 8000, f: () -> T?): T = withTimeout(timeoutMs) {
        var v = f()
        while (v == null) { delay(20); v = f() }
        v
    }

    @Test fun `connects, reports CONNECTED and answers a command`() = runBlocking {
        val r = relay()
        val c = client()
        assertEquals(RelayState.NOT_CONFIGURED, c.state.value.relay)
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }

        // Send a command through the relay side; the device's own dispatcher runs it.
        val cmd = device.commandJson()
        val cmdId = idOf(cmd)
        val session = sessionOf(r)
        session.send(Frame.Text(cmd))
        val reply = withTimeout(5000) { r.fromDevice.receive() }
        assertEquals(MessageType.RESULT, reply.type)
        assertEquals(cmdId, reply.corr)
        assertEquals("Acme", ((reply.payload["data"] as kotlinx.serialization.json.JsonObject)["manufacturer"])!!.jsonPrimitive.content)
    }

    @Test fun `device policy still applies - a disabled capability is refused on the device`() = runBlocking {
        val r = relay()
        val c = client(handler = device.dispatcher(emptySet()))
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        sessionOf(r).send(Frame.Text(device.commandJson()))
        val reply = withTimeout(5000) { r.fromDevice.receive() }
        assertEquals(MessageType.ERROR, reply.type)
        assertEquals("permission_denied", reply.payload["code"]!!.jsonPrimitive.content)
    }

    @Test fun `an unparsable command still gets an error back`() = runBlocking {
        val r = relay()
        val c = client()
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        val id = java.util.UUID.randomUUID()
        sessionOf(r).send(Frame.Text("""{"v":1,"type":"command","id":"$id","device":"nope","payload":{}}"""))
        val reply = withTimeout(5000) { r.fromDevice.receive() }
        assertEquals(MessageType.ERROR, reply.type)
        assertEquals(id.toString(), reply.corr)
    }

    @Test fun `garbage from the relay is ignored and the connection keeps working`() = runBlocking {
        val r = relay()
        val c = client()
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        val s = sessionOf(r)
        s.send(Frame.Text("not json"))
        s.send(Frame.Text("""{"v":1}"""))
        s.send(Frame.Binary(true, byteArrayOf(1, 2, 3)))
        s.send(Frame.Text("x".repeat(dev.androvia.core.Protocol.MAX_MESSAGE_BYTES + 1000))) // oversize: never acted on
        s.send(Frame.Text(device.commandJson()))
        assertEquals(MessageType.RESULT, withTimeout(5000) { r.fromDevice.receive() }.type)
        assertEquals(RelayState.CONNECTED, c.state.value.relay)
        assertEquals(1, r.connections.get())
    }

    @Test fun `a relay-sent cancel stops the command and the relay is told`() = runBlocking {
        val r = relay()
        val started = CompletableDeferred<Unit>()
        val c = client(handler = { raw ->
            started.complete(Unit)
            delay(60_000) // a long-running capability
            device.dispatcher(setOf("device.info"))(raw)
        })
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        val cmd = device.commandJson()
        val s = sessionOf(r)
        s.send(Frame.Text(cmd))
        withTimeout(5000) { started.await() }
        s.send(Frame.Text(r.cancelJson(device.id, idOf(cmd))))
        val reply = withTimeout(5000) { r.fromDevice.receive() }
        assertEquals(MessageType.ERROR, reply.type)
        assertEquals(idOf(cmd), reply.corr)
        assertEquals(ErrorCode.CANCELLED.wire, reply.payload["code"]!!.jsonPrimitive.content)
    }

    @Test fun `too many commands in flight are refused with rate_limited`() = runBlocking {
        val r = relay()
        val gate = CompletableDeferred<Unit>()
        val c = client(
            handler = { raw -> gate.await(); device.dispatcher(setOf("device.info"))(raw) },
            config = RelayClientConfig(heartbeatInterval = Duration.ofMillis(100), maxInFlightCommands = 1),
        )
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        val s = sessionOf(r)
        val first = device.commandJson()
        val second = device.commandJson()
        s.send(Frame.Text(first))
        delay(200)
        s.send(Frame.Text(second))
        val limited = withTimeout(5000) { r.fromDevice.receive() }
        assertEquals(idOf(second), limited.corr)
        assertEquals("rate_limited", limited.payload["code"]!!.jsonPrimitive.content)
        gate.complete(Unit)
        assertEquals(idOf(first), withTimeout(5000) { r.fromDevice.receive() }.corr)
    }

    @Test fun `a rejected device keeps retrying and explains why`() = runBlocking {
        val r = relay(registered = false)
        val c = client()
        start(c, r)
        val st = c.await { it.relay == RelayState.RECONNECTING && it.detail?.contains("rejected") == true }
        assertFalse(st.terminal)
        poll { r.authAttempts.get().takeIf { it >= 3 } } // retries with backoff
        assertEquals(0, r.authenticated.get())
    }

    @Test fun `a signature made with another key is rejected`() = runBlocking {
        val r = FakeRelay(mapOf(device.id to device.spki)).also { relays += it }
        val http = createRelayHttpClient().also { clients += it }
        val impostor = object : RelaySigner {
            override suspend fun deviceId() = device.id // claims to be the real device
            override suspend fun sign(data: ByteArray) = stranger.signer.sign(data) // but holds another key
        }
        val c = RelayClient(http, impostor, device.dispatcher(setOf("device.info")), Clock.systemUTC(), fastBackoff, RelayClientConfig(heartbeatInterval = Duration.ofMillis(100)))
        start(c, r)
        c.await { it.detail?.contains("rejected") == true }
        assertEquals(0, r.authenticated.get())
    }

    @Test fun `replaced by a newer connection is terminal`() = runBlocking {
        val r = relay().apply { closeAfterAuth = 4001.toShort() to "replaced by a newer connection" }
        val c = client()
        val job = start(c, r)
        val st = c.await { it.terminal }
        assertEquals(RelayState.FAILED, st.relay)
        assertTrue(st.detail!!.contains("replaced"))
        withTimeout(3000) { job.join() } // run() returned instead of reconnecting
        assertEquals(1, r.connections.get())
    }

    @Test fun `revoked is terminal`() = runBlocking {
        val r = relay().apply { closeAfterAuth = 4002.toShort() to "device revoked" }
        val c = client()
        val job = start(c, r)
        val st = c.await { it.terminal }
        assertTrue(st.detail!!.contains("revoked"))
        withTimeout(3000) { job.join() }
        assertEquals(1, r.connections.get())
    }

    @Test fun `reconnects after the relay drops the connection`() = runBlocking {
        val r = relay().apply { closeAfterAuth = 1011.toShort() to "restart" }
        val c = client()
        start(c, r)
        poll { r.authenticated.get().takeIf { it >= 1 } }
        r.closeAfterAuth = null // the relay is healthy again
        // CONNECTED also flashes briefly on the first (dropped) connection, so wait for one that stays up.
        withTimeout(8000) {
            while (true) {
                val n = r.connections.get()
                delay(400)
                if (c.state.value.relay == RelayState.CONNECTED && r.connections.get() == n) break
            }
        }
        assertTrue(r.connections.get() >= 2)
    }

    @Test fun `a silent relay is detected and the client reconnects`() = runBlocking {
        val r = relay()
        val c = client(config = RelayClientConfig(heartbeatInterval = Duration.ofMillis(50), silenceTimeout = Duration.ofMillis(600)))
        start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        r.answerHeartbeats = false // the relay stops answering (a half-open connection)
        poll { r.connections.get().takeIf { it >= 2 } }
    }

    @Test fun `a bad hello_ack is never answered with a signature`() = runBlocking {
        for (mode in listOf(FakeRelay.Hello.SHORT_NONCE, FakeRelay.Hello.WRONG_CORR)) {
            val r = relay().apply { hello = mode }
            val c = client()
            start(c, r)
            poll { r.connections.get().takeIf { it >= 2 } } // it tried, rejected the ack, and retried
            assertEquals(0, r.authAttempts.get(), "signed after a bad $mode")
            assertEquals(0, r.authenticated.get())
        }
    }

    @Test fun `an unreachable relay is retried, not fatal`() = runBlocking {
        val dead = RelayEndpoint.parse("ws://127.0.0.1:1", allowInsecure = true)
        val c = client()
        scope.launch { c.run(dead) }
        val st = c.await { it.relay == RelayState.RECONNECTING && it.detail == "Cannot reach the relay" }
        assertFalse(st.terminal)
    }

    @Test fun `cancelling run closes the connection`() = runBlocking {
        val r = relay()
        val c = client()
        val job = start(c, r)
        c.await { it.relay == RelayState.CONNECTED }
        job.cancelAndJoin()
        assertTrue(job.isCancelled)
    }

    private suspend fun sessionOf(r: FakeRelay): DefaultWebSocketServerSession = poll { sessions[r] }

    private fun idOf(json: String): String = dev.androvia.core.EnvelopeParser.parse(json).id
}
