package dev.androvia.api

import dev.androvia.core.Envelope
import dev.androvia.core.EnvelopeParser
import dev.androvia.core.MessageType
import dev.androvia.core.Protocol
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import io.ktor.server.websocket.WebSockets as ServerWebSockets

/**
 * A scriptable relay for client tests. It verifies the device signature against bytes laid out *independently* of the
 * client's own helper, so a drift in the documented layout fails here.
 */
class FakeRelay(private val registered: Map<String, ByteArray>) : AutoCloseable {
    enum class Hello { NORMAL, SHORT_NONCE, WRONG_CORR }

    @Volatile var hello = Hello.NORMAL
    @Volatile var answerHeartbeats = true
    @Volatile var closeAfterAuth: Pair<Short, String>? = null
    @Volatile var onAuthenticated: suspend DefaultWebSocketServerSession.() -> Unit = {}

    val connections = AtomicInteger()
    val authAttempts = AtomicInteger()
    val authenticated = AtomicInteger()
    val fromDevice = Channel<Envelope>(Channel.UNLIMITED) // everything except heartbeats, after authentication

    private val server: EmbeddedServer<*, *> = embeddedServer(CIO, port = 0) {
        install(ServerWebSockets) { maxFrameSize = 1_000_000L }
        routing { webSocket("/v1/device/ws") { serve() } }
    }.start(wait = false)

    val port: Int = runBlocking { server.engine.resolvedConnectors().first().port }
    val origin = "ws://127.0.0.1:$port"

    private suspend fun DefaultWebSocketServerSession.serve() {
        connections.incrementAndGet()
        val helloFrame = incoming.receive() as Frame.Text
        val hello = EnvelopeParser.parse(helloFrame.readText())
        val nonce = ByteArray(if (this@FakeRelay.hello == Hello.SHORT_NONCE) 16 else 32).also { SecureRandom().nextBytes(it) }
        val corr = if (this@FakeRelay.hello == Hello.WRONG_CORR) UUID.randomUUID().toString() else hello.id
        send(Frame.Text(
            """{"v":1,"type":"hello_ack","id":"${UUID.randomUUID()}","corr":"$corr","device":"${hello.device}","ts":"${Instant.now()}","payload":{"nonce":"${Base64.getEncoder().encodeToString(nonce)}","version":1}}""",
        ))
        val authEnv = EnvelopeParser.parse((incoming.receive() as Frame.Text).readText())
        authAttempts.incrementAndGet()
        val sig = Base64.getDecoder().decode((authEnv.payload["signature"] as JsonPrimitive).content)
        // Independent layout: "androvia/relay-auth/v1\0" || nonce || deviceID || origin
        val message = "androvia/relay-auth/v1\u0000".toByteArray() + nonce + hello.device.toByteArray() + origin.toByteArray()
        val spki = registered[hello.device]
        val ok = authEnv.type == MessageType.AUTH && spki != null && Signature.getInstance("SHA256withECDSA").run {
            initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki)))
            update(message)
            verify(sig)
        }
        if (!ok) {
            close(CloseReason(1008, "authentication failed"))
            return
        }
        authenticated.incrementAndGet()
        closeAfterAuth?.let { (code, reason) ->
            // Answer the first heartbeat (confirming auth) and then close, like a relay that drops the device.
            replyHeartbeat(hello.device)
            close(CloseReason(code, reason))
            return
        }
        replyHeartbeat(hello.device) // the confirmation the client waits for
        onAuthenticated()
        for (frame in incoming) {
            val text = (frame as? Frame.Text)?.readText() ?: continue
            val env = runCatching { EnvelopeParser.parse(text) }.getOrNull() ?: continue
            if (env.type == MessageType.HEARTBEAT) {
                if (answerHeartbeats) send(Frame.Text(heartbeat(hello.device, env.id)))
            } else {
                fromDevice.send(env)
            }
        }
    }

    private suspend fun DefaultWebSocketServerSession.replyHeartbeat(device: String) {
        val beat = EnvelopeParser.parse((incoming.receive() as Frame.Text).readText())
        send(Frame.Text(heartbeat(device, beat.id)))
    }

    private fun heartbeat(device: String, corr: String) =
        """{"v":1,"type":"heartbeat","id":"${UUID.randomUUID()}","corr":"$corr","device":"$device","ts":"${Instant.now()}","payload":{}}"""

    fun cancelJson(device: String, corr: String): String {
        val now = Instant.now()
        return Envelope(Protocol.VERSION, MessageType.CANCEL, UUID.randomUUID().toString(), corr, device, now, now.plusSeconds(10), JsonObject(emptyMap())).toJson()
    }

    @Suppress("unused")
    private fun payload() = buildJsonObject { put("x", 1) }

    override fun close() = server.stop(100, 500)
}
