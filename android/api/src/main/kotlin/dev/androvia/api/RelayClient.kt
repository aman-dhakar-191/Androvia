package dev.androvia.api

import dev.androvia.core.Envelope
import dev.androvia.core.EnvelopeParser
import dev.androvia.core.ErrorCode
import dev.androvia.core.ExponentialBackoff
import dev.androvia.core.MessageType
import dev.androvia.core.ProtocolException
import dev.androvia.core.RelayEndpoint
import dev.androvia.core.RelayHandshake
import dev.androvia.core.RelayState
import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import java.time.Clock
import java.time.Duration
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/** Signs with the device key. Implemented over the Android Keystore in :runtime. */
interface RelaySigner {
    suspend fun deviceId(): String
    suspend fun sign(data: ByteArray): ByteArray
}

/** [relay] drives the status UI; [detail] is a short human-readable reason; [terminal] means we stopped trying. */
data class RelayConnectionState(val relay: RelayState, val detail: String? = null, val terminal: Boolean = false)

data class RelayClientConfig(
    val heartbeatInterval: Duration = RelayHandshake.HEARTBEAT_INTERVAL,
    /** No frame from the relay for this long means the connection is dead (the relay answers every heartbeat). */
    val silenceTimeout: Duration = Duration.ofSeconds(75),
    val handshakeTimeout: Duration = Duration.ofSeconds(10),
    val maxInFlightCommands: Int = 8,
    val appVersion: String = "",
)

/**
 * Keeps one authenticated WebSocket to the relay for as long as [run] is active, reconnecting with bounded backoff.
 *
 * Authority stays on the device: every `command` is handed unchanged to [handler] (the local command dispatcher), which
 * validates it and applies the device's own policy. The relay is only a transport.
 *
 * Authentication has no explicit "ok" message, so the first heartbeat is sent right after `auth` and the relay's
 * answer to it is what moves the state to CONNECTED.
 */
class RelayClient(
    private val http: HttpClient,
    private val signer: RelaySigner,
    private val handler: suspend (String) -> Envelope,
    private val clock: Clock = Clock.systemUTC(),
    private val backoff: ExponentialBackoff = ExponentialBackoff(),
    private val config: RelayClientConfig = RelayClientConfig(),
    private val log: (String) -> Unit = {},
) {
    private val _state = MutableStateFlow(RelayConnectionState(RelayState.NOT_CONFIGURED))
    val state: StateFlow<RelayConnectionState> = _state.asStateFlow()

    private sealed interface End {
        data class Retry(val detail: String, val wasConnected: Boolean) : End
        data class Stop(val detail: String) : End
    }

    /** Runs until cancelled, or until the relay says to stop (device revoked, or replaced by another connection). */
    suspend fun run(endpoint: RelayEndpoint) {
        var attempt = 0
        while (true) {
            _state.value = RelayConnectionState(RelayState.RECONNECTING, "Connecting…")
            val end = try {
                session(endpoint)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log("relay connect failed: ${e.javaClass.simpleName}")
                End.Retry("Cannot reach the relay", wasConnected = false)
            }
            when (end) {
                is End.Stop -> {
                    _state.value = RelayConnectionState(RelayState.FAILED, end.detail, terminal = true)
                    return
                }
                is End.Retry -> {
                    if (end.wasConnected) attempt = 0
                    _state.value = RelayConnectionState(RelayState.RECONNECTING, end.detail)
                    delay(backoff.delayFor(attempt++).toMillis())
                }
            }
        }
    }

    private suspend fun session(endpoint: RelayEndpoint): End {
        val ws = http.webSocketSession(urlString = endpoint.wsUrl)
        var connected = false
        try {
            val deviceId = signer.deviceId()
            withTimeout(config.handshakeTimeout.toMillis()) { handshake(ws, endpoint, deviceId) }
            connected = true
            _state.value = RelayConnectionState(RelayState.CONNECTED)
            connectedLoop(ws, deviceId)
        } catch (e: TimeoutCancellationException) {
            log("relay handshake timed out")
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProtocolException) {
            log("relay protocol error: ${e.code.wire}")
        } catch (e: Exception) {
            log("relay session ended: ${e.javaClass.simpleName}")
        } finally {
            withContext(NonCancellable) {
                if (ws.isActive) runCatching { ws.close(CloseReason(CloseReason.Codes.NORMAL, "bye")) }
            }
        }
        return endOf(ws, connected)
    }

    private suspend fun handshake(ws: DefaultClientWebSocketSession, endpoint: RelayEndpoint, deviceId: String) {
        val hello = RelayHandshake.hello(deviceId, config.appVersion, clock.instant())
        ws.send(Frame.Text(hello.toJson()))
        val nonce = RelayHandshake.parseHelloAck(nextText(ws), hello)
        val signature = signer.sign(RelayHandshake.authMessage(nonce, deviceId, endpoint.origin))
        ws.send(Frame.Text(RelayHandshake.auth(deviceId, signature, clock.instant()).toJson()))
        val beat = RelayHandshake.heartbeat(deviceId, clock.instant())
        ws.send(Frame.Text(beat.toJson()))
        // Authentication succeeded only if the relay answers the heartbeat; a failure arrives as a close frame.
        val reply = EnvelopeParser.parse(nextText(ws))
        if (reply.type != MessageType.HEARTBEAT || reply.corr != beat.id) {
            throw ProtocolException(ErrorCode.MALFORMED, "relay did not confirm the connection", reply.id)
        }
    }

    private suspend fun nextText(ws: DefaultClientWebSocketSession): String {
        val frame = ws.incoming.receive() // throws if the relay closed the connection (e.g. authentication failed)
        return (frame as? Frame.Text)?.readText() ?: throw ProtocolException(ErrorCode.MALFORMED, "text frames only")
    }

    private suspend fun connectedLoop(ws: DefaultClientWebSocketSession, deviceId: String) = coroutineScope {
        val lastInbound = AtomicLong(clock.millis())
        val inFlight = ConcurrentHashMap<String, Job>()
        val active = AtomicInteger(0)

        launch { // heartbeat
            while (isActive) {
                delay(config.heartbeatInterval.toMillis())
                ws.send(Frame.Text(RelayHandshake.heartbeat(deviceId, clock.instant()).toJson()))
            }
        }
        launch { // dead-connection watchdog: half-open TCP connections never raise an error on their own
            val tick = (config.silenceTimeout.toMillis() / 4).coerceAtLeast(10)
            while (isActive) {
                delay(tick)
                if (clock.millis() - lastInbound.get() > config.silenceTimeout.toMillis()) {
                    log("relay silent too long; reconnecting")
                    ws.close(CloseReason(CloseReason.Codes.GOING_AWAY, "relay silent"))
                    return@launch
                }
            }
        }

        for (frame in ws.incoming) {
            lastInbound.set(clock.millis())
            val text = (frame as? Frame.Text)?.readText() ?: continue
            val env = try {
                EnvelopeParser.parse(text)
            } catch (e: ProtocolException) {
                // A command we cannot parse still goes to the dispatcher so the relay gets a proper error back;
                // anything else malformed is ignored.
                if (text.contains("\"command\"")) startCommand(ws, text, null, inFlight, active, deviceId)
                continue
            }
            when (env.type) {
                MessageType.COMMAND -> startCommand(ws, text, env.id, inFlight, active, deviceId)
                MessageType.CANCEL -> env.corr?.let { inFlight[it] }?.cancel()
                MessageType.ERROR -> log("relay sent an error message")
                else -> Unit // heartbeat replies and anything unexpected need no action
            }
        }
        coroutineContext.cancelChildren() // the connection ended: stop heartbeat, watchdog and unfinished commands
    }

    private fun CoroutineScope.startCommand(
        ws: DefaultClientWebSocketSession,
        raw: String,
        id: String?,
        inFlight: ConcurrentHashMap<String, Job>,
        active: AtomicInteger,
        deviceId: String,
    ) {
        if (active.incrementAndGet() > config.maxInFlightCommands) {
            active.decrementAndGet()
            if (id != null) launch { sendError(ws, id, deviceId, ErrorCode.RATE_LIMITED, "too many commands in flight") }
            return
        }
        val job = launch {
            try {
                ws.send(Frame.Text(handler(raw).toJson()))
            } catch (e: CancellationException) {
                // A cancelled coroutine cannot suspend, so the reply must run non-cancellable.
                if (id != null) withContext(NonCancellable) {
                    withTimeoutOrNull(1000) { sendError(ws, id, deviceId, ErrorCode.CANCELLED, "cancelled by the relay") }
                }
                throw e
            } catch (e: Exception) {
                log("command handler failed: ${e.javaClass.simpleName}") // details stay on the device
            } finally {
                active.decrementAndGet()
                if (id != null) inFlight.remove(id)
            }
        }
        if (id != null) inFlight[id] = job
    }

    private suspend fun sendError(ws: DefaultClientWebSocketSession, corr: String, deviceId: String, code: ErrorCode, msg: String) {
        runCatching {
            ws.send(Frame.Text(Envelope.error(UUID.randomUUID().toString(), corr, deviceId, clock.instant(), code, msg).toJson()))
        }
    }

    /** Works out why a session ended from the relay's close frame. */
    private suspend fun endOf(ws: DefaultClientWebSocketSession, wasConnected: Boolean): End {
        val code = withTimeoutOrNull(1500) { ws.closeReason.await() }?.code?.toInt()
        return when (code) {
            CLOSE_REPLACED -> End.Stop("Another connection from this device replaced this one")
            CLOSE_REVOKED -> End.Stop("This device was revoked on the relay")
            CLOSE_AUTH_FAILED ->
                End.Retry("The relay rejected this device. Is it registered with this key and address?", wasConnected = false)
            else -> End.Retry(if (wasConnected) "Connection lost" else "Cannot reach the relay", wasConnected)
        }
    }

    companion object {
        const val CLOSE_AUTH_FAILED = 1008
        const val CLOSE_REPLACED = 4001
        const val CLOSE_REVOKED = 4002
    }
}
