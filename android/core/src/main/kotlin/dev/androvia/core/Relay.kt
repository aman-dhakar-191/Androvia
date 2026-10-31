package dev.androvia.core

import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The relay's origin as the user typed it, normalised the same way the relay normalises RELAY_PUBLIC_ORIGIN
 * (lower case, no trailing slash), because the origin is part of what the device signs.
 */
data class RelayEndpoint(val origin: String, val wsUrl: String) {
    companion object {
        const val PATH = "/v1/device/ws"

        /** [allowInsecure] permits ws:// and exists only for tests; the app always passes false. */
        fun parse(input: String, allowInsecure: Boolean = false): RelayEndpoint {
            val text = input.trim()
            require(text.isNotEmpty()) { "Enter the relay address, for example wss://relay.example.com" }
            val uri = try {
                URI(text)
            } catch (e: Exception) {
                throw IllegalArgumentException("That is not a valid address")
            }
            val scheme = uri.scheme?.lowercase()
            require(scheme == "wss" || (allowInsecure && scheme == "ws")) {
                if (scheme == "ws") "Use wss:// (an encrypted connection)" else "The address must start with wss://"
            }
            require(!uri.host.isNullOrEmpty()) { "The address has no host name" }
            require(uri.userInfo == null) { "Remove the user name and password from the address" }
            require(uri.rawQuery == null && uri.rawFragment == null) { "Remove the query or fragment from the address" }
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") { "Use only the host, with no path" }
            require(uri.port == -1 || uri.port in 1..65535) { "The port is out of range" }
            val origin = buildString {
                append(scheme).append("://").append(uri.host.lowercase())
                if (uri.port != -1) append(':').append(uri.port)
            }
            return RelayEndpoint(origin, origin + PATH)
        }
    }
}

/** What the saved relay setting means right now. */
sealed interface RelayConfigState {
    data object NotConfigured : RelayConfigState
    data class Invalid(val message: String) : RelayConfigState
    data class Ready(val endpoint: RelayEndpoint) : RelayConfigState
}

object RelayConfigRules {
    /** Disabled or empty means do not connect; an enabled but unusable address is reported, never guessed at. */
    fun resolve(url: String, enabled: Boolean, allowInsecure: Boolean = false): RelayConfigState = when {
        !enabled -> RelayConfigState.NotConfigured
        else -> try {
            RelayConfigState.Ready(RelayEndpoint.parse(url, allowInsecure))
        } catch (e: IllegalArgumentException) {
            RelayConfigState.Invalid(e.message ?: "Invalid address")
        }
    }
}

/** Device side of the relay handshake and heartbeat (docs/protocol/envelope.md). Pure functions, no I/O. */
object RelayHandshake {
    const val AUTH_PREFIX = "androvia/relay-auth/v1\u0000"
    const val NONCE_BYTES = 32
    val HEARTBEAT_INTERVAL: Duration = Duration.ofSeconds(25)

    /** prefix || nonce || deviceID || relayOrigin, the exact bytes the relay verifies. */
    fun authMessage(nonce: ByteArray, deviceId: String, origin: String): ByteArray =
        (AUTH_PREFIX.toByteArray(Charsets.UTF_8) + nonce + deviceId.toByteArray(Charsets.UTF_8) + origin.toByteArray(Charsets.UTF_8))

    fun hello(deviceId: String, appVersion: String, now: Instant): Envelope = Envelope(
        v = Protocol.VERSION, type = MessageType.HELLO, id = UUID.randomUUID().toString(), corr = null, device = deviceId,
        ts = now, exp = null,
        payload = buildJsonObject {
            put("versions", JsonArray(listOf(JsonPrimitive(Protocol.VERSION))))
            put("app_version", appVersion)
        },
    )

    /** Validates the relay's hello_ack and returns the nonce. Throws [ProtocolException] on anything unexpected. */
    fun parseHelloAck(text: String, hello: Envelope): ByteArray {
        val ack = EnvelopeParser.parse(text)
        fun bad(msg: String): Nothing = throw ProtocolException(ErrorCode.MALFORMED, msg, ack.id)
        if (ack.type != MessageType.HELLO_ACK) bad("expected hello_ack")
        if (ack.corr != hello.id) bad("hello_ack does not answer our hello")
        if (ack.device != hello.device) bad("hello_ack names another device")
        val p = ack.payload
        if ((p.keys - setOf("nonce", "version")).isNotEmpty()) bad("unknown hello_ack field")
        if ((p["version"] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull != Protocol.VERSION) {
            throw ProtocolException(ErrorCode.UNSUPPORTED_VERSION, "relay chose an unsupported version", ack.id)
        }
        val nonce = try {
            Base64.getDecoder().decode(p["nonce"]?.jsonPrimitive?.takeIf { it.isString }?.contentOrNull ?: bad("nonce missing"))
        } catch (e: IllegalArgumentException) {
            bad("nonce is not base64")
        }
        if (nonce.size != NONCE_BYTES) bad("nonce has the wrong length")
        return nonce
    }

    fun auth(deviceId: String, signature: ByteArray, now: Instant): Envelope = Envelope(
        v = Protocol.VERSION, type = MessageType.AUTH, id = UUID.randomUUID().toString(), corr = null, device = deviceId,
        ts = now, exp = null,
        payload = buildJsonObject { put("signature", Base64.getEncoder().encodeToString(signature)) },
    )

    fun heartbeat(deviceId: String, now: Instant): Envelope = Envelope(
        v = Protocol.VERSION, type = MessageType.HEARTBEAT, id = UUID.randomUUID().toString(), corr = null, device = deviceId,
        ts = now, exp = null, payload = JsonObject(emptyMap()),
    )
}
