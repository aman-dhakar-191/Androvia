package dev.androvia.core

import java.time.Duration
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put

/** Stable wire error codes. See docs/protocol/envelope.md. Never rename a [wire] value. */
enum class ErrorCode(val wire: String) {
    MALFORMED("malformed"),
    UNSUPPORTED_VERSION("unsupported_version"),
    UNSUPPORTED_MESSAGE("unsupported_message"),
    TOO_LARGE("too_large"),
    EXPIRED("expired"),
    REPLAYED("replayed"),
    UNKNOWN_CAPABILITY("unknown_capability"),
    CAPABILITY_UNAVAILABLE("capability_unavailable"),
    PERMISSION_REQUIRED("permission_required"),
    PERMISSION_DENIED("permission_denied"),
    INVALID_ARGS("invalid_args"),
    TIMEOUT("timeout"),
    CANCELLED("cancelled"),
    RATE_LIMITED("rate_limited"),
    INTERNAL("internal"),
}

enum class MessageType(val wire: String) {
    HELLO("hello"),
    HELLO_ACK("hello_ack"),
    HEARTBEAT("heartbeat"),
    COMMAND("command"),
    RESULT("result"),
    ERROR("error"),
    CANCEL("cancel"),
}

object Protocol {
    const val VERSION = 1
    const val MAX_MESSAGE_BYTES = 65_536
    val MAX_LIFETIME: Duration = Duration.ofSeconds(60)
    val MAX_CLOCK_SKEW: Duration = Duration.ofSeconds(30)
}

/** Raised for any protocol violation. [requestId] is set once the message id was parsed. */
class ProtocolException(
    val code: ErrorCode,
    message: String,
    val requestId: String? = null,
) : Exception(message)

data class Envelope(
    val v: Int,
    val type: MessageType,
    val id: String,
    val corr: String?,
    val device: String,
    val ts: Instant?,
    val exp: Instant?,
    val payload: JsonObject,
) {
    fun toJson(): String = JsonObject(
        buildMap<String, JsonElement> {
            put("v", JsonPrimitive(v))
            put("type", JsonPrimitive(type.wire))
            put("id", JsonPrimitive(id))
            corr?.let { put("corr", JsonPrimitive(it)) }
            put("device", JsonPrimitive(device))
            ts?.let { put("ts", JsonPrimitive(it.toString())) }
            exp?.let { put("exp", JsonPrimitive(it.toString())) }
            put("payload", payload)
        },
    ).toString()

    companion object {
        fun result(id: String, corr: String?, device: String, now: Instant, data: JsonObject) =
            Envelope(
                Protocol.VERSION, MessageType.RESULT, id, corr, device, now, null,
                buildJsonObject {
                    put("status", "ok")
                    put("data", data)
                },
            )

        fun error(id: String, corr: String?, device: String, now: Instant, code: ErrorCode, message: String) =
            Envelope(
                Protocol.VERSION, MessageType.ERROR, id, corr, device, now, null,
                buildJsonObject {
                    put("code", code.wire)
                    put("message", message)
                },
            )
    }
}

/** Strict envelope parser: unknown fields, wrong types and oversize input are rejected, never ignored. */
object EnvelopeParser {
    private val ALLOWED = setOf("v", "type", "id", "corr", "device", "ts", "exp", "payload")
    private val UUID_RE = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val DEVICE_RE = Regex("^[0-9a-f]{64}$")

    fun parse(raw: String): Envelope {
        if (raw.length > Protocol.MAX_MESSAGE_BYTES ||
            raw.toByteArray(Charsets.UTF_8).size > Protocol.MAX_MESSAGE_BYTES
        ) {
            throw ProtocolException(ErrorCode.TOO_LARGE, "message exceeds ${Protocol.MAX_MESSAGE_BYTES} bytes")
        }
        val root = try {
            Json.parseToJsonElement(raw)
        } catch (e: Exception) {
            throw ProtocolException(ErrorCode.MALFORMED, "not valid JSON")
        }
        if (root !is JsonObject) throw ProtocolException(ErrorCode.MALFORMED, "message must be a JSON object")

        // Pull the id first so that every later error can be correlated.
        val id = (root["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { UUID_RE.matches(it) }
        fun fail(code: ErrorCode, msg: String): Nothing = throw ProtocolException(code, msg, id)

        val unknown = root.keys - ALLOWED
        if (unknown.isNotEmpty()) fail(ErrorCode.MALFORMED, "unknown field")
        if (id == null) fail(ErrorCode.MALFORMED, "id must be a UUID")

        val vPrim = root["v"] as? JsonPrimitive
        val v = if (vPrim == null || vPrim.isString) null else vPrim.intOrNull
        if (v == null) fail(ErrorCode.MALFORMED, "v must be an integer")
        if (v != Protocol.VERSION) fail(ErrorCode.UNSUPPORTED_VERSION, "unsupported protocol version")

        val typeStr = (root["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: fail(ErrorCode.MALFORMED, "type must be a string")
        val type = MessageType.entries.firstOrNull { it.wire == typeStr }
            ?: fail(ErrorCode.UNSUPPORTED_MESSAGE, "unknown message type")

        val corr = if ("corr" in root) {
            (root["corr"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { UUID_RE.matches(it) }
                ?: fail(ErrorCode.MALFORMED, "corr must be a UUID")
        } else {
            null
        }
        if (type == MessageType.COMMAND && corr != null) fail(ErrorCode.MALFORMED, "command must not carry corr")
        if (type in setOf(MessageType.RESULT, MessageType.ERROR, MessageType.CANCEL) && corr == null) {
            fail(ErrorCode.MALFORMED, "corr is required")
        }

        val device = (root["device"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { DEVICE_RE.matches(it) }
            ?: fail(ErrorCode.MALFORMED, "device must be 64 lowercase hex characters")

        fun instant(name: String, required: Boolean): Instant? {
            val el = root[name]
            if (el == null) {
                if (required) fail(ErrorCode.MALFORMED, "$name is required")
                return null
            }
            val s = (el as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: fail(ErrorCode.MALFORMED, "$name must be an ISO-8601 instant")
            return try {
                Instant.parse(s)
            } catch (e: Exception) {
                fail(ErrorCode.MALFORMED, "$name must be an ISO-8601 instant")
            }
        }
        val timed = type == MessageType.COMMAND || type == MessageType.CANCEL
        val ts = instant("ts", timed)
        val exp = instant("exp", timed)

        val payload = root["payload"] as? JsonObject ?: fail(ErrorCode.MALFORMED, "payload must be an object")
        return Envelope(v, type, id, corr, device, ts, exp, payload)
    }
}

internal fun JsonElement.asStringOrNull(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content

internal fun JsonElement.asStringList(): List<String>? =
    (this as? JsonArray)?.map { it.asStringOrNull() ?: return null }
