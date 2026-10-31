package dev.androvia.core

import java.time.Clock
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject

/**
 * Local command boundary. Takes a raw message, returns the response envelope; never throws for bad input.
 * Order: size/shape → type → target device → time window → replay → capability → policy → availability → args → execute.
 * Nothing in the message grants authority; `scopes_claimed` is ignored.
 */
class CommandDispatcher(
    private val registry: CapabilityRegistry,
    private val policy: LocalPolicy,
    private val replayGuard: ReplayGuard,
    private val clock: Clock,
    private val deviceId: suspend () -> String,
) {
    private val allowedPayloadKeys = setOf("capability", "version", "scopes_claimed", "args")

    suspend fun dispatch(raw: String): Envelope {
        val self = deviceId()
        var corr: String? = null
        try {
            val env = EnvelopeParser.parse(raw)
            corr = env.id
            if (env.type != MessageType.COMMAND) {
                throw ProtocolException(ErrorCode.UNSUPPORTED_MESSAGE, "only command messages are handled here", env.id)
            }
            if (env.device != self) {
                throw ProtocolException(ErrorCode.PERMISSION_DENIED, "command is not addressed to this device", env.id)
            }
            val now = clock.instant()
            val ts = env.ts!!
            val exp = env.exp!!
            if (exp <= ts || java.time.Duration.between(ts, exp) > Protocol.MAX_LIFETIME) {
                throw ProtocolException(ErrorCode.MALFORMED, "invalid validity window", env.id)
            }
            if (!exp.isAfter(now) || ts.isAfter(now.plus(Protocol.MAX_CLOCK_SKEW))) {
                throw ProtocolException(ErrorCode.EXPIRED, "command is expired or not yet valid", env.id)
            }

            val p = env.payload
            if ((p.keys - allowedPayloadKeys).isNotEmpty()) {
                throw ProtocolException(ErrorCode.MALFORMED, "unknown payload field", env.id)
            }
            val capId = p["capability"]?.asStringOrNull()
                ?: throw ProtocolException(ErrorCode.MALFORMED, "capability must be a string", env.id)
            val version = (p["version"] as? kotlinx.serialization.json.JsonPrimitive)
                ?.takeIf { !it.isString }?.content?.toIntOrNull()
                ?: throw ProtocolException(ErrorCode.MALFORMED, "version must be an integer", env.id)
            if (p["scopes_claimed"] != null && p["scopes_claimed"]!!.asStringList() == null) {
                throw ProtocolException(ErrorCode.MALFORMED, "scopes_claimed must be a list of strings", env.id)
            }
            val args = when (val a = p["args"]) {
                null -> JsonObject(emptyMap())
                is JsonObject -> a
                else -> throw ProtocolException(ErrorCode.MALFORMED, "args must be an object", env.id)
            }

            // Replay is recorded only for otherwise well-formed, in-window commands.
            when (replayGuard.checkAndRecord(env.id, exp)) {
                ReplayGuard.Result.ACCEPTED -> Unit
                ReplayGuard.Result.REPLAYED -> throw ProtocolException(ErrorCode.REPLAYED, "duplicate command id", env.id)
                ReplayGuard.Result.FULL -> throw ProtocolException(ErrorCode.RATE_LIMITED, "too many pending commands", env.id)
            }

            val capability = registry[capId]
            if (capability == null || capability.descriptor.version != version) {
                throw ProtocolException(ErrorCode.UNKNOWN_CAPABILITY, "unknown capability or version", env.id)
            }
            val d = capability.descriptor

            when (val decision = policy.evaluate(d)) {
                PolicyDecision.Allow -> Unit
                is PolicyDecision.Deny -> throw ProtocolException(ErrorCode.PERMISSION_DENIED, decision.reason, env.id)
            }
            when (val a = capability.availability()) {
                Availability.Available -> Unit
                is Availability.Unavailable ->
                    throw ProtocolException(ErrorCode.CAPABILITY_UNAVAILABLE, a.reason, env.id)
                is Availability.PermissionRequired ->
                    throw ProtocolException(ErrorCode.PERMISSION_REQUIRED, "missing Android permission", env.id)
            }
            d.argsSchema.validate(args)?.let { throw ProtocolException(ErrorCode.INVALID_ARGS, it, env.id) }

            val result = try {
                withTimeout(d.timeout.toMillis()) { capability.execute(args) }
            } catch (e: TimeoutCancellationException) {
                throw ProtocolException(ErrorCode.TIMEOUT, "capability timed out", env.id)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Details are deliberately not returned: they may contain device data.
                throw ProtocolException(ErrorCode.INTERNAL, "capability failed", env.id)
            }
            return when (result) {
                is CapabilityResult.Failure -> error(env.id, result.code, result.message, self)
                is CapabilityResult.Ok -> {
                    val response = Envelope.result(newId(), env.id, self, clock.instant(), result.data)
                    if (response.toJson().toByteArray(Charsets.UTF_8).size > Protocol.MAX_MESSAGE_BYTES) {
                        error(env.id, ErrorCode.INTERNAL, "result too large", self)
                    } else {
                        response
                    }
                }
            }
        } catch (e: ProtocolException) {
            return error(e.requestId ?: corr, e.code, e.message ?: e.code.wire, self)
        }
    }

    private fun error(corr: String?, code: ErrorCode, message: String, self: String) =
        Envelope.error(newId(), corr, self, clock.instant(), code, message)

    private fun newId() = UUID.randomUUID().toString()
}
