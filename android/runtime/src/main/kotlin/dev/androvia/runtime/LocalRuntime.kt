package dev.androvia.runtime

import dev.androvia.authentication.DeviceIdentity
import dev.androvia.authentication.DeviceKeys
import dev.androvia.core.Availability
import dev.androvia.core.CapabilityDescriptor
import dev.androvia.core.CapabilityRegistry
import dev.androvia.core.CommandDispatcher
import dev.androvia.core.Envelope
import dev.androvia.core.LocalPolicy
import dev.androvia.core.MessageType
import dev.androvia.core.Protocol
import dev.androvia.core.ReplayGuard
import java.time.Clock
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class CapabilityStatus(
    val descriptor: CapabilityDescriptor,
    val availability: Availability,
    val enabled: Boolean,
)

/**
 * The local runtime boundary: device identity + capability registry + dispatcher.
 * Phase 1 has no network transport; commands enter only through [dispatch] (UI self-test and tests).
 */
@Singleton
class LocalRuntime @Inject constructor(
    private val keys: DeviceKeys,
    val registry: CapabilityRegistry,
    policy: LocalPolicy,
    private val clock: Clock,
) {
    private val identityLock = Mutex()
    private var cached: DeviceIdentity? = null

    suspend fun identity(): DeviceIdentity = identityLock.withLock {
        cached ?: withContext(Dispatchers.IO) { keys.identity() }.also { cached = it }
    }

    private val dispatcher = CommandDispatcher(registry, policy, ReplayGuard(clock), clock) { identity().deviceId }

    suspend fun dispatch(raw: String): Envelope = dispatcher.dispatch(raw)

    fun statuses(enabledIds: Set<String>): List<CapabilityStatus> =
        registry.all().map { CapabilityStatus(it.descriptor, it.availability(), it.descriptor.id in enabledIds) }

    /** Builds a well-formed, short-lived command addressed to this device (used by the UI self-test and tests). */
    suspend fun buildLocalCommand(capabilityId: String, version: Int = 1, args: JsonObject = JsonObject(emptyMap())): String {
        val now = clock.instant()
        return Envelope(
            v = Protocol.VERSION,
            type = MessageType.COMMAND,
            id = UUID.randomUUID().toString(),
            corr = null,
            device = identity().deviceId,
            ts = now,
            exp = now.plusSeconds(30),
            payload = buildJsonObject {
                put("capability", capabilityId)
                put("version", version)
                put("args", args)
            },
        ).toJson()
    }
}
