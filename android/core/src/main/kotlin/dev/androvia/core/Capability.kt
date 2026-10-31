package dev.androvia.core

import java.time.Duration
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

enum class FieldType { STRING, INTEGER, BOOLEAN }

data class FieldSpec(
    val type: FieldType,
    val required: Boolean = false,
    val maxLength: Int = 256,
    val min: Long? = null,
    val max: Long? = null,
)

/** Minimal closed-object schema: unknown fields are rejected. */
class ObjectSchema(val fields: Map<String, FieldSpec> = emptyMap()) {
    /** Returns null when [args] is valid, otherwise a short message that is safe to return to the caller. */
    fun validate(args: JsonObject): String? {
        for (key in args.keys) if (key !in fields) return "unknown argument '$key'"
        for ((name, spec) in fields) {
            val value = args[name]
            if (value == null) {
                if (spec.required) return "missing argument '$name'"
                continue
            }
            val p = value as? JsonPrimitive ?: return "argument '$name' has wrong type"
            when (spec.type) {
                FieldType.STRING -> {
                    if (!p.isString) return "argument '$name' must be a string"
                    if (p.content.length > spec.maxLength) return "argument '$name' is too long"
                }
                FieldType.BOOLEAN -> if (p.isString || (p.content != "true" && p.content != "false")) {
                    return "argument '$name' must be a boolean"
                }
                FieldType.INTEGER -> {
                    val n = if (p.isString) null else p.longOrNull
                    if (n == null) return "argument '$name' must be an integer"
                    if (spec.min != null && n < spec.min) return "argument '$name' is below the minimum"
                    if (spec.max != null && n > spec.max) return "argument '$name' is above the maximum"
                }
            }
        }
        return null
    }
}

enum class Sensitivity {
    /** Read-only, non-identifying. */
    LOW,

    /** Reads personal data or uses a sensor. Needs explicit user enablement and confirmation (not built yet). */
    SENSITIVE,

    /** Changes device state or has outward effects. */
    HIGH_IMPACT,
}

/** Everything a capability must declare (spec §7). */
data class CapabilityDescriptor(
    val id: String,
    val version: Int,
    val description: String,
    val requiredAndroidPermissions: Set<String> = emptySet(),
    val requiredSpecialAccess: Set<String> = emptySet(),
    val requiresUserInteraction: Boolean = false,
    val minSdk: Int = 29,
    val scopes: Set<String>,
    val sensitivity: Sensitivity,
    val argsSchema: ObjectSchema = ObjectSchema(),
    val outputDescription: String,
    val timeout: Duration = Duration.ofSeconds(10),
    val cancellable: Boolean = true,
)

sealed interface Availability {
    data object Available : Availability
    data class Unavailable(val reason: String) : Availability
    data class PermissionRequired(val permissions: Set<String>) : Availability
}

sealed interface CapabilityResult {
    data class Ok(val data: JsonObject) : CapabilityResult
    data class Failure(val code: ErrorCode, val message: String) : CapabilityResult
}

interface Capability {
    val descriptor: CapabilityDescriptor

    /** Must report [Availability.Unavailable] / [Availability.PermissionRequired] rather than pretend success. */
    fun availability(): Availability

    /** Called only after validation, policy and availability checks. Must honour coroutine cancellation. */
    suspend fun execute(args: JsonObject): CapabilityResult
}

/** Fixed allowlist of capabilities. Nothing is exposed that is not registered here. */
class CapabilityRegistry(capabilities: List<Capability>) {
    private val byId: Map<String, Capability>

    init {
        val map = LinkedHashMap<String, Capability>()
        for (c in capabilities) {
            val id = c.descriptor.id
            require(ID_RE.matches(id)) { "invalid capability id '$id'" }
            require(c.descriptor.scopes.isNotEmpty()) { "capability '$id' declares no scopes" }
            require(map.put(id, c) == null) { "duplicate capability id '$id'" }
        }
        byId = map
    }

    operator fun get(id: String): Capability? = byId[id]

    fun all(): List<Capability> = byId.values.toList()

    private companion object {
        val ID_RE = Regex("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$")
    }
}
