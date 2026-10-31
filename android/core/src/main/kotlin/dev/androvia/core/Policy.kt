package dev.androvia.core

sealed interface PolicyDecision {
    data object Allow : PolicyDecision
    data class Deny(val reason: String) : PolicyDecision
}

/** Device-side authorization. Evaluated for every command, independent of anything the relay claims. */
fun interface LocalPolicy {
    suspend fun evaluate(descriptor: CapabilityDescriptor): PolicyDecision
}

/** Default: nothing is allowed. */
data object DenyAllPolicy : LocalPolicy {
    override suspend fun evaluate(descriptor: CapabilityDescriptor) = PolicyDecision.Deny("denied by default")
}

/**
 * Allows only capabilities the user explicitly enabled. Anything above [Sensitivity.LOW] is denied for now because
 * the user-confirmation flow does not exist yet; this fails closed.
 */
class EnabledSetPolicy(private val enabledIds: suspend () -> Set<String>) : LocalPolicy {
    override suspend fun evaluate(descriptor: CapabilityDescriptor): PolicyDecision = when {
        descriptor.id !in enabledIds() -> PolicyDecision.Deny("capability is not enabled on this device")
        descriptor.sensitivity != Sensitivity.LOW ->
            PolicyDecision.Deny("capability requires user confirmation, which is not implemented")
        else -> PolicyDecision.Allow
    }
}
