package dev.androvia.core

import java.security.MessageDigest
import java.time.Duration
import kotlin.random.Random

/** The device id is the hex SHA-256 of the DER (X.509 SubjectPublicKeyInfo) public key, so it cannot be claimed without the key. */
object DeviceId {
    fun fromPublicKeyDer(spki: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(spki).joinToString("") { "%02x".format(it) }
}

/** Bounded exponential backoff with "equal jitter": half the ceiling is fixed, half is random, so delay is never 0. */
class ExponentialBackoff(
    private val base: Duration = Duration.ofSeconds(1),
    private val cap: Duration = Duration.ofSeconds(60),
    private val random: Random = Random.Default,
) {
    init {
        require(!base.isNegative && !base.isZero && base <= cap) { "invalid backoff bounds" }
    }

    /** [attempt] starts at 0 for the first retry. */
    fun delayFor(attempt: Int): Duration {
        val shift = attempt.coerceIn(0, 30)
        val ceilingMs = minOf(cap.toMillis(), base.toMillis() * (1L shl shift))
        val half = ceilingMs / 2
        return Duration.ofMillis(half + if (ceilingMs - half > 0) random.nextLong(ceilingMs - half + 1) else 0)
    }
}

enum class RuntimeStatus { STOPPED, OFFLINE, RECONNECTING, CONNECTED, PERMISSION_LIMITED }

/** FAILED: the connection stopped and needs attention (revoked, replaced, invalid address). */
enum class RelayState { NOT_CONFIGURED, RECONNECTING, CONNECTED, FAILED }

object RuntimeStatusResolver {
    /** PERMISSION_LIMITED means the service runs but its notification is hidden because the permission was denied. */
    fun resolve(serviceRunning: Boolean, notificationsGranted: Boolean, relay: RelayState): RuntimeStatus = when {
        !serviceRunning -> RuntimeStatus.STOPPED
        !notificationsGranted -> RuntimeStatus.PERMISSION_LIMITED
        relay == RelayState.CONNECTED -> RuntimeStatus.CONNECTED
        relay == RelayState.RECONNECTING -> RuntimeStatus.RECONNECTING
        else -> RuntimeStatus.OFFLINE
    }
}
