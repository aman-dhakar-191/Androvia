package dev.androvia.core

import java.time.Clock
import java.time.Instant

/** Remembers command ids until they expire, so a captured command cannot be delivered twice. Thread-safe. */
class ReplayGuard(private val clock: Clock, private val maxEntries: Int = 4096) {
    enum class Result { ACCEPTED, REPLAYED, FULL }

    private val seen = HashMap<String, Instant>()

    @Synchronized
    fun checkAndRecord(id: String, expiresAt: Instant): Result {
        val now = clock.instant()
        if (seen.size >= maxEntries / 2) seen.values.removeAll { !it.isAfter(now) }
        if (seen.containsKey(id)) return Result.REPLAYED
        if (seen.size >= maxEntries) return Result.FULL
        seen[id] = expiresAt
        return Result.ACCEPTED
    }
}
