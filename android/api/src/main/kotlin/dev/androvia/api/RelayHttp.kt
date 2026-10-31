package dev.androvia.api

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.websocket.WebSockets

/**
 * HTTP client for the relay connection.
 *
 * Liveness is handled by the protocol heartbeat, so the transport-level ping is off. Certificates are verified against
 * the system trust store. The OkHttp engine does not support Ktor's `maxFrameSize`, so the 64 KiB message limit is
 * enforced when messages are parsed (EnvelopeParser rejects anything larger and the client never acts on it).
 */
fun createRelayHttpClient(): HttpClient = HttpClient(OkHttp) {
    install(WebSockets) {
        pingIntervalMillis = 0
    }
}
