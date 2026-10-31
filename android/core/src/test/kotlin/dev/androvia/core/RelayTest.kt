package dev.androvia.core

import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

private val DEV = "a".repeat(64)
private val NOW = Instant.parse("2026-10-31T12:00:00Z")

class RelayEndpointTest {
    @Test fun `accepts a wss origin and builds the websocket url`() {
        val e = RelayEndpoint.parse("wss://relay.example.com")
        assertEquals("wss://relay.example.com", e.origin)
        assertEquals("wss://relay.example.com/v1/device/ws", e.wsUrl)
    }

    @Test fun `normalises case, whitespace, trailing slash and keeps the port`() {
        assertEquals("wss://relay.example.com:8443", RelayEndpoint.parse("  WSS://Relay.Example.COM:8443/ ").origin)
    }

    @Test fun `rejects everything that is not a plain wss origin`() {
        val bad = listOf(
            "", "   ", "relay.example.com", "https://relay.example.com", "http://relay.example.com", "ws://relay.example.com",
            "wss://", "wss://user:pw@relay.example.com", "wss://relay.example.com/path", "wss://relay.example.com?x=1",
            "wss://relay.example.com#frag", "wss://relay.example.com:0", "wss://relay.example.com:99999", "wss://exa mple.com",
            "ftp://relay.example.com", "wss:relay.example.com",
        )
        for (b in bad) assertFailsWith<IllegalArgumentException>("accepted: '$b'") { RelayEndpoint.parse(b) }
    }

    @Test fun `ws is refused unless explicitly allowed for tests`() {
        assertFailsWith<IllegalArgumentException> { RelayEndpoint.parse("ws://localhost:8443") }
        assertEquals("ws://localhost:8443", RelayEndpoint.parse("ws://localhost:8443", allowInsecure = true).origin)
    }

    @Test fun `config rules`() {
        assertEquals(RelayConfigState.NotConfigured, RelayConfigRules.resolve("wss://r.example.com", enabled = false))
        assertEquals(RelayConfigState.NotConfigured, RelayConfigRules.resolve("", enabled = false))
        assertIs<RelayConfigState.Invalid>(RelayConfigRules.resolve("", enabled = true))
        assertIs<RelayConfigState.Invalid>(RelayConfigRules.resolve("http://x", enabled = true))
        assertIs<RelayConfigState.Ready>(RelayConfigRules.resolve("wss://r.example.com", enabled = true))
    }
}

class RelayHandshakeTest {
    private val hello = RelayHandshake.hello(DEV, "0.1.0", NOW)

    private fun ack(
        corr: String = hello.id, device: String = DEV, nonce: String = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() }),
        version: String = "1", extra: String = "", type: String = "hello_ack",
    ) = """{"v":1,"type":"$type","id":"${java.util.UUID.randomUUID()}","corr":"$corr","device":"$device","ts":"2026-10-31T12:00:00Z","payload":{"nonce":"$nonce","version":$version$extra}}"""

    @Test fun `hello is a valid envelope`() {
        val parsed = EnvelopeParser.parse(hello.toJson())
        assertEquals(MessageType.HELLO, parsed.type)
        assertTrue(parsed.payload["versions"].toString().contains("1"))
    }

    @Test fun `parses a good hello_ack`() {
        assertContentEquals(ByteArray(32) { it.toByte() }, RelayHandshake.parseHelloAck(ack(), hello))
    }

    @Test fun `rejects bad hello_ack`() {
        val cases = mapOf(
            "wrong type" to ack(type = "heartbeat"),
            "answers another hello" to ack(corr = java.util.UUID.randomUUID().toString()),
            "another device" to ack(device = "b".repeat(64)),
            "short nonce" to ack(nonce = Base64.getEncoder().encodeToString(ByteArray(16))),
            "long nonce" to ack(nonce = Base64.getEncoder().encodeToString(ByteArray(64))),
            "nonce not base64" to ack(nonce = "!!!"),
            "unknown field" to ack(extra = ""","admin":true"""),
            "not json" to "nope",
        )
        for ((name, text) in cases) assertFailsWith<ProtocolException>(name) { RelayHandshake.parseHelloAck(text, hello) }
        assertFailsWith<ProtocolException>("version 2") { RelayHandshake.parseHelloAck(ack(version = "2"), hello) }
        assertFailsWith<ProtocolException>("version as string") { RelayHandshake.parseHelloAck(ack(version = "\"1\""), hello) }
    }

    @Test fun `auth message layout matches the documented bytes`() {
        val nonce = ByteArray(32) { 7 }
        val m = RelayHandshake.authMessage(nonce, DEV, "wss://r.example.com")
        val prefix = "androvia/relay-auth/v1\u0000".toByteArray()
        assertContentEquals(prefix, m.copyOfRange(0, prefix.size))
        assertContentEquals(nonce, m.copyOfRange(prefix.size, prefix.size + 32))
        assertEquals(DEV + "wss://r.example.com", String(m, prefix.size + 32, m.size - prefix.size - 32))
    }

    @Test fun `auth and heartbeat parse as envelopes`() {
        val auth = EnvelopeParser.parse(RelayHandshake.auth(DEV, byteArrayOf(1, 2, 3), NOW).toJson())
        assertEquals(MessageType.AUTH, auth.type)
        assertEquals(MessageType.HEARTBEAT, EnvelopeParser.parse(RelayHandshake.heartbeat(DEV, NOW).toJson()).type)
    }
}
