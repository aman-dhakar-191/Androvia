package dev.androvia.api

import dev.androvia.capabilities.DeviceInfo
import dev.androvia.capabilities.DeviceInfoCapability
import dev.androvia.core.CapabilityRegistry
import dev.androvia.core.CommandDispatcher
import dev.androvia.core.DeviceId
import dev.androvia.core.EnabledSetPolicy
import dev.androvia.core.Envelope
import dev.androvia.core.MessageType
import dev.androvia.core.Protocol
import dev.androvia.core.ReplayGuard
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** A JVM stand-in for the Android Keystore key: EC P-256, SHA256withECDSA, DER signatures, SPKI public key. */
class TestDevice {
    val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    val spki: ByteArray = keyPair.public.encoded
    val id: String = DeviceId.fromPublicKeyDer(spki)
    val publicKeyB64: String = Base64.getEncoder().encodeToString(spki)

    val signer = object : RelaySigner {
        override suspend fun deviceId() = id
        override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(data)
            sign()
        }
    }

    fun commandJson(capability: String = "device.info", version: Int = 1, args: JsonObject = JsonObject(emptyMap()), id: String = UUID.randomUUID().toString()): String {
        val now = Instant.now()
        return Envelope(
            Protocol.VERSION, MessageType.COMMAND, id, null, this.id, now, now.plusSeconds(30),
            buildJsonObject {
                put("capability", capability)
                put("version", version)
                put("args", args)
            },
        ).toJson()
    }

    fun dispatcher(enabled: Set<String>): suspend (String) -> Envelope {
        val clock = Clock.systemUTC()
        val d = CommandDispatcher(
            CapabilityRegistry(listOf(DeviceInfoCapability { DeviceInfo("Acme", "Phone 1", "16", 36, "2026-10-01", listOf("arm64-v8a")) })),
            EnabledSetPolicy { enabled }, ReplayGuard(clock), clock,
        ) { id }
        return { raw -> d.dispatch(raw) }
    }
}
