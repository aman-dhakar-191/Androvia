package dev.androvia.capabilities

import dev.androvia.core.Availability
import dev.androvia.core.Capability
import dev.androvia.core.CapabilityDescriptor
import dev.androvia.core.CapabilityResult
import dev.androvia.core.Sensitivity
import java.time.Duration
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Non-identifying build facts. Deliberately excludes serials, IMEI, MAC/IP addresses and installed apps. */
data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val androidRelease: String,
    val sdkInt: Int,
    val securityPatch: String?,
    val supportedAbis: List<String>,
)

fun interface DeviceInfoSource {
    fun read(): DeviceInfo
}

class DeviceInfoCapability(private val source: DeviceInfoSource) : Capability {
    override val descriptor = CapabilityDescriptor(
        id = ID,
        version = 1,
        description = "Basic, non-identifying device and OS build information.",
        scopes = setOf("device.info:read"),
        sensitivity = Sensitivity.LOW,
        outputDescription = "manufacturer, model, android_release, sdk_int, security_patch, supported_abis",
        timeout = Duration.ofSeconds(5),
        cancellable = false,
    )

    // Needs no Android permission and is available on every supported OS version.
    override fun availability() = Availability.Available

    override suspend fun execute(args: JsonObject): CapabilityResult {
        val info = source.read()
        return CapabilityResult.Ok(
            buildJsonObject {
                put("manufacturer", info.manufacturer)
                put("model", info.model)
                put("android_release", info.androidRelease)
                put("sdk_int", info.sdkInt)
                info.securityPatch?.let { put("security_patch", it) }
                put("supported_abis", kotlinx.serialization.json.JsonArray(info.supportedAbis.map { kotlinx.serialization.json.JsonPrimitive(it) }))
            },
        )
    }

    companion object {
        const val ID = "device.info"
    }
}
