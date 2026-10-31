package dev.androvia.runtime

import android.os.Build
import dev.androvia.capabilities.DeviceInfo
import dev.androvia.capabilities.DeviceInfoSource
import dev.androvia.core.EnabledSetPolicy
import java.time.Clock
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map

object AndroidDeviceInfoSource : DeviceInfoSource {
    override fun read() = DeviceInfo(
        manufacturer = Build.MANUFACTURER,
        model = Build.MODEL,
        androidRelease = Build.VERSION.RELEASE,
        sdkInt = Build.VERSION.SDK_INT,
        securityPatch = Build.VERSION.SECURITY_PATCH.takeIf { it.isNotBlank() },
        supportedAbis = Build.SUPPORTED_ABIS.toList(),
    )
}

fun roomPolicy(dao: CapabilityConfigDao) = EnabledSetPolicy { dao.enabledIds().toSet() }

@Singleton
class RuntimeStateStore @Inject constructor(
    private val dao: RuntimeStateDao,
    private val clock: Clock,
) {
    val serviceRunning: Flow<Boolean> = dao.observe().map { it?.serviceRunning ?: false }

    private val _lastStartError = MutableStateFlow<String?>(null)
    val lastStartError: StateFlow<String?> = _lastStartError.asStateFlow()

    suspend fun setServiceRunning(running: Boolean) {
        dao.upsert(RuntimeStateEntity(serviceRunning = running, updatedAtEpochMs = clock.millis()))
        if (running) _lastStartError.value = null
    }

    fun reportStartFailure(message: String) {
        _lastStartError.value = message
    }
}
