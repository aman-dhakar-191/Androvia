package dev.androvia.app

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dev.androvia.api.RelayConnectionState
import dev.androvia.core.RelayState
import dev.androvia.core.RuntimeStatus
import dev.androvia.core.RuntimeStatusResolver
import dev.androvia.runtime.CapabilityConfigDao
import dev.androvia.runtime.CapabilityConfigEntity
import dev.androvia.runtime.CapabilityStatus
import dev.androvia.runtime.RelayConfigDao
import dev.androvia.runtime.RelayConfigEntity
import dev.androvia.runtime.RelayStateStore
import dev.androvia.runtime.LocalRuntime
import dev.androvia.runtime.RuntimeController
import dev.androvia.runtime.RuntimeStateStore
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class UiState(
    val status: RuntimeStatus = RuntimeStatus.STOPPED,
    val deviceId: String? = null,
    val keyLevel: String? = null,
    val capabilities: List<CapabilityStatus> = emptyList(),
    val notificationsEnabled: Boolean = true,
    val startError: String? = null,
    val selfTestOutput: String? = null,
    val publicKeyB64: String? = null,
    val relayLoaded: Boolean = false,
    val relayUrl: String = "",
    val relayEnabled: Boolean = false,
    val relay: RelayConnectionState = RelayConnectionState(RelayState.NOT_CONFIGURED),
)

@HiltViewModel
class MainViewModel @Inject constructor(
    private val runtime: LocalRuntime,
    private val controller: RuntimeController,
    private val store: RuntimeStateStore,
    private val configDao: CapabilityConfigDao,
    private val relayConfigDao: RelayConfigDao,
    private val relayStore: RelayStateStore,
) : ViewModel() {
    private data class Extras(
        val deviceId: String?,
        val keyLevel: String?,
        val notifications: Boolean,
        val selfTest: String?,
        val publicKeyB64: String?,
    )

    private val extras = MutableStateFlow(Extras(null, null, true, null, null))

    private val core = combine(store.serviceRunning, configDao.observeAll(), store.lastStartError, extras) { running, configs, startError, x ->
        Core(running, configs, startError, x)
    }

    private data class Core(val running: Boolean, val configs: List<dev.androvia.runtime.CapabilityConfigEntity>, val startError: String?, val x: Extras)

    val state: StateFlow<UiState> = combine(core, relayConfigDao.observe(), relayStore.state) { c, relayCfg, relay ->
        val running = c.running
        val configs = c.configs
        val startError = c.startError
        val x = c.x
        val enabled = configs.filter { it.enabled }.map { it.capabilityId }.toSet()
        UiState(
            status = RuntimeStatusResolver.resolve(running, x.notifications, relay.relay),
            deviceId = x.deviceId,
            keyLevel = x.keyLevel,
            capabilities = runtime.statuses(enabled),
            notificationsEnabled = x.notifications,
            startError = startError,
            selfTestOutput = x.selfTest,
            publicKeyB64 = x.publicKeyB64,
            relayLoaded = true,
            relayUrl = relayCfg?.url.orEmpty(),
            relayEnabled = relayCfg?.enabled ?: false,
            relay = relay,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UiState())

    init {
        viewModelScope.launch {
            val id = runtime.identity()
            extras.update {
                it.copy(
                    deviceId = id.deviceId,
                    keyLevel = id.securityLevel.name,
                    publicKeyB64 = java.util.Base64.getEncoder().encodeToString(id.publicKeySpki),
                )
            }
        }
    }

    fun refreshNotifications(context: Context) =
        extras.update { it.copy(notifications = controller.notificationsEnabled(context)) }

    fun start(context: Context) = controller.start(context)
    fun stop(context: Context) = controller.stop(context)

    /** Saves the relay address and on/off switch. Nothing connects until the runtime is also running. */
    fun saveRelay(url: String, enabled: Boolean) {
        viewModelScope.launch { relayConfigDao.upsert(RelayConfigEntity(url = url.trim(), enabled = enabled)) }
    }

    fun setEnabled(capabilityId: String, enabled: Boolean) {
        viewModelScope.launch { configDao.upsert(CapabilityConfigEntity(capabilityId, enabled)) }
    }

    /** Sends a real, well-formed command through the dispatcher, so denials and results come from the real code path. */
    fun selfTest(capabilityId: String) {
        viewModelScope.launch {
            val response = runtime.dispatch(runtime.buildLocalCommand(capabilityId))
            extras.update { it.copy(selfTest = response.toJson()) }
        }
    }
}
