package dev.androvia.runtime

import android.util.Log
import dev.androvia.api.RelayClient
import dev.androvia.api.RelayClientConfig
import dev.androvia.api.RelayConnectionState
import dev.androvia.api.RelaySigner
import dev.androvia.api.createRelayHttpClient
import dev.androvia.core.ExponentialBackoff
import dev.androvia.core.RelayConfigRules
import dev.androvia.core.RelayConfigState
import dev.androvia.core.RelayEndpoint
import dev.androvia.core.RelayState
import java.time.Clock
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/** What the UI shows about the relay connection. */
@Singleton
class RelayStateStore @Inject constructor() {
    private val _state = MutableStateFlow(RelayConnectionState(RelayState.NOT_CONFIGURED))
    val state: StateFlow<RelayConnectionState> = _state.asStateFlow()

    fun set(s: RelayConnectionState) {
        _state.value = s
    }

    fun reset() = set(RelayConnectionState(RelayState.NOT_CONFIGURED))
}

/**
 * Connects to the relay the user configured, for as long as [runWhileActive] is running. The foreground service runs it,
 * so there is no connection (and no way for the relay to reach this device) while the runtime is stopped.
 *
 * Nothing connects unless the user entered a wss:// address AND switched the relay on.
 */
@Singleton
class RelayConnector @Inject constructor(
    private val runtime: LocalRuntime,
    private val configDao: RelayConfigDao,
    private val store: RelayStateStore,
    private val clock: Clock,
) {
    private val signer = object : RelaySigner {
        override suspend fun deviceId(): String = runtime.identity().deviceId
        override suspend fun sign(data: ByteArray): ByteArray = runtime.sign(data)
    }

    suspend fun runWhileActive() {
        configDao.observe().distinctUntilChanged().collectLatest { cfg ->
            // collectLatest cancels the previous connection whenever the setting changes.
            when (val rule = RelayConfigRules.resolve(cfg?.url.orEmpty(), cfg?.enabled ?: false)) {
                RelayConfigState.NotConfigured -> store.reset()
                is RelayConfigState.Invalid -> store.set(RelayConnectionState(RelayState.FAILED, rule.message, terminal = true))
                is RelayConfigState.Ready -> connect(rule.endpoint)
            }
        }
    }

    private suspend fun connect(endpoint: RelayEndpoint) = coroutineScope {
        val http = createRelayHttpClient()
        try {
            val client = RelayClient(
                http = http,
                signer = signer,
                handler = runtime::dispatch, // the device's own dispatcher: schema checks, replay guard, local policy
                clock = clock,
                backoff = ExponentialBackoff(),
                config = RelayClientConfig(appVersion = "androvia-android"),
                log = { Log.i(TAG, it) }, // messages never contain keys, signatures or command arguments
            )
            val forward = launch { client.state.collect { store.set(it) } }
            try {
                client.run(endpoint)
            } finally {
                store.set(client.state.value) // make sure a final (e.g. terminal) state is not lost to cancellation of `forward`
                forward.cancel()
            }
        } finally {
            http.close()
        }
    }

    private companion object {
        const val TAG = "AndroviaRelay"
    }
}
