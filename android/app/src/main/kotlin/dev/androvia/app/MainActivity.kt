package dev.androvia.app

import android.Manifest
import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import dev.androvia.core.Availability
import dev.androvia.core.RuntimeStatus

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) { StatusScreen(vm) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        vm.refreshNotifications(this)
    }
}

private fun statusText(s: RuntimeStatus) = when (s) {
    RuntimeStatus.STOPPED -> "Stopped"
    RuntimeStatus.OFFLINE -> "Running locally, no relay configured"
    RuntimeStatus.RECONNECTING -> "Reconnecting to relay"
    RuntimeStatus.CONNECTED -> "Connected to relay"
    RuntimeStatus.PERMISSION_LIMITED -> "Running, but notifications are blocked (permission-limited)"
}

@Composable
private fun StatusScreen(vm: MainViewModel) {
    val context: Context = LocalContext.current
    val ui by vm.state.collectAsStateWithLifecycle()
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        vm.refreshNotifications(context)
        vm.start(context)
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Androvia", style = MaterialTheme.typography.headlineMedium)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Runtime", style = MaterialTheme.typography.titleMedium)
                Text(statusText(ui.status))
                ui.startError?.let { Text("Could not start: $it", color = MaterialTheme.colorScheme.error) }
                if (!ui.notificationsEnabled) {
                    Text("Notifications are off, so the runtime's notification is hidden from the shade. Allow them in system settings.")
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        enabled = ui.status == RuntimeStatus.STOPPED,
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !ui.notificationsEnabled) {
                                notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                vm.start(context)
                            }
                        },
                    ) { Text("Start") }
                    OutlinedButton(
                        enabled = ui.status != RuntimeStatus.STOPPED,
                        onClick = { vm.stop(context) },
                    ) { Text("Stop") }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Device identity", style = MaterialTheme.typography.titleMedium)
                Text(ui.deviceId ?: "Creating key…")
                Text("Key protection: ${ui.keyLevel ?: "unknown"}", style = MaterialTheme.typography.bodySmall)
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Capabilities (all off until you enable them)", style = MaterialTheme.typography.titleMedium)
                ui.capabilities.forEach { c ->
                    val d = c.descriptor
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("${d.id} v${d.version}")
                            Text(d.description, style = MaterialTheme.typography.bodySmall)
                            Text(
                                when (val a = c.availability) {
                                    Availability.Available -> "Available"
                                    is Availability.Unavailable -> "Unavailable: ${a.reason}"
                                    is Availability.PermissionRequired -> "Needs Android permission"
                                },
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Switch(checked = c.enabled, onCheckedChange = { vm.setEnabled(d.id, it) })
                    }
                    OutlinedButton(onClick = { vm.selfTest(d.id) }) { Text("Run local self-test") }
                }
                ui.selfTestOutput?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }

        Text(
            "Android can stop this runtime at any time: force-stop, reboot, battery management, Doze and network loss " +
                "all interrupt it. Phase 1 has no relay connection; commands only run locally.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
