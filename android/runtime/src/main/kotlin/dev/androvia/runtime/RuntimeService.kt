package dev.androvia.runtime

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service for the runtime (type `specialUse`, ADR 0001). Phase 1: it only holds the runtime "running"
 * and shows its notification; there is no relay connection yet. START_NOT_STICKY on purpose: Android may refuse
 * to start a foreground service from the background, so we do not rely on system restarts.
 */
@AndroidEntryPoint
class RuntimeService : Service() {
    @Inject lateinit var store: RuntimeStateStore
    @Inject @AppScope lateinit var appScope: CoroutineScope
    @Inject lateinit var connector: RelayConnector
    @Inject lateinit var relayState: RelayStateStore

    // Lives and dies with the service: no service, no relay connection.
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var relayJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        ensureChannel(this)
        try {
            ServiceCompat.startForeground(
                this, NOTIFICATION_ID, buildNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } catch (e: Exception) {
            // e.g. ForegroundServiceStartNotAllowedException when started from the background.
            store.reportStartFailure(e.javaClass.simpleName)
            appScope.launch { store.setServiceRunning(false) }
            stopSelf()
            return START_NOT_STICKY
        }
        appScope.launch { store.setServiceRunning(true) }
        if (relayJob?.isActive != true) relayJob = serviceScope.launch { connector.runWhileActive() }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        serviceScope.cancel()
        relayState.reset()
        appScope.launch { store.setServiceRunning(false) }
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        val stop = PendingIntent.getService(
            this, 1, Intent(this, RuntimeService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Androvia runtime")
            .setContentText("Androvia runtime is running.")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
    }

    companion object {
        const val ACTION_STOP = "dev.androvia.runtime.STOP"
        private const val CHANNEL_ID = "androvia_runtime"
        private const val NOTIFICATION_ID = 1

        fun ensureChannel(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Runtime status", NotificationManager.IMPORTANCE_LOW),
                )
            }
        }
    }
}

/** Start/stop entry points for the UI. Starting must happen from a user-visible state (an Activity). */
@Singleton
class RuntimeController @Inject constructor(private val store: RuntimeStateStore) {
    fun start(context: Context) {
        try {
            ContextCompat.startForegroundService(context, Intent(context, RuntimeService::class.java))
        } catch (e: Exception) {
            store.reportStartFailure(e.javaClass.simpleName)
        }
    }

    fun stop(context: Context) {
        context.startService(Intent(context, RuntimeService::class.java).setAction(RuntimeService.ACTION_STOP))
    }

    fun notificationsEnabled(context: Context): Boolean = NotificationManagerCompat.from(context).areNotificationsEnabled()
}
