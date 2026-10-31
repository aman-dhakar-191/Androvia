package dev.androvia.app

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import dev.androvia.runtime.AppScope
import dev.androvia.runtime.RuntimeStateStore
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

@HiltAndroidApp
class AndroviaApp : Application() {
    @Inject lateinit var store: RuntimeStateStore
    @Inject @AppScope lateinit var appScope: CoroutineScope

    override fun onCreate() {
        super.onCreate()
        // A new process cannot have a running service yet (it is START_NOT_STICKY), so clear any stale "running" flag
        // left behind by a crash or force-stop. The service sets it again when it actually starts.
        appScope.launch { store.setServiceRunning(false) }
    }
}
