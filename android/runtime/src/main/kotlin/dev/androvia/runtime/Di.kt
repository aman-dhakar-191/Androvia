package dev.androvia.runtime

import android.content.Context
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import dev.androvia.authentication.AndroidKeystoreDeviceKeys
import dev.androvia.authentication.DeviceKeys
import dev.androvia.capabilities.DeviceInfoCapability
import dev.androvia.core.CapabilityRegistry
import dev.androvia.core.LocalPolicy
import java.time.Clock
import javax.inject.Qualifier
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class AppScope

@Module
@InstallIn(SingletonComponent::class)
object RuntimeModule {
    @Provides @Singleton
    fun database(@ApplicationContext context: Context): AndroviaDatabase =
        Room.databaseBuilder(context, AndroviaDatabase::class.java, "androvia.db").build()

    @Provides fun runtimeStateDao(db: AndroviaDatabase): RuntimeStateDao = db.runtimeStateDao()

    @Provides fun capabilityConfigDao(db: AndroviaDatabase): CapabilityConfigDao = db.capabilityConfigDao()

    @Provides @Singleton fun clock(): Clock = Clock.systemUTC()

    @Provides @Singleton fun deviceKeys(): DeviceKeys = AndroidKeystoreDeviceKeys()

    /** The only capabilities that exist. Adding one here is an explicit, reviewed act. */
    @Provides @Singleton
    fun registry(): CapabilityRegistry = CapabilityRegistry(listOf(DeviceInfoCapability(AndroidDeviceInfoSource)))

    @Provides @Singleton
    fun policy(dao: CapabilityConfigDao): LocalPolicy = roomPolicy(dao)

    /** Outlives the service so state writes in onDestroy complete. */
    @Provides @Singleton @AppScope
    fun appScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}
