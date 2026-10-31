package dev.androvia.runtime

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

/** Single-row table (id = 1). */
@Entity(tableName = "runtime_state")
data class RuntimeStateEntity(
    @PrimaryKey val id: Int = 1,
    val serviceRunning: Boolean,
    val updatedAtEpochMs: Long,
)

/** One row per capability the user has explicitly switched on or off. Absent row = disabled (deny by default). */
@Entity(tableName = "capability_config")
data class CapabilityConfigEntity(
    @PrimaryKey val capabilityId: String,
    val enabled: Boolean,
)

@Dao
interface RuntimeStateDao {
    @Query("SELECT * FROM runtime_state WHERE id = 1")
    fun observe(): Flow<RuntimeStateEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: RuntimeStateEntity)
}

@Dao
interface CapabilityConfigDao {
    @Query("SELECT * FROM capability_config")
    fun observeAll(): Flow<List<CapabilityConfigEntity>>

    @Query("SELECT capabilityId FROM capability_config WHERE enabled = 1")
    suspend fun enabledIds(): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: CapabilityConfigEntity)
}

@Database(
    entities = [RuntimeStateEntity::class, CapabilityConfigEntity::class],
    version = 1,
    exportSchema = false,
)
abstract class AndroviaDatabase : RoomDatabase() {
    abstract fun runtimeStateDao(): RuntimeStateDao
    abstract fun capabilityConfigDao(): CapabilityConfigDao
}
