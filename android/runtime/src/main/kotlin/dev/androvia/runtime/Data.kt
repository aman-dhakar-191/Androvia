package dev.androvia.runtime

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
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

/** The relay the user chose (single row, id = 1). Contains no secret: devices authenticate with their Keystore key. */
@Entity(tableName = "relay_config")
data class RelayConfigEntity(
    @PrimaryKey val id: Int = 1,
    val url: String,
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

@Dao
interface RelayConfigDao {
    @Query("SELECT * FROM relay_config WHERE id = 1")
    fun observe(): Flow<RelayConfigEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: RelayConfigEntity)
}

object RuntimeMigrations {
    /** Adds relay_config. Existing tables and the user's capability choices are left untouched. */
    val MIGRATION_1_2 = object : Migration(1, 2) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("CREATE TABLE IF NOT EXISTS `relay_config` (`id` INTEGER NOT NULL, `url` TEXT NOT NULL, `enabled` INTEGER NOT NULL, PRIMARY KEY(`id`))")
        }
    }
    val ALL = arrayOf<Migration>(MIGRATION_1_2)
}

@Database(
    entities = [RuntimeStateEntity::class, CapabilityConfigEntity::class, RelayConfigEntity::class],
    version = 2,
    exportSchema = false,
)
abstract class AndroviaDatabase : RoomDatabase() {
    abstract fun runtimeStateDao(): RuntimeStateDao
    abstract fun capabilityConfigDao(): CapabilityConfigDao
    abstract fun relayConfigDao(): RelayConfigDao
}
