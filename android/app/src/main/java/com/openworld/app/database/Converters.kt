package com.openworld.app.database

import androidx.room.TypeConverter
import com.openworld.app.model.ProfileType
import com.openworld.app.model.UpdateStatus

/**
 * Room 类型转换�? *
 * 用于将枚举类型转换为数据库可存储的格�? */
class Converters {

    @TypeConverter
    fun fromProfileType(value: ProfileType): String = value.name

    @TypeConverter
    fun toProfileType(value: String): ProfileType =
        runCatching { ProfileType.valueOf(value) }.getOrDefault(ProfileType.Subscription)

    @TypeConverter
    fun fromUpdateStatus(value: UpdateStatus): String = value.name

    @TypeConverter
    fun toUpdateStatus(value: String): UpdateStatus =
        runCatching { UpdateStatus.valueOf(value) }.getOrDefault(UpdateStatus.Idle)
}







