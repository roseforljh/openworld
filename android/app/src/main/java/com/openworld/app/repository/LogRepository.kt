package com.openworld.app.repository

import com.google.gson.JsonArray
import com.google.gson.JsonParser
import com.openworld.core.OpenWorldCore
import java.util.concurrent.ConcurrentLinkedDeque

object LogRepository {

    data class LogEntry(val level: Int, val message: String, val timestamp: Long = System.currentTimeMillis())

    private const val MAX_SIZE = 1000
    private val buffer = ConcurrentLinkedDeque<LogEntry>()
    private var lastPullTimestamp: Long = 0
    private val seenNoTimestamp = LinkedHashSet<String>()
    private const val SEEN_MAX = 200

    fun add(level: Int, message: String) {
        buffer.addLast(LogEntry(level, message))
        while (buffer.size > MAX_SIZE) buffer.pollFirst()
    }

    fun pullFromCore() {
        val status = try { OpenWorldCore.getStatus().orEmpty() } catch (_: Exception) { "" }
        if (status.isEmpty()) return

        val logs = parseLogsFromStatus(status)
        if (logs.isEmpty()) return

        var maxTs = lastPullTimestamp
        for (entry in logs) {
            if (entry.timestamp > 0) {
                if (entry.timestamp <= lastPullTimestamp) continue
                if (entry.timestamp > maxTs) maxTs = entry.timestamp
            } else {
                val key = "${entry.level}|${entry.message}"
                if (seenNoTimestamp.contains(key)) continue
                seenNoTimestamp.add(key)
                if (seenNoTimestamp.size > SEEN_MAX) {
                    val iter = seenNoTimestamp.iterator()
                    iter.next()
                    iter.remove()
                }
            }
            add(entry.level, entry.message)
        }
        if (maxTs > lastPullTimestamp) lastPullTimestamp = maxTs
    }

    fun getAll(): List<LogEntry> = buffer.toList()

    fun size(): Int = buffer.size

    fun getFiltered(minLevel: Int): List<LogEntry> = buffer.filter { it.level >= minLevel }

    fun clear() {
        buffer.clear()
        lastPullTimestamp = 0
        seenNoTimestamp.clear()
    }

    fun levelName(level: Int): String = when (level) {
        0 -> "TRACE"
        1 -> "DEBUG"
        2 -> "INFO"
        3 -> "WARN"
        4 -> "ERROR"
        else -> "UNKNOWN"
    }

    private fun parseLogsFromStatus(statusJson: String): List<LogEntry> {
        return try {
            val root = JsonParser.parseString(statusJson).asJsonObject
            val logs = root.get("logs") as? JsonArray ?: return emptyList()
            logs.mapNotNull { element ->
                if (element.isJsonObject) {
                    val obj = element.asJsonObject
                    val level = obj.get("level")?.asInt ?: obj.get("lvl")?.asInt ?: 2
                    val message = obj.get("message")?.asString
                        ?: obj.get("msg")?.asString
                        ?: return@mapNotNull null
                    val timestamp = obj.get("timestamp")?.asLong
                        ?: obj.get("ts")?.asLong
                        ?: 0L
                    LogEntry(level = level, message = message, timestamp = timestamp)
                } else if (element.isJsonPrimitive && element.asJsonPrimitive.isString) {
                    LogEntry(level = 2, message = element.asString, timestamp = 0L)
                } else {
                    null
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
