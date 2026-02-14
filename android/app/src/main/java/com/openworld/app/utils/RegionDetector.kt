package com.openworld.app.utils

import java.util.Collections

/**
 * 地区检测工具类
 *
 * 根据节点名称检测地区标�?(国旗 Emoji)
 * 使用预编译规则和 LRU 缓存优化性能
 */
object RegionDetector {

    private const val MAX_CACHE_SIZE = 2000

    private val REGEX_FLAG_EMOJI = Regex("[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]")

    private data class RegionRule(
        val flag: String,
        val chineseKeywords: List<String>,
        val englishKeywords: List<String>,
        val wordBoundaryKeywords: List<String>
    )

    private val REGION_RULES = listOf(
        RegionRule("🇭🇰", listOf("香港"), listOf("hong kong"), listOf("hk")),
        RegionRule("🇹🇼", listOf("台湾"), listOf("taiwan"), listOf("tw")),
        RegionRule("🇯🇵", listOf("日本"), listOf("japan", "tokyo"), listOf("jp")),
        RegionRule("🇸🇬", listOf("新加�?), listOf("singapore"), listOf("sg")),
        RegionRule("🇺🇸", listOf("美国"), listOf("united states", "america"), listOf("us", "usa")),
        RegionRule("🇰🇷", listOf("韩国"), listOf("korea"), listOf("kr")),
        RegionRule("🇬🇧", listOf("英国"), listOf("britain", "england"), listOf("uk", "gb")),
        RegionRule("🇩🇪", listOf("德国"), listOf("germany"), listOf("de")),
        RegionRule("🇫🇷", listOf("法国"), listOf("france"), listOf("fr")),
        RegionRule("🇨🇦", listOf("加拿�?), listOf("canada"), listOf("ca")),
        RegionRule("🇦🇺", listOf("澳大利亚"), listOf("australia"), listOf("au")),
        RegionRule("🇷🇺", listOf("俄罗�?), listOf("russia"), listOf("ru")),
        RegionRule("🇮🇳", listOf("印度"), listOf("india"), listOf("in")),
        RegionRule("🇧🇷", listOf("巴西"), listOf("brazil"), listOf("br")),
        RegionRule("🇳🇱", listOf("荷兰"), listOf("netherlands"), listOf("nl")),
        RegionRule("🇹🇷", listOf("土耳其"), listOf("turkey"), listOf("tr")),
        RegionRule("🇦🇷", listOf("阿根�?), listOf("argentina"), listOf("ar")),
        RegionRule("🇲🇾", listOf("马来西亚"), listOf("malaysia"), listOf("my")),
        RegionRule("🇹🇭", listOf("泰国"), listOf("thailand"), listOf("th")),
        RegionRule("🇻🇳", listOf("越南"), listOf("vietnam"), listOf("vn")),
        RegionRule("🇵🇭", listOf("菲律�?), listOf("philippines"), listOf("ph")),
        RegionRule("🇮🇩", listOf("印尼"), listOf("indonesia"), listOf("id"))
    )

    private val WORD_BOUNDARY_REGEX_MAP: Map<String, Regex> = REGION_RULES
        .flatMap { it.wordBoundaryKeywords }
        .associateWith { word -> Regex("(^|[^a-z])${Regex.escape(word)}([^a-z]|$)") }

    private val cache: MutableMap<String, String> = Collections.synchronizedMap(
        object : LinkedHashMap<String, String>(MAX_CACHE_SIZE, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean {
                return size > MAX_CACHE_SIZE
            }
        }
    )

    /**
     * 检测字符串是否包含国旗 Emoji
     */
    fun containsFlagEmoji(str: String): Boolean {
        return REGEX_FLAG_EMOJI.containsMatchIn(str)
    }

    /**
     * 根据节点名称检测地区标�?     *
     * @param name 节点名称
     * @return 国旗 Emoji，未知地区返�?"🌐"
     */
    @Suppress("ReturnCount")
    fun detect(name: String): String {
        cache[name]?.let { return it }

        val lowerName = name.lowercase()

        for (rule in REGION_RULES) {
            if (rule.chineseKeywords.any { lowerName.contains(it) }) {
                cache[name] = rule.flag
                return rule.flag
            }

            if (rule.englishKeywords.any { lowerName.contains(it) }) {
                cache[name] = rule.flag
                return rule.flag
            }

            if (rule.wordBoundaryKeywords.any { word ->
                    WORD_BOUNDARY_REGEX_MAP[word]?.containsMatchIn(lowerName) == true
                }) {
                cache[name] = rule.flag
                return rule.flag
            }
        }

        cache[name] = "🌐"
        return "🌐"
    }

    /**
     * 清空缓存
     */
    fun clearCache() {
        cache.clear()
    }
}







