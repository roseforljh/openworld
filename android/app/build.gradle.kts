import com.android.build.api.dsl.ApplicationExtension
import java.util.Properties

plugins {
    id("com.android.application")
    id("com.google.devtools.ksp")
    id("io.gitlab.arturbosch.detekt")
    id("org.jetbrains.kotlin.plugin.compose")
}

val abiOnly = providers.gradleProperty("abiOnly").orNull
    ?.trim()
    ?.takeIf { it.isNotBlank() }

val isBundleBuild = gradle.startParameter.taskNames.any { it.contains("bundle", ignoreCase = true) }

val preferredDefaultAbis = listOf("arm64-v8a", "armeabi-v7a")
val availableCoreAbis = preferredDefaultAbis.filter { abi ->
    file("src/main/jniLibs/$abi/libopenworld.so").isFile
}

if (!abiOnly.isNullOrBlank() && abiOnly !in availableCoreAbis) {
    throw GradleException(
        "Requested abiOnly=$abiOnly, but src/main/jniLibs/$abiOnly/libopenworld.so is missing. " +
            "Available core ABIs: ${availableCoreAbis.ifEmpty { listOf("none") }}"
    )
}

val defaultAbis = preferredDefaultAbis.filter { it in availableCoreAbis }
if (defaultAbis.isEmpty()) {
    throw GradleException(
        "No libopenworld.so found under src/main/jniLibs/<abi>/. " +
            "Run ./scripts/build_android.ps1 -Release first."
    )
}

val apkAbis = abiOnly?.let { listOf(it) } ?: defaultAbis

configure<ApplicationExtension> {
    namespace = "com.openworld.app"
    compileSdk = 36

    ndkVersion = providers.gradleProperty("ndkVersion").orNull ?: "29.0.14206865"

    // 体积优先：优先压缩 APK 体积 (useLegacyPackaging = true)
    val preferCompressedApk = providers.gradleProperty("preferCompressedApk").orNull?.toBoolean() ?: true

    defaultConfig {
        applicationId = "com.openworld.app"
        minSdk = 24
        targetSdk = 36
        
        // Dynamic versioning
        val gitCommitCountOutput = providers.exec {
            commandLine("git", "rev-list", "--count", "HEAD")
        }.standardOutput.asText.get().trim()
        val gitCommitCount = gitCommitCountOutput.toIntOrNull() ?: 1
        
        // Offset to ensure versionCode > previous hardcoded value (5946)
        val gitVersionCode = 6000 + gitCommitCount

        val gitVersionName = System.getenv("VERSION_NAME") ?: run {
             providers.exec {
                 commandLine("git", "describe", "--tags", "--always")
             }.standardOutput.asText.get().trim()
        }

        versionCode = gitVersionCode
        versionName = gitVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        androidResources {
            localeFilters += listOf("zh", "en") // 仅保留中文和英文资源，减少体积
        }
    }

    signingConfigs {
        create("release") {
            val props = Properties()
            val propsFile = rootProject.file("signing.properties")
            if (propsFile.exists()) {
                // 本地开发：从 signing.properties 文件读取
                props.load(propsFile.inputStream())
                storeFile = rootProject.file(props.getProperty("STORE_FILE"))
                storePassword = props.getProperty("KEYSTORE_PASSWORD")
                keyAlias = props.getProperty("KEY_ALIAS")
                keyPassword = props.getProperty("KEY_PASSWORD")
            } else {
                // CI 环境：从环境变量读取签名配置
                val keystorePath = System.getenv("KEYSTORE_PATH")
                val keystorePassword = System.getenv("KEYSTORE_PASSWORD")
                val keyAliasEnv = System.getenv("KEY_ALIAS")
                val keyPasswordEnv = System.getenv("KEY_PASSWORD")
                
                if (keystorePath != null) {
                    storeFile = File(keystorePath)
                    storePassword = keystorePassword
                    keyAlias = keyAliasEnv
                    keyPassword = keyPasswordEnv
                }
            }

        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            // 在 debug 模式下也可以开启简单的分包优化，或者减小 ABI 范围
            // 如果仅用于本地调试，建议在 local.properties 中配置仅编译当前设备的架构
        }
    }
    
    splits {
        abi {
            // AAB 构建时不能启用多 APK 输出（否则 buildReleasePreBundle 会报 multiple shrunk-resources）
            isEnable = !isBundleBuild
            reset()
            isUniversalApk = false
            include(*apkAbis.toTypedArray())
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    buildFeatures {
        aidl = true
        compose = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "**/kotlin/**"
            excludes += "**/*.kotlin_*"
            excludes += "**/META-INF/*.version"
            excludes += "DebugProbesKt.bin"
            excludes += "META-INF/*.kotlin_module"
            excludes += "META-INF/proguard/*"
        }
        // 优化 JNI 库打包方式
        // useLegacyPackaging = true 会压缩 APK 中的 .so，使下载体积最小（体积优先策略）
        // 但安装后会解压到 lib 目录，增加安装后占用。
        jniLibs {
            useLegacyPackaging = preferCompressedApk
        }
    }
    
    // 避免压缩规则集文件，提高读取效率
    androidResources {
        noCompress += "srs"
    }
    
    // 单元测试配置：返回 Android API 默认值，避免 android.util.* 抛异常
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// JVM Target Configuration for Kotlin
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    // OpenWorld 内核 - 使用本地 jniLibs 目录
    // 核心功能由 com.openworld.core.OpenWorldCore 提供
    // libopenworld.so 需要通过 Rust 编译生成

    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.11.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.navigation:navigation-compose:2.8.0")
    
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.datastore:datastore-preferences:1.0.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-process:2.8.7")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.tencent:mmkv:1.3.2")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    val roomVersion = "2.7.2"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2023.08.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.7")
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    baseline = file("$rootDir/config/detekt/baseline.xml")
    autoCorrect = true
}
