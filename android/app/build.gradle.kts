plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// JNI 声明/导出一致性校验任务
val verifyJniAlignment by tasks.registering(Exec::class) {
    val androidRoot = rootProject.projectDir
    val script = File(androidRoot, "verify_jni_alignment.ps1")

    workingDir = androidRoot
    commandLine(
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", script.absolutePath
    )
}

// Rust 内核编译任务
val buildRustCore by tasks.registering(Exec::class) {
    val projectRoot = rootProject.projectDir.parentFile  // OpenWorld 根目录
    val target = "aarch64-linux-android"
    val profile = if (gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }) "release" else "debug"
    val jniLibsDir = file("src/main/jniLibs/arm64-v8a")
    val soFile = file("${projectRoot}/target/${target}/${profile}/libopenworld.so")

    workingDir = projectRoot
    environment("CARGO_BUILD_JOBS", "2")
    val ndkBin = "C:/Users/33039/AppData/Local/Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/windows-x86_64/bin"
    environment("CC_aarch64_linux_android", "$ndkBin/aarch64-linux-android24-clang.cmd")
    environment("AR_aarch64_linux_android", "$ndkBin/llvm-ar.exe")
    environment("RANLIB_aarch64_linux_android", "$ndkBin/llvm-ranlib.exe")

    val args = mutableListOf(
        "cargo", "build",
        "--lib",
        "--target", target,
        "--no-default-features",
        "--features", "android"
    )
    if (profile == "release") args.add("--release")
    commandLine(args)

    doLast {
        if (soFile.exists()) {
            jniLibsDir.mkdirs()
            soFile.copyTo(file("${jniLibsDir}/libopenworld.so"), overwrite = true)
            println("Copied libopenworld.so (${soFile.length() / 1024}KB) -> ${jniLibsDir}")
        } else {
            throw GradleException("libopenworld.so not found at: ${soFile}")
        }
    }
}

// preBuild 前先做 JNI 对齐校验；若缺少 so 再触发 Rust 编译
tasks.named("preBuild") {
    dependsOn(verifyJniAlignment)

    val soFile = file("src/main/jniLibs/arm64-v8a/libopenworld.so")
    if (!soFile.exists()) {
        dependsOn(buildRustCore)
    }
}

android {
    namespace = "com.openworld.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.openworld.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.11.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Core
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    // Navigation
    implementation("androidx.navigation:navigation-compose:2.8.4")

    // JSON
    implementation("com.google.code.gson:gson:2.11.0")

    // YAML
    implementation("org.yaml:snakeyaml:2.2")

    // Network (订阅拉取)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // QR 扫码
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
