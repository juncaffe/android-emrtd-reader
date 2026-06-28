import org.gradle.kotlin.dsl.implementation
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.juncaffe.epassport.app"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        minSdk = 24
        targetSdk = libs.versions.compile.sdk.get().toInt()
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // @Module 클래스를 검사 disable(임시)
        javaCompileOptions {
            annotationProcessorOptions {
                arguments["dagger.hilt.disableModulesHaveInstallInCheck"] = "true"
            }
        }
    }
    hilt {
        enableAggregatingTask = false
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/**",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*"
            )
        }
    }
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// app 은 ePassport 를 project() 가 아닌 aar 바이너리로 소비한다(완전 교체, flatDir: app/libs).
// 빌드 전에 ePassport-release.aar 를 app/libs 로 복사해 둔다.
tasks.named("preBuild") {
    dependsOn(":ePassport:copyAarToApp")
}

dependencies {
    // ePassport = aar 바이너리 (flatDir 저장소는 settings.gradle.kts 에 선언)
    implementation(mapOf("name" to "ePassport-release", "ext" to "aar"))
    implementation(libs.bundles.androidx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.compose)

    // aar 는 transitive 메타데이터가 없으므로 mrtdcore(jar)가 요구하는 BouncyCastle 을 직접 선언한다.
    implementation(libs.bundles.bouncycastle)
    implementation(libs.bouncy.castle.pkix)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.dagger.hilt)
    ksp(libs.dagger.compiler)

    testImplementation(libs.junit)
    androidTestImplementation(libs.bundles.test)
    androidTestImplementation(libs.bundles.test)
    debugImplementation(libs.bundles.ui.debug)
}
