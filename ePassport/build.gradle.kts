plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.maven.publish)
}

group = "io.github.juncaffe"
version = rootProject.extra["epassport_version"] as String

android {
    namespace = "com.juncaffe.epassport"
    compileSdk = libs.versions.compile.sdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.min.sdk.get().toInt()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
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
    kotlinOptions {
        jvmTarget = "17"
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
//            withJavadocJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "io.github.juncaffe"
                artifactId = "epassport-reader"
                version = rootProject.extra["epassport_version"] as String

                pom {
                    name.set("Android ePassport Reader")
                    description.set("Clean-room eMRTD (ICAO 9303) NFC reader for Android, built on mrtdcore")
                    url.set("https://github.com/juncaffe/android-epassport-reader")
                    licenses {
                        license {
                            name.set("Apache-2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    developers {
                        developer {
                            id.set("juncaffe")
                            name.set("JunCaffe")
                            url.set("https://github.com/juncaffe")
                        }
                    }
                }
            }
        }
        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/juncaffe/android-epassport-reader")
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

tasks.register<Copy>("copyAarToApp") {
    dependsOn("assembleRelease")
    from(layout.buildDirectory.dir("outputs/aar"))
    into(rootProject.file("app/libs"))
}

// mrtdcore 를 project() 가 아닌 jar 바이너리로 소비한다(완전 교체).
// 빌드 전에 mrtdcore.jar 를 ePassport/libs 로 복사해 둔다.
tasks.named("preBuild") {
    dependsOn(":mrtdcore:copyJarToEpassport")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    // mrtdcore = java-library 산출 jar. AGP 가 로컬 jar 를 aar(libs)에 번들링한다.
    api(files("libs/mrtdcore.jar"))
    // jar 는 transitive 메타데이터가 없으므로 mrtdcore 가 의존하는 BouncyCastle 을 직접 선언한다.
    implementation(libs.bouncy.castle.provier)
    implementation(libs.bouncy.castle.pkix)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
