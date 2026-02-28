import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("java-library")
    alias(libs.plugins.jetbrains.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    // ICAO/ASN.1/CMS/crypto 는 BouncyCastle(MIT) 에 위임 (clean-room: docs/design/07)
    // bcprov: 기본 ASN.1/x509/crypto, bcpkix: asn1.cms / asn1.icao (SOD, LDSSecurityObject)
    implementation(libs.bouncy.castle.provier)
    implementation(libs.bouncy.castle.pkix)

    testImplementation(libs.junit)
}

// ePassport 모듈이 mrtdcore 를 jar 바이너리로 소비하도록 산출물(jar)을 복사한다.
// 완전 교체 방식: ePassport 는 project(":mrtdcore") 대신 ePassport/libs/mrtdcore.jar 를 사용한다.
tasks.register<Copy>("copyJarToEpassport") {
    dependsOn(tasks.named("jar"))
    from(layout.buildDirectory.dir("libs"))
    include("mrtdcore.jar")
    into(rootProject.file("ePassport/libs"))
}
