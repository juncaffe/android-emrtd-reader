plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.jetbrains.kotlin.jvm) apply false
}

extra["epassport_version"] = "0.1.0"

// mrtdcore.jar 생성 → ePassport 에 jar 를 포함해 ePassport aar 빌드 → app/libs 로 복사
// ./gradlew updateEpassportAar
//
// copyAarToApp → assembleRelease → (ePassport:preBuild → mrtdcore:copyJarToEpassport → mrtdcore:jar)
// 로 체인이 이어지므로 위 태스크 하나로 전체 파이프라인이 실행된다.
//
// :app:preBuild 가 :ePassport:copyAarToApp 에 의존하도록 wiring 되어 있어,
// 태스크를 먼저 실행하지 않고 app 을 Run 해도 최신 라이브러리로 실행된다.
tasks.register("updateEpassportAar") {
    group = "build"
    description = "mrtdcore.jar 생성 → ePassport aar 빌드 → app/libs 갱신"
    dependsOn(":ePassport:copyAarToApp")
}

// 라이브러리 갱신 후 곧바로 앱 설치까지 한 번에 수행하는 태스크.
// ./gradlew runApp
tasks.register("runApp") {
    group = "build"
    description = "라이브러리 갱신 + app 디버그 설치(installDebug)"
    dependsOn(":app:installDebug")
}