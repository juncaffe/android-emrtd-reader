pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
        // app 이 ePassport-release.aar 를 바이너리로 소비(완전 교체 방식).
        // FAIL_ON_PROJECT_REPOS 때문에 flatDir 는 모듈이 아닌 여기에 선언한다.
        flatDir { dirs("${rootDir}/app/libs") }
    }
}

rootProject.name = "mrtd-android"
include(":app")
include(":ePassport")
include(":mrtdcore")
