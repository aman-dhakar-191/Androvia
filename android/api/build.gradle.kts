import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    api(project(":core"))
    api(libs.ktor.client.core)
    api(libs.ktor.client.websockets)
    implementation(libs.ktor.client.okhttp)

    testImplementation(project(":capabilities"))
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.ktor.server.cio)
    testImplementation(libs.ktor.server.websockets)
}

tasks.test {
    useJUnitPlatform()
    // The end-to-end test against the real Go relay runs only when these are set (CI sets them).
    listOf("RELAY_E2E_URL", "RELAY_E2E_ADMIN_TOKEN").forEach { name ->
        System.getenv(name)?.let { environment(name, it) }
    }
    testLogging { events("failed", "skipped"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
