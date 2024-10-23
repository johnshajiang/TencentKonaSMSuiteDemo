plugins {
    java
    id("org.springframework.boot") version "3.2.10"
    id("io.spring.dependency-management") version "1.1.6"
    id("org.graalvm.buildtools.native") version "0.10.3"
}

group = "com.github.johnshajiang"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        url = uri("https://oss.sonatype.org/content/repositories/snapshots")
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")

    implementation("com.tencent.kona:kona-crypto:1.0.15-SNAPSHOT")
    implementation("com.tencent.kona:kona-pkix:1.0.15-SNAPSHOT")
    implementation("com.tencent.kona:kona-ssl:1.0.15-SNAPSHOT")
    implementation("com.tencent.kona:kona-provider:1.0.15-SNAPSHOT")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

graalvmNative {
    binaries.all {
        buildArgs.add("--initialize-at-build-time=com.tencent.kona.crypto.CryptoUtils")
//        buildArgs.add("-Dcom.tencent.kona.useNativeCrypto=true")
    }
}
