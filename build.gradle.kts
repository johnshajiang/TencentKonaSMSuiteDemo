plugins {
    java
    id("org.springframework.boot") version "3.2.10"
    id("io.spring.dependency-management") version "1.1.6"
}

group = "com.github.johnshajiang"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")

    implementation("com.tencent.kona:kona-crypto:1.0.14")
    implementation("com.tencent.kona:kona-pkix:1.0.14")
    implementation("com.tencent.kona:kona-ssl:1.0.14")
    implementation("com.tencent.kona:kona-provider:1.0.14")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}