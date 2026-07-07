plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.securechat.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.securechat.app"
        minSdk = 26      // Android 8.0 — WebView supports the crypto + asset loader we need
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        viewBinding = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false // nothing to strip: logic lives in bundled JS
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
}

// Single source of truth: the audited web client lives in ../../client. Copy it
// into the app's assets at build time (excluding tests / package manifests) so
// the APK always ships the exact reviewed files and the bundle can never drift
// from the web deployment. The generated copy is gitignored.
val syncWebClient = tasks.register<Copy>("syncWebClient") {
    from(rootProject.file("../client")) {
        exclude("*.test.mjs", "*.integration.test.mjs", "package*.json", "node_modules")
    }
    into(layout.projectDirectory.dir("src/main/assets/web"))
}
tasks.named("preBuild") { dependsOn(syncWebClient) }

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    // WebViewAssetLoader (serves bundled assets as a secure https origin) and
    // addDocumentStartJavaScript (injects the relay config before page scripts).
    implementation("androidx.webkit:webkit:1.11.0")
}
