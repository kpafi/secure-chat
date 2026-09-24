import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing is optional and local-only: `keystore.properties` is
// gitignored (see keystore.properties.example). Without it, assembleRelease
// still builds but produces an unsigned apk.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val hasReleaseSigning = keystorePropertiesFile.exists()
val keystoreProperties = Properties().apply {
    if (hasReleaseSigning) load(keystorePropertiesFile.inputStream())
}

android {
    namespace = "org.securechat.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.securechat.app"
        minSdk = 26      // Android 8.0 — WebView supports the crypto + asset loader we need
        targetSdk = 34
        versionCode = 3
        versionName = "0.3.0"
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true // for BuildConfig.DEBUG (debug-only WebView remote debugging)
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // nothing to strip: logic lives in bundled JS
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        // Robolectric needs the MERGED resources to inflate an activity — without
        // this it runs in legacy mode and AppCompat's own drawables are missing,
        // so MainActivity cannot be started in a unit test (UnsupportedWebViewTest).
        unitTests.isIncludeAndroidResources = true
    }
}

// Single source of truth: the audited web client lives in ../../client. Copy it
// into the app's assets at build time (excluding tests / package manifests) so
// the APK always ships the exact reviewed files and the bundle can never drift
// from the web deployment. The generated copy is gitignored.
// Pentest 2026-07-26 (Android L-11): this was a `Copy`, which is ADDITIVE — it
// never removes files from the destination that no longer exist in the source.
// A client module that was deleted or renamed therefore stayed in
// src/main/assets/web and kept shipping inside the APK indefinitely, still
// reachable at https://secure-chat.internal/... `Sync` mirrors the source
// exactly, deleting stale files, so the bundle cannot drift from the reviewed
// client. (Safe here: the destination holds nothing but this task's output.)
val syncWebClient = tasks.register<Sync>("syncWebClient") {
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

    // Local unit tests. Robolectric supplies a real android.net.Uri so the
    // RelayUrls host-validation regression tests exercise the actual parser.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.12.2")
}
