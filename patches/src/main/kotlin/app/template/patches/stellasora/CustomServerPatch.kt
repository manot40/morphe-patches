package app.template.patches.stellasora

import app.morphe.patcher.extensions.InstructionExtensions.addInstruction
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.instructions
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.patch.resourceFile
import app.morphe.patcher.patch.resourceXml
import app.morphe.patcher.patch.stringOption
import app.template.patches.shared.Constants.COMPATIBILITY_STELLA_SORA
import com.android.tools.smali.dexlib2.AccessFlags
import java.io.File

private const val TRUST_ALL_MANAGER_CLASS = "Lcom/yostar/airisdk/core/net/NetClientManage\$1;"

@Suppress("unused")
val customServerPatch = patch(
    name = "Custom server",
    description = "Replaces Stella Sora API endpoints with a custom server domain and bypasses X509TrustManager certificate checks.",
    default = true
) {
    compatibleWith(COMPATIBILITY_STELLA_SORA)

    val serverDomainOption = stringOption(
        key = "serverDomain",
        default = "stellasora.local",
        title = "Server domain",
        description = "Custom domain to replace nova.stellasora.global and en-sdk-api.yostarplat.com.",
        required = true
    ) {
        !it.isNullOrBlank()
    }

    execute {
        val domain = serverDomainOption.value!!
            .trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .trimEnd('/')

        // 1. Replace domains in assets/SDKConfigSettings.json
        val sdkConfigFile = resourceFile("assets/SDKConfigSettings.json")
        if (!sdkConfigFile.exists()) {
            throw PatchException("assets/SDKConfigSettings.json not found in APK")
        }
        val updatedJson = sdkConfigFile.readText()
            .replace("nova.stellasora.global", domain)
            .replace("en-sdk-api.yostarplat.com", domain)
        sdkConfigFile.writeText(updatedJson)

        // 2. Configure network_security_config.xml in AndroidManifest.xml
        var networkSecurityFileName = "network_security_config.xml"
        resourceXml("AndroidManifest.xml").use { manifest ->
            val application = manifest.elements("application").first()
            val config = application.attribute("android:networkSecurityConfig")
            if (config != null && config.contains("/")) {
                networkSecurityFileName = config.substringAfter("/") + ".xml"
            } else {
                application.setAttribute("android:networkSecurityConfig", "@xml/network_security_config")
            }
        }
        File(resourceFile("res/xml"), networkSecurityFileName).writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <base-config cleartextTrafficPermitted="true">
                    <trust-anchors>
                        <certificates src="system" />
                        <certificates src="user" overridePins="true" />
                    </trust-anchors>
                </base-config>
                <debug-overrides>
                    <trust-anchors>
                        <certificates src="system" />
                        <certificates src="user" overridePins="true" />
                    </trust-anchors>
                </debug-overrides>
            </network-security-config>
            """.trimIndent()
        )

        // 3. Expose Yostar's built-in trust-all X509TrustManager (NetClientManage$1) and NetClientManage.setOkHttpSsl
        mutableClassDefBy(TRUST_ALL_MANAGER_CLASS).apply {
            setAccessFlags((accessFlags and AccessFlags.PRIVATE.value.inv()) or AccessFlags.PUBLIC.value)
            methods.first { it.name == "<init>" }.apply {
                setAccessFlags((accessFlags and AccessFlags.PRIVATE.value.inv()) or AccessFlags.PUBLIC.value)
            }
        }

        NetClientManageSetOkHttpSslFingerprint.method.apply {
            setAccessFlags((accessFlags and AccessFlags.PRIVATE.value.inv()) or AccessFlags.PUBLIC.value)
        }

        // 4. Configure every OkHttpClient$Builder instance to use setOkHttpSsl (trust-all X509TrustManager)
        OkHttpClientBuilderInitFingerprint.method.apply {
            addInstruction(
                instructions.lastIndex,
                "invoke-static { p0 }, Lcom/yostar/airisdk/core/net/NetClientManage;->setOkHttpSsl(Lokhttp3/OkHttpClient\$Builder;)Lokhttp3/OkHttpClient\$Builder;"
            )
        }

        // 5. Return trust-all X509TrustManager from OkHttp Platform.platformTrustManager()
        OkHttpPlatformTrustManagerFingerprint.method.addInstructions(
            0,
            """
                new-instance v0, $TRUST_ALL_MANAGER_CLASS
                invoke-direct { v0 }, $TRUST_ALL_MANAGER_CLASS-><init>()V
                return-object v0
            """
        )

        // 6. Bypass AndroidCertificateChainCleaner.clean() (X509TrustManagerExtensions.checkServerTrusted)
        AndroidCertificateChainCleanerCleanFingerprint.method.addInstruction(
            0,
            "return-object p1"
        )

        // 7. Bypass OkHostnameVerifier.verify() for self-signed certs with mismatched SAN/CN
        val returnTrueSmali = """
            const/4 v0, 0x1
            return v0
        """
        OkHostnameVerifierVerifySessionFingerprint.method.addInstructions(0, returnTrueSmali)
        OkHostnameVerifierVerifyCertFingerprint.method.addInstructions(0, returnTrueSmali)

        // 8. Bypass X509TrustManager & HostnameVerifier in Yostar volley HttpsURLConnection (SSLSocketFactoryCompat)
        VolleySslSocketFactoryCompatInitFingerprint.method.addInstructions(
            1,
            """
                new-instance v0, $TRUST_ALL_MANAGER_CLASS
                invoke-direct { v0 }, $TRUST_ALL_MANAGER_CLASS-><init>()V
                new-instance v1, Lcom/yostar/airisdk/core/net/SSLSocketFactoryCompat;
                invoke-direct { v1, v0 }, Lcom/yostar/airisdk/core/net/SSLSocketFactoryCompat;-><init>(Ljavax/net/ssl/X509TrustManager;)V
                iput-object v1, p0, Lcom/yostar/airisdk/core/net/volley/SSLSocketFactoryCompat;->delegate:Ljavax/net/ssl/SSLSocketFactory;
                sget-object v0, Lokhttp3/internal/tls/OkHostnameVerifier;->INSTANCE:Lokhttp3/internal/tls/OkHostnameVerifier;
                invoke-static { v0 }, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
                return-void
            """
        )
    }
}
