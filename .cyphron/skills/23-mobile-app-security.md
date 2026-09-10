# Skill 23 — Mobile Application Security

> Cyphron's methodology for securing mobile applications (iOS, Android). Cyphron knows mobile attack vectors — insecure data storage, improper certificate validation, intent hijacking, reverse engineering, runtime manipulation — and builds mobile defenses following OWASP MASVS.

---

## WHEN TO ACTIVATE

- User asks to secure a mobile app (iOS/Android)
- User asks about OWASP MASVS or Mobile Top 10
- User asks about mobile app reverse engineering protection
- User asks about secure storage on mobile
- User asks about certificate pinning or mobile API security

---

## METHODOLOGY

### Step 1: Identify Platform
- iOS (Swift, Objective-C)
- Android (Kotlin, Java, React Native, Flutter)
- Hybrid/Cross-platform

### Step 2: OWASP MASVS Categories

| Category | What to Check |
|---|---|
| MASVS-STORAGE | Secure storage of sensitive data |
| MASVS-CRYPTO | Cryptographic implementation |
| MASVS-NETWORK | Network communication security |
| MASVS-PLATFORM | Platform interaction security |
| MASVS-CODE | Code quality & tamper resistance |
| MASVS-RESILIENCE | Reverse engineering resistance |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### Secure Storage (Android — Keystore)
```kotlin
// Store sensitive data in Android Keystore (not SharedPreferences)
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class SecureStorage(context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun getOrCreateKey(): SecretKey {
        if (!keyStore.containsAlias("app_key")) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(
                KeyGenParameterSpec.Builder("app_key",
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)  // require biometric/PIN
                    .build()
            )
            return keyGenerator.generateKey()
        }
        return (keyStore.getEntry("app_key", null) as KeyStore.SecretKeyEntry).secretKey
    }

    fun encrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data)
        return iv + encrypted  // prepend IV
    }
}
```

### Secure Storage (iOS — Keychain)
```swift
import Security

class KeychainHelper {
    static func save(key: String, data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,  // not synced
        ]
        SecItemDelete(query as CFDictionary)
        var addQuery = query
        addQuery[kSecValueData as String] = data as CFData
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)
        return result as? Data
    }
}
```

### Certificate Pinning (Android — OkHttp)
```kotlin
import okhttp3.CertificatePinner

val pinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")  // backup pin
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build()
```

### Certificate Pinning (iOS — URLSession)
```swift
import Security

class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Compare with pinned certificate
        let pinnedCertData = // load from bundle
        let serverCertData = SecCertificateCopyData(certificate) as Data

        if pinnedCertData == serverCertData {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

### Anti-Tampering (Android — Root Detection + Integrity)
```kotlin
class SecurityChecks {
    fun isDeviceRooted(): Boolean {
        val paths = listOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    fun verifyAppIntegrity(context: Context): Boolean {
        try {
            val packageInfo = context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            val signatures = packageInfo.signatures
            val expectedHash = "sha256:EXPECTED_HASH_HERE"
            val actualHash = signatures[0].toCharsString().sha256()
            return "sha256:$actualHash" == expectedHash
        } catch (e: Exception) {
            return false
        }
    }
}
```

### Secure Network Communication
```kotlin
// Android — network_security_config.xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">  <!-- No HTTP -->
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- Only if needed for testing -->
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain>api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

---

## AUDIT CHECKLIST (MASVS)

- [ ] Sensitive data stored in Keystore/Keychain (not SharedPreferences/NSUserDefaults)
- [ ] No sensitive data in logs
- [ ] No sensitive data in backups (excludeFromBackup)
- [ ] TLS 1.2+ for all network communication
- [ ] Certificate pinning on critical endpoints
- [ ] No cleartext HTTP traffic
- [ ] Cryptographic operations use platform APIs (not custom crypto)
- [ ] Keys stored in hardware-backed keystore
- [ ] Input validation on all user input
- [ ] WebView JavaScript disabled unless needed
- [ ] Deep links validated
- [ ] Intent handling secured (no exported activities without need)
- [ ] Code obfuscation (ProGuard/R8)
- [ ] Root/jailbreak detection
- [ ] App integrity verification
- [ ] Anti-debugging controls
- [ ] Biometric authentication for sensitive operations
