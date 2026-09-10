# Skill 24 — IoT & Embedded Security

> Cyphron's methodology for securing IoT devices and embedded systems. Cyphron knows IoT attack vectors — firmware extraction, hardcoded credentials, insecure update mechanisms, physical attacks — and builds IoT defenses following OWASP IoT Top 10.

---

## WHEN TO ACTIVATE

- User asks to secure IoT devices or embedded systems
- User asks about firmware security or secure boot
- User asks about OWASP IoT Top 10
- User asks about hardware security (TPM, HSM, secure elements)
- User asks about OTA (Over-The-Air) update security

---

## METHODOLOGY

### Step 1: Identify IoT Architecture
- Device (microcontroller, SoC, sensors)
- Communication (WiFi, BLE, Zigbee, LoRa, cellular)
- Gateway/Hub
- Cloud backend
- Mobile companion app

### Step 2: OWASP IoT Top 10 (2018)

| # | Category | What to Check |
|---|---|---|
| I1 | Weak Guessable Passwords | Default creds, weak passwords |
| I2 | Insecure Network Services | Unneeded ports, insecure protocols |
| I3 | Insecure Ecosystem Interfaces | API, web, mobile app security |
| I4 | Lack of Secure Update Mechanism | No signed updates, no rollback |
| I5 | Use of Insecure or Outdated Components | Vulnerable libraries, old firmware |
| I6 | Insufficient Privacy Protection | Excessive data collection, no consent |
| I7 | Insecure Data Transfer & Storage | No encryption, plaintext credentials |
| I8 | Lack of Device Management | No inventory, no patching, no decommissioning |
| I9 | Insecure Default Settings | Default passwords, insecure defaults |
| I10 | Lack of Physical Hardening | No tamper detection, debug ports open |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### Secure Boot Chain
```
ROM Bootloader (immutable) → verifies → SPL (Second Stage)
SPL → verifies → U-Boot
U-Boot → verifies → Kernel
Kernel → verifies → Rootfs
Rootfs → verifies → Application

Each stage verifies signature of next stage.
If verification fails → halt or recovery mode.
```

### Firmware Signing & OTA Update
```python
#!/usr/bin/env python3
"""Secure OTA update server — signs firmware, client verifies before install."""
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class FirmwareSigner:
    def __init__(self, private_key_path):
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    def sign_firmware(self, firmware_path):
        with open(firmware_path, 'rb') as f:
            firmware = f.read()

        # Sign the firmware hash
        signature = self.private_key.sign(
            firmware,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return signature

class FirmwareVerifier:
    def __init__(self, public_key_path):
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())

    def verify_firmware(self, firmware, signature):
        try:
            self.public_key.verify(
                signature,
                firmware,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
```

### Secure Communication (MQTT over TLS)
```python
import paho.mqtt.client as mqtt
import ssl

client = mqtt.Client()

# TLS configuration
client.tls_set(
    ca_certs='ca.crt',
    certfile='device.crt',
    keyfile='device.key',
    cert_reqs=ssl.CERT_REQUIRED,
    tls_version=ssl.PROTOCOL_TLSv1_2,
    ciphers='ECDHE-ECDSA-AES256-GCM-SHA384'
)

# Mutual TLS — device authenticates to broker, broker to device
client.username_pw_set('device-001', 'unique-per-device-token')
client.connect('mqtt.example.com', 8883)
```

### Device Identity (Unique Per Device)
```c
// Embedded C — generate unique device key at provisioning
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

int provision_device_key(unsigned char *key_buf, size_t key_len) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed from hardware entropy source (TRNG)
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        return -1;
    }

    // Generate unique key
    if (mbedtls_ctr_drbg_random(&ctr_drbg, key_buf, key_len) != 0) {
        return -1;
    }

    // Store in secure element (ATECC508A, TPM)
    store_in_secure_element(key_buf, key_len);

    return 0;
}
```

### Physical Hardening
```c
// Disable debug interfaces in production
void disable_debug_interfaces(void) {
    // Disable JTAG/SWD
    #ifdef PRODUCTION
    HAL_DBGMCU_DisableDBG_STANDBATE();
    HAL_DBGMCU_DisableDBG_STOP();
    HAL_DBGMCU_DisableDBG_SLEEP();

    // Lock flash read protection
    HAL_FLASH_OB_Lock();

    // Enable watchdog (prevent lockup)
    IWDG_Init(IWDG_PRESCALER_64, 0xFFF);
    #endif
}

// Tamper detection
void tamper_detection_init(void) {
    // Enable tamper interrupt on RTC
    HAL_RTCEx_SetTamper_IT(&hrtc);
    // On tamper: erase secure keys, halt device
}

void HAL_RTCEx_TamperStampEventCallback(RTC_HandleTypeDef *hrtc) {
    erase_secure_keys();
    halt_device();
}
```

---

## AUDIT CHECKLIST (IoT)

- [ ] No default/weak passwords (unique per device or forced change)
- [ ] Firmware signed and verified before boot
- [ ] OTA updates signed and verified
- [ ] Firmware rollback protection
- [ ] All communication encrypted (TLS 1.2+)
- [ ] Mutual TLS for device-to-cloud
- [ ] Unique device identity (per-device keys)
- [ ] Keys stored in secure element (TPM/SE)
- [ ] Debug interfaces disabled in production
- [ ] Tamper detection on physical access
- [ ] No hardcoded credentials in firmware
- [ ] Firmware encryption for IP protection
- [ ] Secure decommissioning (key erasure)
- [ ] Vulnerability disclosure program
- [ ] Minimal attack surface (only needed ports/services)
- [ ] Rate limiting on authentication
