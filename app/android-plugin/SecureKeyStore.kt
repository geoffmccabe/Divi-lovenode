// LoveNode — Android Keystore backend for the staking key.
//
// AUTHORED, NOT YET COMPILED. This needs the Android toolchain to build and run;
// it is written to be dropped into the Tauri Android plugin project that
// `cargo tauri android init` generates. See app/README-ANDROID.md.
//
// ── The security design ─────────────────────────────────────────────────────
// The Android Keystore cannot hold a secp256k1 key and sign arbitrary Divi block
// hashes with it — Keystore only signs with the algorithms it supports, and Divi
// signing must happen in Rust. So we use Keystore for what it is best at:
// a hardware-backed AES-GCM key that NEVER leaves the secure element, used to
// ENCRYPT the staking secret at rest.
//
//   store():  Rust hands us 32 secret bytes  ->  AES-GCM encrypt with the
//             hardware key  ->  save {iv, ciphertext} to app-private files.
//   load():   read the file  ->  AES-GCM decrypt (this is the point the OS can
//             require device unlock / biometric)  ->  return the 32 bytes to
//             Rust, which signs and immediately drops them.
//
// The plaintext secret exists only briefly in memory during signing. The key
// that protects it at rest is non-exportable and hardware-backed where the
// device supports it (StrongBox / TEE).

package love.divi.lovenode

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecureKeyStore(private val filesDir: File) {

    private val androidKeyStore = "AndroidKeyStore"
    private val wrapKeyAlias = "lovenode_wrap_key_v1"
    private val secretFile = File(filesDir, "staking_key.enc")
    private val addrFile = File(filesDir, "addresses.txt")
    private val gcmTagBits = 128
    private val ivLen = 12

    /** True once an encrypted staking secret is stored. */
    fun hasKey(): Boolean = secretFile.exists()

    /** Encrypt and store 32 secret bytes plus the compressed flag. */
    fun store(secret: ByteArray, compressed: Boolean) {
        require(secret.size == 32) { "staking secret must be 32 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrapKey())
        val iv = cipher.iv
        // prepend the compressed flag byte to the plaintext, so load() recovers it
        val plain = ByteArray(33)
        plain[0] = if (compressed) 1 else 0
        System.arraycopy(secret, 0, plain, 1, 32)
        val ct = cipher.doFinal(plain)
        // file layout: [ivLen][iv][ciphertext]
        secretFile.outputStream().use {
            it.write(ivLen)
            it.write(iv)
            it.write(ct)
        }
        // wipe the transient plaintext copy
        plain.fill(0)
    }

    /**
     * Decrypt and return {compressed flag, 32 secret bytes}. Triggers device
     * unlock / biometric (the wrap key requires user auth).
     *
     * IMPORTANT design note — overnight staking:
     * Because auth is required, load() CANNOT run while the phone is locked. So
     * do NOT call it per-signature. Call it ONCE when the user taps "Start
     * staking" (they are present and can authenticate), hand the secret to the
     * Rust staking session, and keep it in the foreground-service process memory
     * for the run. The key is then available to sign blocks overnight without
     * further prompts. If the OS fully kills the process, the user re-authenticates
     * next time they open the app. This is the standard hot-staking trade-off:
     * at-rest the key is hardware-protected and user-gated; during an active
     * session it lives in the running process, like any staking wallet.
     */
    fun load(): Pair<Boolean, ByteArray> {
        require(secretFile.exists()) { "no staking key has been set up yet" }
        val bytes = secretFile.readBytes()
        val ivl = bytes[0].toInt()
        require(ivl == ivLen && bytes.size > 1 + ivl) { "corrupt key file" }
        val iv = bytes.copyOfRange(1, 1 + ivl)
        val ct = bytes.copyOfRange(1 + ivl, bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getWrapKey(), GCMParameterSpec(gcmTagBits, iv))
        val plain = cipher.doFinal(ct)
        val compressed = plain[0].toInt() == 1
        val secret = plain.copyOfRange(1, 33)
        plain.fill(0)
        return Pair(compressed, secret)
    }

    fun setAddresses(addresses: List<String>) {
        addrFile.writeText(addresses.joinToString("\n"))
    }

    fun addresses(): List<String> =
        if (addrFile.exists()) addrFile.readLines().filter { it.isNotBlank() } else emptyList()

    /** Permanently delete the key, addresses, AND the hardware wrap key.
     *  Destroying the wrap key matters: without it, a ciphertext retained via
     *  backup or flash remanence cannot be decrypted, so wipe is not reversible
     *  by restoring an old copy. */
    fun wipe() {
        secretFile.delete()
        addrFile.delete()
        try {
            val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
            ks.deleteEntry(wrapKeyAlias)
        } catch (_: Exception) { /* already gone */ }
    }

    // ── hardware-backed AES key ─────────────────────────────────────────────
    private fun getOrCreateWrapKey(): SecretKey {
        getWrapKeyOrNull()?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
        val spec = KeyGenParameterSpec.Builder(
            wrapKeyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // Require the device to be unlocked (and, where the app opts in, a
            // biometric) before this key can decrypt the staking secret. Without
            // this, any in-process path or app-data attacker recovers the key
            // silently -- so it is ON, not commented out.
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                30, // seconds the auth stays valid, so signing a run of blocks
                    // doesn't prompt on every single one
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC
            )
            // StrongBox (a dedicated security chip) where the device has one.
            // Wrap in try/catch at the call site: not all devices provide it.
            .setIsStrongBoxBacked(true)
            .build()
        gen.init(spec)
        return gen.generateKey()
    }

    private fun getWrapKey(): SecretKey =
        getWrapKeyOrNull() ?: error("wrap key missing; cannot decrypt staking key")

    private fun getWrapKeyOrNull(): SecretKey? {
        val ks = KeyStore.getInstance(androidKeyStore).apply { load(null) }
        return (ks.getEntry(wrapKeyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }
}
