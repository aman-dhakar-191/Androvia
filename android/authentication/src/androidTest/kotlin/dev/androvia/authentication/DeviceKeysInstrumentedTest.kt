package dev.androvia.authentication

import dev.androvia.core.DeviceId
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceKeysInstrumentedTest {
    private val alias = "androvia.test." + UUID.randomUUID()
    private val keys = AndroidKeystoreDeviceKeys(alias)

    @After fun cleanup() = keys.deleteKey()

    @Test fun identityIsStableAcrossInstances() {
        val a = keys.identity()
        val b = AndroidKeystoreDeviceKeys(alias).identity()
        assertEquals(a.deviceId, b.deviceId)
        assertArrayEquals(a.publicKeySpki, b.publicKeySpki)
    }

    @Test fun deviceIdIsHashOfPublicKey() {
        val id = keys.identity()
        assertEquals(DeviceId.fromPublicKeyDer(id.publicKeySpki), id.deviceId)
        assertEquals(64, id.deviceId.length)
    }

    @Test fun signatureVerifiesAndRejectsTamperedData() {
        val id = keys.identity()
        val data = "challenge".toByteArray()
        val sig = keys.sign(data)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(id.publicKeySpki))
        fun isValid(msg: ByteArray): Boolean {
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(pub)
            verifier.update(msg)
            return verifier.verify(sig)
        }
        assertTrue(isValid(data))
        assertFalse(isValid("challengf".toByteArray()))
    }

    @Test fun differentAliasesGiveDifferentIdentities() {
        val other = AndroidKeystoreDeviceKeys("androvia.test." + UUID.randomUUID())
        try {
            assertNotEquals(keys.identity().deviceId, other.identity().deviceId)
        } finally {
            other.deleteKey()
        }
    }

    @Test fun deletingTheKeyChangesTheIdentity() {
        val before = keys.identity().deviceId
        keys.deleteKey()
        assertNotEquals(before, keys.identity().deviceId)
    }

    @Test fun securityLevelIsDeterminedNotAssumed() {
        assertNotEquals(KeySecurityLevel.UNKNOWN, keys.identity().securityLevel)
    }
}
