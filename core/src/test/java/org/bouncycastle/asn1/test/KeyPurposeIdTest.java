package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.util.test.SimpleTest;

/**
 * OID coverage for the recently-added Extended Key Usage KeyPurposeId constants (RFC 9336, RFC 9509,
 * RFC 9734, RFC 9809 and RFC 4556), guarding their branch numbers against typos. Most live under the
 * PKIX id-kp arc 1.3.6.1.5.5.7.3; the PKINIT pair sits under the Kerberos id-pkinit arc
 * 1.3.6.1.5.2.3. Each is checked to round-trip through getInstance().
 */
public class KeyPurposeIdTest
    extends SimpleTest
{
    public String getName()
    {
        return "KeyPurposeId";
    }

    public void performTest()
        throws Exception
    {
        checkKeyPurposeId(KeyPurposeId.id_kp_documentSigning, "1.3.6.1.5.5.7.3.36");           // RFC 9336
        checkKeyPurposeId(KeyPurposeId.id_kp_jwt, "1.3.6.1.5.5.7.3.37");                       // RFC 9509
        checkKeyPurposeId(KeyPurposeId.id_kp_httpContentEncrypt, "1.3.6.1.5.5.7.3.38");        // RFC 9509
        checkKeyPurposeId(KeyPurposeId.id_kp_oauthAccessTokenSigning, "1.3.6.1.5.5.7.3.39");   // RFC 9509
        checkKeyPurposeId(KeyPurposeId.id_kp_imUri, "1.3.6.1.5.5.7.3.40");                     // RFC 9734
        checkKeyPurposeId(KeyPurposeId.id_kp_configSigning, "1.3.6.1.5.5.7.3.41");             // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_trustAnchorConfigSigning, "1.3.6.1.5.5.7.3.42");  // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_updatePackageSigning, "1.3.6.1.5.5.7.3.43");      // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_safetyCommunication, "1.3.6.1.5.5.7.3.44");       // RFC 9809

        checkKeyPurposeId(KeyPurposeId.id_kp_secureShellClient, "1.3.6.1.5.5.7.3.21");           // RFC 6187
        checkKeyPurposeId(KeyPurposeId.id_kp_secureShellServer, "1.3.6.1.5.5.7.3.22");           // RFC 6187
        checkKeyPurposeId(KeyPurposeId.id_kp_cmcArchive, "1.3.6.1.5.5.7.3.29");                  // RFC 6402
        checkKeyPurposeId(KeyPurposeId.id_kp_bundleSecurity, "1.3.6.1.5.5.7.3.35");              // RFC 9174

        // Kerberos PKINIT, id-pkinit arc rather than id-kp
        checkKeyPurposeId(KeyPurposeId.id_kp_pkinitClientAuth, "1.3.6.1.5.2.3.4");             // RFC 4556
        checkKeyPurposeId(KeyPurposeId.id_kp_pkinitKdc, "1.3.6.1.5.2.3.5");                    // RFC 4556
    }

    private void checkKeyPurposeId(KeyPurposeId kp, String expectedOid)
        throws Exception
    {
        isEquals("wrong OID for KeyPurposeId " + expectedOid, expectedOid, kp.getId());

        KeyPurposeId recovered = KeyPurposeId.getInstance(ASN1Primitive.fromByteArray(kp.getEncoded()));
        isTrue("KeyPurposeId did not round-trip: " + expectedOid, kp.equals(recovered));
    }

    public static void main(String[] args)
    {
        runTest(new KeyPurposeIdTest());
    }
}
