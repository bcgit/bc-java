package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.util.test.SimpleTest;

/**
 * OID coverage for the recently-added Extended Key Usage KeyPurposeId constants (RFC 9336, RFC 9734
 * and RFC 9809), guarding their id-kp branch numbers against typos. All live under the PKIX id-kp
 * arc 1.3.6.1.5.5.7.3, and each is checked to round-trip through getInstance().
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
        checkKeyPurposeId(KeyPurposeId.id_kp_imUri, "1.3.6.1.5.5.7.3.40");                     // RFC 9734
        checkKeyPurposeId(KeyPurposeId.id_kp_configSigning, "1.3.6.1.5.5.7.3.41");             // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_trustAnchorConfigSigning, "1.3.6.1.5.5.7.3.42");  // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_updatePackageSigning, "1.3.6.1.5.5.7.3.43");      // RFC 9809
        checkKeyPurposeId(KeyPurposeId.id_kp_safetyCommunication, "1.3.6.1.5.5.7.3.44");       // RFC 9809
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
