package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

/**
 * Regression tests for the XMSS / XMSS^MT public-key decode path in {@link PublicKeyFactory}. The
 * raw RFC 9802 / RFC 8391 SubjectPublicKeyInfo form prefixes the key material with a 4-octet
 * parameter-set OID; a malformed key whose material is shorter than that prefix, or which carries a
 * valid OID but truncated root/seed material, must be rejected with an IOException rather than
 * leaking an ArrayIndexOutOfBoundsException / IllegalArgumentException out of the declared contract.
 */
public class XMSSPublicKeyParseTest
    extends TestCase
{
    // every OID that routes through the XMSSConverter / XMSSMTConverter in PublicKeyFactory
    private static final ASN1ObjectIdentifier[] XMSS_OIDS = new ASN1ObjectIdentifier[]
    {
        PQCObjectIdentifiers.xmss,
        IsaraObjectIdentifiers.id_alg_xmss,
        IANAObjectIdentifiers.id_alg_xmss_hashsig,
        PQCObjectIdentifiers.xmss_mt,
        IsaraObjectIdentifiers.id_alg_xmssmt,
        IANAObjectIdentifiers.id_alg_xmssmt_hashsig,
    };

    public void testShortPublicKeyRejected()
        throws Exception
    {
        // key material shorter than the 4-octet OID prefix used to throw ArrayIndexOutOfBoundsException
        for (int i = 0; i != XMSS_OIDS.length; i++)
        {
            for (int len = 0; len != 4; len++)
            {
                SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(XMSS_OIDS[i]), new byte[len]);
                try
                {
                    PublicKeyFactory.createKey(spki);
                    fail("expected IOException for " + XMSS_OIDS[i] + " with key length " + len);
                }
                catch (IOException e)
                {
                    // expected
                }
            }
        }
    }

    public void testTruncatedPublicKeyRejected()
        throws Exception
    {
        // a valid 4-octet parameter-set OID (0x01) followed by truncated root/seed material used to
        // throw IllegalArgumentException ("public key has wrong size") out of the key builder
        byte[] keyEnc = new byte[]{0, 0, 0, 1, 0, 0, 0, 0};
        for (int i = 0; i != XMSS_OIDS.length; i++)
        {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(XMSS_OIDS[i]), keyEnc);
            try
            {
                PublicKeyFactory.createKey(spki);
                fail("expected IOException for truncated " + XMSS_OIDS[i]);
            }
            catch (IOException e)
            {
                // expected
            }
        }
    }
}
