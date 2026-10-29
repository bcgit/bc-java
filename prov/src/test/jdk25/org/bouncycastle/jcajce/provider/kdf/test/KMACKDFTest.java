package org.bouncycastle.jcajce.provider.kdf.test;

import java.security.Security;

import javax.crypto.KDF;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KMACKDFParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * The RFC 9629 KMAC KDF services against a direct KMAC computation, including the OID names.
 */
public class KMACKDFTest
    extends TestCase
{
    private static final byte[] SECRET = Hex.decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    private static final byte[] CONTEXT = Hex.decode("30140609608648016503040105020120040101");
    private static final byte[] CUSTOM = Strings.toByteArray("KEMRecipientInfo");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKMAC()
        throws Exception
    {
        doTest("KMAC128-KDF", 128, 32, null);
        doTest("KMAC256-KDF", 256, 32, null);
        doTest(NISTObjectIdentifiers.id_Kmac128.getId(), 128, 16, CUSTOM);
        doTest(NISTObjectIdentifiers.id_Kmac256.getId(), 256, 48, CUSTOM);
    }

    private void doTest(String name, int bits, int len, byte[] customization)
        throws Exception
    {
        KMAC mac = new KMAC(bits, customization == null ? new byte[0] : customization);
        mac.init(new KeyParameter(SECRET));
        mac.update(CONTEXT, 0, CONTEXT.length);
        byte[] expected = new byte[len];
        mac.doFinal(expected, 0, len);

        KDF kdf = KDF.getInstance(name, "BC");

        assertTrue(name, Arrays.areEqual(expected, kdf.deriveData(new KMACKDFParameterSpec(SECRET, CONTEXT, customization, len))));
        assertTrue(name, Arrays.areEqual(expected, kdf.deriveKey("AES", new KMACKDFParameterSpec(SECRET, CONTEXT, customization, len)).getEncoded()));

        // the customization string is part of the derivation
        assertFalse(name, Arrays.areEqual(expected, kdf.deriveData(new KMACKDFParameterSpec(SECRET, CONTEXT, Strings.toByteArray("other"), len))));
    }
}
