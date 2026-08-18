package org.bouncycastle.cms.test;

import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * The SecureRandom passed to {@link JceCMSContentEncryptorBuilder#setSecureRandom} has to drive the
 * content IV / nonce generation, not just RC2. Previously it reached only the RC2 branch of
 * EnvelopedDataHelper.generateParameters, so for every other algorithm - including AES-GCM - the IV
 * came from a default SecureRandom and setSecureRandom() was silently ignored.
 */
public class ContentEncryptorRandomTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSuppliedRandomDrivesGcmNonce()
        throws Exception
    {
        byte[] nonce = new byte[12];
        for (int i = 0; i != nonce.length; i++)
        {
            nonce[i] = (byte)(0xC0 + i);
        }

        // the parameters for AES-GCM are a SEQUENCE whose first element is the nonce OCTET STRING
        ASN1Sequence params = ASN1Sequence.getInstance(gcmParameters(CMSAlgorithm.AES256_GCM, nonce));

        assertTrue("supplied SecureRandom did not drive the GCM nonce",
            Arrays.areEqual(nonce, ASN1OctetString.getInstance(params.getObjectAt(0)).getOctets()));
    }

    public void testSuppliedRandomDrivesCbcIV()
        throws Exception
    {
        byte[] iv = new byte[16];
        for (int i = 0; i != iv.length; i++)
        {
            iv[i] = (byte)(0xA0 + i);
        }

        // the parameters for AES-CBC are the IV as a bare OCTET STRING
        byte[] emitted = ASN1OctetString.getInstance(
            gcmParameters(CMSAlgorithm.AES256_CBC, iv)).getOctets();

        assertTrue("supplied SecureRandom did not drive the CBC IV", Arrays.areEqual(iv, emitted));
    }

    private static org.bouncycastle.asn1.ASN1Encodable gcmParameters(ASN1ObjectIdentifier alg, byte[] ivMaterial)
        throws Exception
    {
        // a supplied key means the SecureRandom is consumed only for the IV / nonce, so a
        // FixedSecureRandom emitting exactly ivMaterial makes the emitted parameters deterministic
        SecureRandom fixed = new FixedSecureRandom(ivMaterial);

        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(alg)
            .setProvider("BC")
            .setSecureRandom(fixed)
            .build(new byte[32]);

        return enc.getAlgorithmIdentifier().getParameters();
    }
}
