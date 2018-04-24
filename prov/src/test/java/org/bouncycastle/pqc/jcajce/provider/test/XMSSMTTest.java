package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Test cases for the use of XMSS^MT with the BCPQC provider.
 */
public class XMSSMTTest
    extends TestCase
{
    byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testKeyExtraction()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        PrivateKey nKey = xmssSig.getUpdatedPrivateKey();

        assertFalse(kp.getPrivate().equals(nKey));

        xmssSig.update(msg, 0, msg.length);

        try
        {
            sig.sign();
            fail("no exception after key extraction");
        }
        catch (SignatureException e)
        {
            assertEquals("signing key no longer usable", e.getMessage());
        }

        try
        {
            xmssSig.getUpdatedPrivateKey();
            fail("no exception after key extraction");
        }
        catch (IllegalStateException e)
        {
            assertEquals("signature object not in a signing state", e.getMessage());
        }

        xmssSig.initSign(nKey);

        xmssSig.update(msg, 0, msg.length);

        s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTSha256SignatureMultiple()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        StateAwareSignature sig1 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        StateAwareSignature sig2 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        StateAwareSignature sig3 = (StateAwareSignature)Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        sig1.initSign(kp.getPrivate());

        sig2.initSign(sig1.getUpdatedPrivateKey());

        sig3.initSign(sig2.getUpdatedPrivateKey());

        sig1.update(msg, 0, msg.length);

        byte[] s1 = sig1.sign();

        sig2.update(msg, 0, msg.length);

        byte[] s2 = sig2.sign();

        sig3.update(msg, 0, msg.length);

        byte[] s3 = sig3.sign();

        sig1.initVerify(kp.getPublic());

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s1));

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s2));

        sig1.update(msg, 0, msg.length);

        assertTrue(sig1.verify(s3));
    }

    public void testXMSSMTSha512KeyFactory()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);

        XMSSMTKey pubKey = (XMSSMTKey)keyFactory.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);

        assertEquals(20, privKey.getHeight());
        assertEquals(10, privKey.getLayers());
        assertEquals(XMSSParameterSpec.SHA512, privKey.getTreeDigest());

        assertEquals(20, pubKey.getHeight());
        assertEquals(10, pubKey.getLayers());
        assertEquals(XMSSParameterSpec.SHA512, pubKey.getTreeDigest());
    }

    public void testXMSSMTSha256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTSha512Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(10, 5, XMSSMTParameterSpec.SHA512), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTShake128Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE128), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHAKE128withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testXMSSMTShake256Signature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHAKE256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHAKE256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        xmssSig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        xmssSig.initVerify(kp.getPublic());

        xmssSig.update(msg, 0, msg.length);

        assertTrue(xmssSig.verify(s));
    }

    public void testKeyRebuild()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(6, 3, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");

        assertTrue(sig instanceof StateAwareSignature);

        StateAwareSignature xmssSig = (StateAwareSignature)sig;

        xmssSig.initSign(kp.getPrivate());

        for (int i = 0; i != 5; i++)
        {
            xmssSig.update(msg, 0, msg.length);

            xmssSig.sign();
        }

        PrivateKey pKey = xmssSig.getUpdatedPrivateKey();

        PrivateKeyInfo pKeyInfo = PrivateKeyInfo.getInstance(pKey.getEncoded());

        KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");

        ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());

        // create a new PrivateKeyInfo containing a key with no BDS state.
        pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
            new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0), seq.getObjectAt(1) }));

        XMSSMTKey privKey = (XMSSMTKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));

        xmssSig.initSign(pKey);

        xmssSig.update(msg, 0, msg.length);

        byte[] sig1 = xmssSig.sign();

        xmssSig.initSign((PrivateKey)privKey);

        xmssSig.update(msg, 0, msg.length);

        byte[] sig2 = xmssSig.sign();

        // make sure we get the same signature as the two keys should now
        // be in the same state.
        assertTrue(Arrays.areEqual(sig1, sig2));
    }
}
