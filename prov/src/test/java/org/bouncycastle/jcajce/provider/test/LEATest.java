package org.bouncycastle.jcajce.provider.test;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class LEATest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testEcbKnownAnswer()
        throws Exception
    {
        // KAT vectors lifted from core/src/test/java/.../LEATest (TTAS standard).
        kat("LEA-128", "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
                       "101112131415161718191a1b1c1d1e1f",
                       "9fc84e3528c6c6185532c7a704648bfd");
        kat("LEA-192", "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687",
                       "202122232425262728292a2b2c2d2e2f",
                       "6fb95e325aad1b878cdcf5357674c6f2");
        kat("LEA-256", "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f",
                       "303132333435363738393a3b3c3d3e3f",
                       "d651aff647b189c13a8900ca27f9e197");
    }

    private void kat(String label, String hexKey, String hexPt, String hexExpected)
        throws Exception
    {
        SecretKey k = new SecretKeySpec(Hex.decode(hexKey), "LEA");
        Cipher enc = Cipher.getInstance("LEA/ECB/NoPadding", BC);
        enc.init(Cipher.ENCRYPT_MODE, k);
        byte[] ct = enc.doFinal(Hex.decode(hexPt));
        assertTrue(label + " encrypt KAT", Arrays.areEqual(Hex.decode(hexExpected), ct));

        Cipher dec = Cipher.getInstance("LEA/ECB/NoPadding", BC);
        dec.init(Cipher.DECRYPT_MODE, k);
        byte[] pt = dec.doFinal(ct);
        assertTrue(label + " decrypt KAT", Arrays.areEqual(Hex.decode(hexPt), pt));
    }

    public void testCbcCfbOfbRoundTrip()
        throws Exception
    {
        byte[] msg = "WallaWallaWashington-WallaWallaWashington".getBytes();
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++)
        {
            iv[i] = (byte)i;
        }

        SecretKey k = newKey(192);

        for (String transformation : new String[]{
            "LEA/CBC/PKCS5Padding",
            "LEA/CBC/NoPadding",
            "LEA/CFB/NoPadding",
            "LEA/OFB/NoPadding"})
        {
            // For NoPadding we need the input to be a multiple of the block size.
            byte[] input = transformation.endsWith("NoPadding")
                ? Arrays.copyOfRange(msg, 0, 32) : msg;

            Cipher enc = Cipher.getInstance(transformation, BC);
            enc.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
            byte[] ct = enc.doFinal(input);

            Cipher dec = Cipher.getInstance(transformation, BC);
            dec.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
            byte[] pt = dec.doFinal(ct);

            assertTrue(transformation + " round-trip", Arrays.areEqual(input, pt));
        }
    }

    public void testGcmCcmRoundTrip()
        throws Exception
    {
        byte[] msg = "the quick brown fox".getBytes();
        byte[] nonce = new byte[12];

        SecretKey k = newKey(128);

        Cipher gcm = Cipher.getInstance("LEA-GCM", BC);
        gcm.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, nonce));
        byte[] ct = gcm.doFinal(msg);
        gcm.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, nonce));
        assertTrue("LEA-GCM round-trip", Arrays.areEqual(msg, gcm.doFinal(ct)));

        Cipher ccm = Cipher.getInstance("LEA-CCM", BC);
        ccm.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(96, nonce));
        ct = ccm.doFinal(msg);
        ccm.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(96, nonce));
        assertTrue("LEA-CCM round-trip", Arrays.areEqual(msg, ccm.doFinal(ct)));
    }

    public void testKeyGenAndSecretKeyFactory()
        throws Exception
    {
        // Default key size is 128 bits.
        SecretKey def = KeyGenerator.getInstance("LEA", BC).generateKey();
        assertEquals(16, def.getEncoded().length);

        for (int bits : new int[]{128, 192, 256})
        {
            KeyGenerator kg = KeyGenerator.getInstance("LEA", BC);
            kg.init(bits);
            SecretKey k = kg.generateKey();
            assertEquals(bits / 8, k.getEncoded().length);
            assertEquals("LEA", k.getAlgorithm());
        }

        // SecretKeyFactory should round-trip an encoded SecretKey.
        byte[] raw = new byte[16];
        for (int i = 0; i < raw.length; i++)
        {
            raw[i] = (byte)i;
        }
        SecretKey original = new SecretKeySpec(raw, "LEA");
        SecretKeyFactory skf = SecretKeyFactory.getInstance("LEA", BC);
        SecretKey roundTrip = skf.translateKey(original);
        assertTrue("SecretKeyFactory round-trip",
            Arrays.areEqual(original.getEncoded(), roundTrip.getEncoded()));
    }

    public void testCmacGmacPoly1305()
        throws Exception
    {
        byte[] data = "MAC me please".getBytes();

        SecretKey k128 = newKey(128);

        Mac cmac = Mac.getInstance("LEA-CMAC", BC);
        cmac.init(k128);
        cmac.update(data);
        byte[] cmacOut = cmac.doFinal();
        assertEquals(16, cmacOut.length);
        assertTrue("LEA-CMAC determinism",
            Arrays.areEqual(cmacOut, recomputeMac("LEA-CMAC", k128, data, null)));

        Mac gmac = Mac.getInstance("LEA-GMAC", BC);
        gmac.init(k128, new IvParameterSpec(new byte[12]));
        gmac.update(data);
        byte[] gmacOut = gmac.doFinal();
        assertEquals(16, gmacOut.length);
        assertTrue("LEA-GMAC determinism",
            Arrays.areEqual(gmacOut, recomputeMac("LEA-GMAC", k128, data, new byte[12])));

        // Poly1305 requires a key conditioned by Poly1305KeyGenerator.
        SecretKey polyKey = KeyGenerator.getInstance("POLY1305-LEA", BC).generateKey();
        Mac poly = Mac.getInstance("POLY1305-LEA", BC);
        poly.init(polyKey, new IvParameterSpec(new byte[16]));
        poly.update(data);
        assertEquals(16, poly.doFinal().length);
    }

    private byte[] recomputeMac(String algo, SecretKey key, byte[] data, byte[] iv)
        throws Exception
    {
        Mac mac = Mac.getInstance(algo, BC);
        if (iv == null)
        {
            mac.init(key);
        }
        else
        {
            mac.init(key, new IvParameterSpec(iv));
        }
        mac.update(data);
        return mac.doFinal();
    }

    public void testAlgorithmParameters()
        throws Exception
    {
        // AlgorithmParameters.LEA holds an IV and round-trips ASN.1.
        AlgorithmParameterGenerator pg = AlgorithmParameterGenerator.getInstance("LEA", BC);
        AlgorithmParameters params = pg.generateParameters();
        assertEquals("LEA", params.getAlgorithm());
        IvParameterSpec spec = params.getParameterSpec(IvParameterSpec.class);
        assertEquals(16, spec.getIV().length);

        // AlgorithmParameters.LEA-GCM and LEA-CCM accept a GCMParameterSpec.
        for (String svc : new String[]{"LEA-GCM", "LEA-CCM"})
        {
            AlgorithmParameters ap = AlgorithmParameters.getInstance(svc, BC);
            ap.init(new GCMParameterSpec(128, new byte[12]));
            byte[] enc = ap.getEncoded();
            AlgorithmParameters reparsed = AlgorithmParameters.getInstance(svc, BC);
            reparsed.init(enc);
            AlgorithmParameterSpec back = reparsed.getParameterSpec(AlgorithmParameterSpec.class);
            assertNotNull(svc + " AlgorithmParameters reparse", back);
        }
    }

    public void testUnregisteredKeyGeneratorAliases()
        throws Exception
    {
        // Make sure we haven't accidentally registered a service we don't intend to expose.
        try
        {
            KeyGenerator.getInstance("LEAWRAP", BC);
            fail("LEAWRAP should not be registered");
        }
        catch (NoSuchAlgorithmException expected)
        {
            // expected
        }
    }

    private SecretKey newKey(int bits)
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("LEA", BC);
        kg.init(bits);
        return kg.generateKey();
    }
}
