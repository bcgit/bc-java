package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class AEADTest extends SimpleTest
{

    // EAX test vector from EAXTest
    private byte[] K2 = Hex.decode("91945D3F4DCBEE0BF45EF52255F095A4");
    private byte[] N2 = Hex.decode("BECAF043B0A23D843194BA972C66DEBD");
    private byte[] A2 = Hex.decode("FA3BFD4806EB53FA");
    private byte[] P2 = Hex.decode("F7FB");
    private byte[] C2 = Hex.decode("19DD5C4C9331049D0BDAB0277408F67967E5");
    // C2 with only 64bit MAC (default for EAX)
    private byte[] C2_short = Hex.decode("19DD5C4C9331049D0BDA");

    private byte[] KGCM = Hex.decode("00000000000000000000000000000000");
    private byte[] NGCM = Hex.decode("000000000000000000000000");
    private byte[] CGCM = Hex.decode("58e2fccefa7e3061367f1d57a4e7455a");

    public String getName()
    {
        return "AEAD";
    }

    public void performTest() throws Exception
    {
        boolean aeadAvailable = false;
        try
        {
            this.getClass().getClassLoader().loadClass("javax.crypto.spec.GCMParameterSpec");
            aeadAvailable = true;
        }
        catch (ClassNotFoundException e)
        {
        }
        testAEADParameterSpec(K2, N2, A2, P2, C2);
        if (aeadAvailable)
        {
            checkCipherWithAD(K2, N2, A2, P2, C2_short);
            testGCMParameterSpec(K2, N2, A2, P2, C2);
            testGCMParameterSpecWithRepeatKey(K2, N2, A2, P2, C2);
            testGCMGeneric(KGCM, NGCM, new byte[0], new byte[0], CGCM);
            testGCMParameterSpecWithMultipleUpdates(K2, N2, A2, P2, C2);
            testRepeatedGCMWithSpec(KGCM, NGCM, A2, P2, Hex.decode("f4732d84342623f65b7d63c3c335dd44b87d"));
            testCCMParameterSpecWithShortTag();
        }
        else
        {
            System.err.println("GCM AEADTests disabled due to JDK");
        }
        testTampering(aeadAvailable);
    }

    private void testTampering(boolean aeadAvailable)
        throws InvalidKeyException,
        InvalidAlgorithmParameterException,
        NoSuchAlgorithmException,
        NoSuchProviderException,
        NoSuchPaddingException,
        IllegalBlockSizeException,
        BadPaddingException
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        final SecretKeySpec key = new SecretKeySpec(new byte[eax.getBlockSize()], eax.getAlgorithm());
        final IvParameterSpec iv = new IvParameterSpec(new byte[eax.getBlockSize()]);

        eax.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = eax.doFinal(new byte[100]);
        ciphertext[ciphertext.length - 1] = (byte)(ciphertext[ciphertext.length - 1] + 1);  // Tamper

        try
        {
            eax.init(Cipher.DECRYPT_MODE, key, iv);
            eax.doFinal(ciphertext);
            fail("Tampered ciphertext should be invalid");
        }
        catch (BadPaddingException e)
        {
            if (aeadAvailable)
            {
                if (!e.getClass().getName().equals("javax.crypto.AEADBadTagException"))
                {
                    fail("Tampered AEAD ciphertext should fail with AEADBadTagException when available, got: "+e.getClass().getName());
                }
            }
        }
    }

    private void checkCipherWithAD(byte[] K,
                                   byte[] N,
                                   byte[] A,
                                   byte[] P,
                                   byte[] C) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, NoSuchProviderException
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");
        IvParameterSpec iv = new IvParameterSpec(N);
        eax.init(Cipher.ENCRYPT_MODE, key, iv);

        eax.updateAAD(A);
        byte[] c = eax.doFinal(P);

        if (!areEqual(C, c))
        {
            fail("JCE encrypt with additional data failed.");
        }

        eax.init(Cipher.DECRYPT_MODE, key, iv);
        eax.updateAAD(A);
        byte[] p = eax.doFinal(C);

        if (!areEqual(P, p))
        {
            fail("JCE decrypt with additional data failed.");
        }
    }

    private void testAEADParameterSpec(byte[] K,
                                       byte[] N,
                                       byte[] A,
                                       byte[] P,
                                       byte[] C)
        throws Exception
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");

        AEADParameterSpec spec = new AEADParameterSpec(N, 128, A);
        eax.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] c = eax.doFinal(P);

        if (!Arrays.areEqual(C, c))
        {
            TestCase.fail("JCE encrypt with additional data and AEADParameterSpec failed.");
        }

        // doFinal test
        c = eax.doFinal(P);

        if (!Arrays.areEqual(C, c))
        {
            TestCase.fail("JCE encrypt with additional data and AEADParameterSpec failed after do final");
        }

        eax.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] p = eax.doFinal(C);

        if (!Arrays.areEqual(P, p))
        {
            TestCase.fail("JCE decrypt with additional data and AEADParameterSpec failed.");
        }

        AlgorithmParameters algParams = eax.getParameters();

        byte[] encParams = algParams.getEncoded();

        GCMParameters gcmParameters = GCMParameters.getInstance(encParams);

        if (!Arrays.areEqual(spec.getIV(), gcmParameters.getNonce()) || spec.getMacSizeInBits() != gcmParameters.getIcvLen() * 8)
        {
            TestCase.fail("parameters mismatch");
        }

        // note: associated data is not preserved
        AEADParameterSpec cSpec = algParams.getParameterSpec(AEADParameterSpec.class);
        if (!Arrays.areEqual(spec.getIV(), cSpec.getNonce()) || spec.getMacSizeInBits() != cSpec.getMacSizeInBits()
            || cSpec.getAssociatedData() != null)
        {
            TestCase.fail("parameters mismatch");
        }

        AlgorithmParameters aeadParams = AlgorithmParameters.getInstance("GCM", "BC");

        aeadParams.init(spec);

        cSpec = aeadParams.getParameterSpec(AEADParameterSpec.class);
        if (!Arrays.areEqual(spec.getIV(), cSpec.getNonce()) || spec.getMacSizeInBits() != cSpec.getMacSizeInBits()
            || cSpec.getAssociatedData() != null)
        {
            TestCase.fail("parameters mismatch");
        }
    }

    private void testGCMParameterSpec(byte[] K,
                                      byte[] N,
                                      byte[] A,
                                      byte[] P,
                                      byte[] C)
        throws InvalidKeyException,
        NoSuchAlgorithmException, NoSuchPaddingException,
        IllegalBlockSizeException, BadPaddingException,
        InvalidAlgorithmParameterException, NoSuchProviderException, IOException
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");

        // GCMParameterSpec mapped to AEADParameters and overrides default MAC
        // size
        GCMParameterSpec spec = new GCMParameterSpec(128, N);
        eax.init(Cipher.ENCRYPT_MODE, key, spec);

        eax.updateAAD(A);
        byte[] c = eax.doFinal(P);

        if (!areEqual(C, c))
        {
            fail("JCE encrypt with additional data and GCMParameterSpec failed.");
        }

        eax.init(Cipher.DECRYPT_MODE, key, spec);
        eax.updateAAD(A);
        byte[] p = eax.doFinal(C);

        if (!areEqual(P, p))
        {
            fail("JCE decrypt with additional data and GCMParameterSpec failed.");
        }

        AlgorithmParameters algParams = eax.getParameters();

        byte[] encParams = algParams.getEncoded();

        GCMParameters gcmParameters = GCMParameters.getInstance(encParams);

        if (!Arrays.areEqual(spec.getIV(), gcmParameters.getNonce()) || spec.getTLen() != gcmParameters.getIcvLen() * 8)
        {
            fail("parameters mismatch");
        }
    }

    private void testGCMParameterSpecWithMultipleUpdates(byte[] K,
                                      byte[] N,
                                      byte[] A,
                                      byte[] P,
                                      byte[] C)
        throws Exception
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");
        SecureRandom random = new SecureRandom();

        for (int i = 900; i != 1024; i++)
        {
            byte[] message = new byte[i];

            random.nextBytes(message);

            // GCMParameterSpec mapped to AEADParameters and overrides the default MAC size. The
            // nonce is varied per iteration: re-initialising the same Cipher for encryption with a
            // repeated key+nonce is rejected by the AEAD nonce-reuse guard, and this round-trip
            // test does not depend on the nonce value.
            byte[] n = Arrays.clone(N);
            for (int b = 0; b < n.length && b < 4; b++)
            {
                n[b] ^= (byte)(i >>> (8 * b));
            }
            GCMParameterSpec spec = new GCMParameterSpec(128, n);

            eax.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] out = new byte[eax.getOutputSize(i)];

            int offSet = 0;

            int count;
            for (count = 0; count < i / 21; count++)
            {
                offSet += eax.update(message, count * 21, 21, out, offSet);
            }

            offSet += eax.doFinal(message, count * 21, i - (count * 21), out, offSet);

            byte[] dec = new byte[i];
            int    len = offSet;

            eax.init(Cipher.DECRYPT_MODE, key, spec);

            offSet = 0;
            for (count = 0; count < len / 10; count++)
            {
                offSet += eax.update(out, count * 10, 10, dec, offSet);
            }

            offSet += eax.doFinal(out, count * 10, len - (count * 10), dec, offSet);

            if (!Arrays.areEqual(message, dec) || offSet != message.length)
            {
                fail("message mismatch");
            }
        }
    }


    private void testGCMParameterSpecWithRepeatKey(byte[] K,
                                                   byte[] N,
                                                   byte[] A,
                                                   byte[] P,
                                                   byte[] C)
        throws InvalidKeyException, NoSuchAlgorithmException,
        NoSuchPaddingException, IllegalBlockSizeException,
        BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException
    {
        Cipher eax = Cipher.getInstance("AES/EAX/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, N);
        eax.init(Cipher.ENCRYPT_MODE, key, spec);

        eax.updateAAD(A);
        byte[] c = eax.doFinal(P);

        if (!areEqual(C, c))
        {
            fail("JCE encrypt with additional data and RepeatedSecretKeySpec failed.");
        }

        // Check GCMParameterSpec handling knows about RepeatedSecretKeySpec
        eax.init(Cipher.DECRYPT_MODE, new RepeatedSecretKeySpec("AES"), spec);
        eax.updateAAD(A);
        byte[] p = eax.doFinal(C);

        if (!areEqual(P, p))
        {
            fail("JCE decrypt with additional data and RepeatedSecretKeySpec failed.");
        }

        AlgorithmParameters algParams = eax.getParameters();

        byte[] encParams = algParams.getEncoded();

        GCMParameters gcmParameters = GCMParameters.getInstance(encParams);

        if (!Arrays.areEqual(spec.getIV(), gcmParameters.getNonce()) || spec.getTLen() != gcmParameters.getIcvLen() * 8)
        {
            fail("parameters mismatch");
        }
    }

    // A CCM AlgorithmParameters must accept a GCMParameterSpec carrying a short (sub-12-octet) tag -
    // the JCE has no dedicated CCM spec, so a GCMParameterSpec conveys the CCM nonce and ICV length,
    // and the 8-octet tag of the TLS *_CCM_8 cipher suites is a legal RFC 5084 CCM ICV. Before the fix
    // (GcmSpecUtil.extractCcmParameters used by the AES/ARIA/LEA AlgParamsCCM) this threw "Cannot
    // process GCMParameterSpec", because the parameters were built via GCMParameters, which enforces
    // the RFC 5084 GCM range of 12-16. GCM itself must still reject the short tag.
    private void testCCMParameterSpecWithShortTag()
        throws Exception
    {
        byte[] K = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] N = Hex.decode("000102030405060708090a0b");
        byte[] A = Hex.decode("0001020304050607");
        byte[] P = Hex.decode("48656c6c6f2c20776f726c6421");

        SecretKeySpec key = new SecretKeySpec(K, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(64, N); // 8-octet tag, as used by *_CCM_8

        // AlgParamsCCM: round-trip the short-tag spec through the CCM AlgorithmParameters
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("CCM", "BC");
        algParams.init(spec);

        CCMParameters ccmParameters = CCMParameters.getInstance(algParams.getEncoded());
        if (!Arrays.areEqual(N, ccmParameters.getNonce()) || ccmParameters.getIcvLen() != 8)
        {
            fail("CCM AlgorithmParameters did not round-trip a short-tag GCMParameterSpec");
        }

        // full encrypt/decrypt round-trip through the CCM cipher using those parameters
        Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, key, algParams);
        enc.updateAAD(A);
        byte[] c = enc.doFinal(P);

        Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        dec.init(Cipher.DECRYPT_MODE, key, algParams);
        dec.updateAAD(A);
        if (!areEqual(P, dec.doFinal(c)))
        {
            fail("CCM short-tag round-trip failed");
        }

        // GcmSpecUtil: extractCcmParameters accepts the 8-octet ICV; extractGcmParameters must reject it
        if (CCMParameters.getInstance(GcmSpecUtil.extractCcmParameters(spec)).getIcvLen() != 8)
        {
            fail("extractCcmParameters produced wrong ICV length");
        }
        try
        {
            GcmSpecUtil.extractGcmParameters(spec);
            fail("extractGcmParameters accepted an 8-octet ICV");
        }
        catch (InvalidParameterSpecException e)
        {
            // expected - GCM ICV must be 12-16 (RFC 5084)
        }

        // and the GCM AlgorithmParameters must still reject a short tag (GCM was not loosened)
        try
        {
            AlgorithmParameters.getInstance("GCM", "BC").init(new GCMParameterSpec(64, N));
            fail("GCM AlgorithmParameters accepted an 8-octet ICV");
        }
        catch (InvalidParameterSpecException e)
        {
            // expected
        }
    }

    private void testGCMGeneric(byte[] K,
                                      byte[] N,
                                      byte[] A,
                                      byte[] P,
                                      byte[] C)
        throws InvalidKeyException,
        NoSuchAlgorithmException, NoSuchPaddingException,
        IllegalBlockSizeException, BadPaddingException,
        InvalidAlgorithmParameterException, NoSuchProviderException, IOException, InvalidParameterSpecException
    {
        Cipher eax = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");

        // GCMParameterSpec mapped to AEADParameters and overrides default MAC
        // size
        GCMParameterSpec spec = new GCMParameterSpec(128, N);
        eax.init(Cipher.ENCRYPT_MODE, key, spec);

        eax.updateAAD(A);
        byte[] c = eax.doFinal(P);

        if (!areEqual(C, c))
        {
            fail("JCE encrypt with additional data and GCMParameterSpec failed.");
        }

        eax = Cipher.getInstance("GCM", "BC");
        eax.init(Cipher.DECRYPT_MODE, key, spec);
        eax.updateAAD(A);
        byte[] p = eax.doFinal(C);

        if (!areEqual(P, p))
        {
            fail("JCE decrypt with additional data and GCMParameterSpec failed.");
        }

        AlgorithmParameters algParams = eax.getParameters();

        byte[] encParams = algParams.getEncoded();

        GCMParameters gcmParameters = GCMParameters.getInstance(encParams);

        if (!Arrays.areEqual(spec.getIV(), gcmParameters.getNonce()) || spec.getTLen() != gcmParameters.getIcvLen() * 8)
        {
            fail("parameters mismatch");
        }

        GCMParameterSpec gcmSpec = algParams.getParameterSpec(GCMParameterSpec.class);

        if (!Arrays.areEqual(gcmSpec.getIV(), gcmParameters.getNonce()) || gcmSpec.getTLen() != gcmParameters.getIcvLen() * 8)
        {
            fail("spec parameters mismatch");
        }

        if (!Arrays.areEqual(eax.getIV(), gcmParameters.getNonce()))
        {
            fail("iv mismatch");
        }
    }

    private void testRepeatedGCMWithSpec(byte[] K,
                                 byte[] N,
                                 byte[] A,
                                 byte[] P,
                                 byte[] C)
        throws InvalidKeyException, NoSuchAlgorithmException,
        NoSuchPaddingException, IllegalBlockSizeException,
        BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException
    {
        Cipher eax = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        SecretKeySpec key = new SecretKeySpec(K, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, N);
        eax.init(Cipher.ENCRYPT_MODE, key, spec);

        eax.updateAAD(A);
        byte[] c = eax.doFinal(P);

        if (!areEqual(C, c))
        {
            fail("JCE encrypt with additional data and RepeatedSecretKeySpec failed.");
        }

        eax = Cipher.getInstance("GCM", "BC");
        eax.init(Cipher.DECRYPT_MODE, key, spec);
        eax.updateAAD(A);
        byte[] p = eax.doFinal(C);

        if (!areEqual(P, p))
        {
            fail("JCE decrypt with additional data and GCMParameterSpec failed.");
        }

        try
        {
            eax.init(Cipher.ENCRYPT_MODE, new RepeatedSecretKeySpec("AES"), spec);
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("wrong message", "cannot reuse nonce for GCM encryption".equals(e.getMessage()));
        }

        try
        {
            eax.init(Cipher.ENCRYPT_MODE, new RepeatedSecretKeySpec("AES"), new IvParameterSpec(spec.getIV()));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("wrong message", "cannot reuse nonce for GCM encryption".equals(e.getMessage()));
        }

        try
        {
            eax.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(K, "AES"), new IvParameterSpec(spec.getIV()));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("wrong message", "cannot reuse nonce for GCM encryption".equals(e.getMessage()));
        }
    }

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AEADTest());
    }
}
