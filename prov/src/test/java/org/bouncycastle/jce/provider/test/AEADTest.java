package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.RepeatedSecretKeySpec;
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

    @Override
    public String getName()
    {
        return "AEAD";
    }

    @Override
    public void performTest() throws Exception
    {
        checkCipherWithAD(K2, N2, A2, P2, C2_short);
        testGCMParameterSpec(K2, N2, A2, P2, C2);
        testGCMParameterSpecWithRepeatKey(K2, N2, A2, P2, C2);
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

    private void testGCMParameterSpec(byte[] K,
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
    }

    private void testGCMParameterSpecWithRepeatKey(byte[] K,
                                                   byte[] N,
                                                   byte[] A,
                                                   byte[] P,
                                                   byte[] C)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException
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
    }

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new AEADTest());
    }

}
