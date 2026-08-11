package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.internal.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the ISO 18033-2 / RFC 9690 RSA-KEM Cipher SPI, reachable as
 * "RSA-KTS-KEM-KWS" and by the id-kem-rsa OID that CMS KEMRecipientInfo names.
 */
public class RSAKEMCipherTest
    extends SimpleTest
{
    private static final String KEM_NAME = "RSA-KTS-KEM-KWS";

    public String getName()
    {
        return "RSAKEMCipher";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048, new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        SecretKey cek = new SecretKeySpec(new byte[]{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, "AES");

        wrapUnwrapTest(KEM_NAME, kp, cek);
        wrapUnwrapTest(ISOIECObjectIdentifiers.id_kem_rsa.getId(), kp, cek);
        repeatedUnwrapTest(kp, cek);
        blindingEngagedTest(kp, cek);
    }

    /**
     * Blinding is result-preserving, so a round trip cannot tell a blinded decapsulation from an
     * unblinded one. Randomness consumption can: the blinding factor is drawn from the SecureRandom
     * handed to Cipher.init, so an unwrap that draws nothing did not blind.
     */
    private void blindingEngagedTest(KeyPair kp, SecretKey cek)
        throws Exception
    {
        KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder("AES-KWP", 256).build();

        Cipher wrapper = Cipher.getInstance(KEM_NAME, "BC");

        wrapper.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec);

        byte[] wrapped = wrapper.wrap(cek);

        CountingSecureRandom counter = new CountingSecureRandom();

        Cipher unwrapper = Cipher.getInstance(KEM_NAME, "BC");

        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsSpec, counter);

        SecretKey recovered = (SecretKey)unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        if (counter.count == 0)
        {
            fail("unwrap drew no randomness: the private exponent operation was not blinded");
        }

        if (!areEqual(cek.getEncoded(), recovered.getEncoded()))
        {
            fail("blinded unwrap recovered the wrong CEK");
        }
    }

    private static class CountingSecureRandom
        extends SecureRandom
    {
        private final SecureRandom delegate = new SecureRandom();

        int count;

        public void nextBytes(byte[] bytes)
        {
            count++;
            delegate.nextBytes(bytes);
        }
    }

    private void wrapUnwrapTest(String cipherName, KeyPair kp, SecretKey cek)
        throws Exception
    {
        KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder("AES-KWP", 256).build();

        Cipher wrapper = Cipher.getInstance(cipherName, "BC");

        wrapper.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec);

        byte[] wrapped = wrapper.wrap(cek);

        Cipher unwrapper = Cipher.getInstance(cipherName, "BC");

        unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsSpec);

        SecretKey recovered = (SecretKey)unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

        if (!areEqual(cek.getEncoded(), recovered.getEncoded()))
        {
            fail("CEK not recovered through " + cipherName);
        }
    }

    /**
     * Decapsulation blinds the private exponent operation with a fresh factor per call, so a
     * wrong unblinding step shows up as unwraps that disagree with each other.
     */
    private void repeatedUnwrapTest(KeyPair kp, SecretKey cek)
        throws Exception
    {
        KTSParameterSpec ktsSpec = new KTSParameterSpec.Builder("AES-KWP", 256).build();

        Cipher wrapper = Cipher.getInstance(KEM_NAME, "BC");

        wrapper.init(Cipher.WRAP_MODE, kp.getPublic(), ktsSpec);

        byte[] wrapped = wrapper.wrap(cek);

        for (int i = 0; i != 20; i++)
        {
            Cipher unwrapper = Cipher.getInstance(KEM_NAME, "BC");

            unwrapper.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsSpec);

            SecretKey recovered = (SecretKey)unwrapper.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

            if (!areEqual(cek.getEncoded(), recovered.getEncoded()))
            {
                fail("repeated blinded unwrap disagreed at iteration " + i);
            }
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new RSAKEMCipherTest());
    }
}
