package org.bouncycastle.openpgp.test;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.*;
import java.util.Date;

/**
 * Curve25519Legacy ECDH Secret Key Material uses big-endian MPI form,
 * while X25519 keys use little-endian native encoding.
 * This test verifies that legacy X25519 keys using ECDH are reverse-encoded,
 * while X25519 keys are natively encoded.
 */
public class Curve25519PrivateKeyEncodingTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "Curve25519PrivateKeyEncodingTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        containsTest();
        verifySecretKeyReverseEncoding();
    }

    private void verifySecretKeyReverseEncoding()
            throws PGPException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        bc_verifySecretKeyReverseEncoding();
        jca_verifySecretKeyReverseEncoding();
    }

    /**
     * Verify that legacy ECDH keys over curve25519 encode the private key in reversed encoding,
     * while dedicated X25519 keys use native encoding for the private key material.
     * Test the JcaJce implementation.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws PGPException
     * @throws IOException
     */
    private void jca_verifySecretKeyReverseEncoding()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, PGPException, IOException
    {
        JcaPGPKeyConverter c = new JcaPGPKeyConverter();

        Date date = currentTimeRounded();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", new BouncyCastleProvider());
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();

        byte[] rawPrivateKey = jcaNativePrivateKey(kp.getPrivate());

        // Legacy key uses reversed encoding
        PGPKeyPair pgpECDHKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] encodedECDHPrivateKey = pgpECDHKeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("ECDH Curve25519Legacy (X25519) key MUST encode secret key in 'reverse' (big-endian MPI encoding) (JCE implementation)",
                containsSubsequence(encodedECDHPrivateKey, Arrays.reverse(rawPrivateKey)));

        byte[] decodedECDHPrivateKey = jcaNativePrivateKey(c.getPrivateKey(pgpECDHKeyPair.getPrivateKey()));
        isEncodingEqual("Decoded ECDH Curve25519Legacy (X25519) key MUST match original raw key (JCE implementation)",
                decodedECDHPrivateKey, rawPrivateKey);

        // X25519 key uses native encoding
        PGPKeyPair pgpX25519KeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, date);
        byte[] encodedX25519PrivateKey = pgpX25519KeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("X25519 key MUST use native encoding (little-endian) to encode the secret key material (JCE implementation)",
                containsSubsequence(encodedX25519PrivateKey, rawPrivateKey));

        byte[] decodedX25519PrivateKey = jcaNativePrivateKey(c.getPrivateKey(pgpX25519KeyPair.getPrivateKey()));
        isEncodingEqual("Decoded X25519 key MUST match original raw key (JCE implementation)",
                rawPrivateKey, decodedX25519PrivateKey);
    }

    /**
     * Return the native encoding of the given private key.
     * @param privateKey private key
     * @return native encoding
     * @throws IOException
     */
    private byte[] jcaNativePrivateKey(PrivateKey privateKey)
            throws IOException
    {
        PrivateKeyInfo kInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        return ASN1OctetString.getInstance(kInfo.parsePrivateKey()).getOctets();
    }

    /**
     * Verify that legacy ECDH keys over curve25519 encode the private key in reversed encoding,
     * while dedicated X25519 keys use native encoding for the private key material.
     * Test the BC implementation.
     */
    private void bc_verifySecretKeyReverseEncoding()
            throws PGPException
    {
        BcPGPKeyConverter c = new BcPGPKeyConverter();

        Date date = currentTimeRounded();
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        byte[] rawPrivateKey = ((X25519PrivateKeyParameters) kp.getPrivate()).getEncoded();

        // Legacy key uses reversed encoding
        PGPKeyPair pgpECDHKeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, date);
        byte[] encodedECDHPrivateKey = pgpECDHKeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("ECDH Curve25519Legacy (X25519) key MUST encode secret key in 'reverse' (big-endian MPI encoding) (BC implementation)",
                containsSubsequence(encodedECDHPrivateKey, Arrays.reverse(rawPrivateKey)));

        byte[] decodedECDHPrivateKey = ((X25519PrivateKeyParameters) c.getPrivateKey(pgpECDHKeyPair.getPrivateKey())).getEncoded();
        isEncodingEqual("Decoded ECDH Curve25519Legacy (X25519) key MUST match original raw key (BC implementation)",
                decodedECDHPrivateKey, rawPrivateKey);

        // X25519 key uses native encoding
        PGPKeyPair pgpX25519KeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, date);
        byte[] encodedX25519PrivateKey = pgpX25519KeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue("X25519 key MUST use native encoding (little-endian) to encode the secret key material (BC implementation)",
                containsSubsequence(encodedX25519PrivateKey, rawPrivateKey));

        byte[] decodedX25519PrivateKey = ((X25519PrivateKeyParameters) c.getPrivateKey(pgpX25519KeyPair.getPrivateKey())).getEncoded();
        isEncodingEqual("Decoded X25519 key MUST match original raw key (BC implementation)",
                rawPrivateKey, decodedX25519PrivateKey);
    }

    /**
     * Return true, if the given sequence contains the given subsequence entirely.
     * @param sequence sequence
     * @param subsequence subsequence
     * @return true if subsequence is a subsequence of sequence
     */
    public boolean containsSubsequence(byte[] sequence, byte[] subsequence)
    {
        outer: for (int i = 0; i < sequence.length - subsequence.length + 1; i++)
        {
            for (int j = 0; j < subsequence.length; j++)
            {
                if (sequence[i + j] != subsequence[j])
                {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Test proper functionality of the {@link #containsSubsequence(byte[], byte[])} method.
     */
    private void containsTest() {
        // Make sure our containsSubsequence method functions correctly
        byte[] s = new byte[] {0x00, 0x01, 0x02, 0x03};
        isTrue(containsSubsequence(s, new byte[] {0x00, 0x01}));
        isTrue(containsSubsequence(s, new byte[] {0x01, 0x02}));
        isTrue(containsSubsequence(s, new byte[] {0x02, 0x03}));
        isTrue(containsSubsequence(s, new byte[] {0x00}));
        isTrue(containsSubsequence(s, new byte[] {0x03}));
        isTrue(containsSubsequence(s, new byte[] {0x00, 0x01, 0x02, 0x03}));
        isTrue(containsSubsequence(s, new byte[0]));
        isTrue(containsSubsequence(new byte[0], new byte[0]));

        isFalse(containsSubsequence(s, new byte[] {0x00, 0x02}));
        isFalse(containsSubsequence(s, new byte[] {0x00, 0x00}));
        isFalse(containsSubsequence(s, new byte[] {0x00, 0x01, 0x02, 0x03, 0x04}));
        isFalse(containsSubsequence(s, new byte[] {0x04}));
        isFalse(containsSubsequence(new byte[0], new byte[] {0x00}));
    }

    public static void main(String[] args)
    {
        runTest(new Curve25519PrivateKeyEncodingTest());
    }
}
