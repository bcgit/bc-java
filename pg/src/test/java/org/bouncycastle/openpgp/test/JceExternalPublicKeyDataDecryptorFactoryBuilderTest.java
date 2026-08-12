package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.api.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for {@link JceExternalPublicKeyDataDecryptorFactoryBuilder}, emulating the externally-held
 * key with a callback that performs the raw private-key operation through the JCA in software.
 */
public class JceExternalPublicKeyDataDecryptorFactoryBuilderTest
    extends SimpleTest
{
    private static final byte[] TEXT = Strings.toByteArray("hello world!\n");

    @Override
    public String getName()
    {
        return "JceExternalPublicKeyDataDecryptorFactoryBuilderTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testDedicatedX25519();
        testDedicatedX448();
        testLegacyX25519();
        testNistCurveECDH();
        testRSA();
        testMalformedEncSessionKeyThrowsPGPException();
    }

    /**
     * Builder whose callback holds the private key in software and performs the raw operation the
     * way a hardware token would - taking the ephemeral key as a JCA {@link PublicKey} and returning
     * the plain RSA decryption result / agreement secret.
     */
    private static final class TestExternalBuilder
        extends JceExternalPublicKeyDataDecryptorFactoryBuilder
    {
        private final PrivateKey externalKey;

        TestExternalBuilder(PrivateKey externalKey)
        {
            this.externalKey = externalKey;
        }

        @Override
        public PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
        {
            throw new UnsupportedOperationException("not used by this test");
        }

        PublicKeyDataDecryptorFactory build(PGPPublicKey pubKey)
            throws PGPException
        {
            return build(new PGPKeyPair(pubKey, null), new PublicKeyCryptoCallback()
            {
                @Override
                public byte[] decryptRSA(int keyAlgorithm, byte[] pEnc)
                    throws PGPException
                {
                    try
                    {
                        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                        c.init(Cipher.DECRYPT_MODE, externalKey);
                        return c.doFinal(pEnc);
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("external RSA operation failed: " + e.getMessage(), e);
                    }
                }

                @Override
                public byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
                    throws PGPException
                {
                    throw new PGPException("ElGamal not supported by the external key");
                }

                @Override
                public byte[] decryptECDH(ECDHPublicBCPGKey pubKey, PublicKey ephemeralKey)
                    throws PGPException
                {
                    return agree("ECDH", ephemeralKey);
                }

                @Override
                public byte[] decryptX25519(PublicKey ephemeralKey)
                    throws PGPException
                {
                    return agree("X25519", ephemeralKey);
                }

                @Override
                public byte[] decryptX448(PublicKey ephemeralKey)
                    throws PGPException
                {
                    return agree("X448", ephemeralKey);
                }

                private byte[] agree(String algorithm, PublicKey ephemeralKey)
                    throws PGPException
                {
                    try
                    {
                        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "BC");
                        agreement.init(externalKey);
                        agreement.doPhase(ephemeralKey, true);
                        return agreement.generateSecret();
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("external key agreement failed: " + e.getMessage(), e);
                    }
                }
            });
        }
    }

    private void testDedicatedX25519()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", "BC");
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("dedicated X25519",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, new Date()), kp.getPrivate());
    }

    private void testDedicatedX448()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", "BC");
        gen.initialize(new XDHParameterSpec("X448"));
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("dedicated X448",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.X448, kp, new Date()), kp.getPrivate());
    }

    private void testLegacyX25519()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", "BC");
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("legacy X25519 ECDH",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, new Date()), kp.getPrivate());
    }

    private void testNistCurveECDH()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDH", "BC");
        gen.initialize(new ECNamedCurveGenParameterSpec("P-256"));
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("P-256 ECDH",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, new Date()), kp.getPrivate());
    }

    private void testRSA()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("RSA",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date()), kp.getPrivate());
    }

    /**
     * A malformed (truncated or length-corrupted) encrypted session key must surface as the
     * {@link PGPException} the interface contract names, exactly as the software-backed factories
     * behave - never as an ArrayIndexOutOfBoundsException or other unchecked exception.
     */
    private void testMalformedEncSessionKeyThrowsPGPException()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("XDH", "BC");
        gen.initialize(new XDHParameterSpec("X25519"));
        KeyPair kp = gen.generateKeyPair();
        PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, new Date());

        TestExternalBuilder builder = new TestExternalBuilder(kp.getPrivate());
        builder.setProvider(new BouncyCastleProvider());
        PublicKeyDataDecryptorFactory factory = builder.build(keyPair.getPublicKey());

        // X25519 ESK truncated right after the ephemeral key: no size octet to read
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.X25519, new byte[32]);

        // v3 X25519 ESK whose size octet (0) leaves no room for the symmetric algorithm id
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.X25519, new byte[33]);

        // ECDH ESK shorter than its own two length octets
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.ECDH, new byte[1]);
    }

    private void expectMalformedFailure(PublicKeyDataDecryptorFactory factory, int keyAlgorithm, byte[] enc)
    {
        try
        {
            factory.recoverSessionData(keyAlgorithm, new byte[][] { enc }, PublicKeyEncSessionPacket.VERSION_3);
            fail("no exception for malformed encrypted session key");
        }
        catch (PGPException e)
        {
            isEquals("encoded length out of range", e.getMessage());
        }
    }

    private void encryptDecryptRoundTrip(String description, PGPKeyPair keyPair, PrivateKey externalKey)
        throws Exception
    {
        // v4 SEIPD with a v3 PKESK, and v6 SEIPD with a v6 PKESK - the two exercise different
        // ESK parsing and data-decryptor paths in the factory
        encryptDecryptRoundTrip(description + " (v4)", keyPair, externalKey,
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
                .setProvider("BC").setSecureRandom(new SecureRandom()));
        encryptDecryptRoundTrip(description + " (v6)", keyPair, externalKey,
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setUseV6AEAD().setWithAEAD(AEADAlgorithmTags.OCB, 6)
                .setProvider("BC").setSecureRandom(new SecureRandom()));
    }

    private void encryptDecryptRoundTrip(String description, PGPKeyPair keyPair, PrivateKey externalKey,
        JcePGPDataEncryptorBuilder encryptorBuilder)
        throws Exception
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, TEXT.length, new Date());
        pOut.write(TEXT);
        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey()).setProvider("BC"));

        OutputStream cOut = cPk.open(cbOut, data.length);
        cOut.write(data);
        cOut.close();

        // decrypt with a factory that only sees the public half - the raw private-key operation is
        // routed out through the test callback the way a hardware token's would be
        TestExternalBuilder builder = new TestExternalBuilder(externalKey);
        builder.setProvider(new BouncyCastleProvider());
        PublicKeyDataDecryptorFactory factory = builder.build(keyPair.getPublicKey());

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(factory);

        pgpF = new JcaPGPObjectFactory(clear);
        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        byte[] out = Streams.readAll(ld.getInputStream());

        isTrue(description + ": wrong plain text in decrypted packet", areEqual(out, TEXT));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new JceExternalPublicKeyDataDecryptorFactoryBuilderTest());
    }
}
