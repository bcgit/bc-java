package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class Argon2S2KTest
    extends SimpleTest
{

    private static final SecureRandom RANDOM = new SecureRandom();

    static final String TEST_MSG_PASSWORD = "password";

    // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-
    static final String TEST_MSG_AES128 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 128-bit key\n" +
        "Comment: Session key: 01FE16BBACFD1E7B78EF3B865187374F\n" +
        "\n" +
        "wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+\n" +
        "YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH\n" +
        "XfA3pqV4mTzF\n" +
        "=uIks\n" +
        "-----END PGP MESSAGE-----";

    // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-a
    private static final String TEST_MSG_AES192 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 192-bit key\n" +
        "Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955AF8DFE194\n" +
        "\n" +
        "wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw\n" +
        "F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys\n" +
        "LVg77Mwwfgl2n/d572WciAM=\n" +
        "=n8Ma\n" +
        "-----END PGP MESSAGE-----";

    // https://www.rfc-editor.org/rfc/rfc9580.html#name-v4-skesk-using-argon2-with-ae
    private static final String TEST_MSG_AES256 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 256-bit key\n" +
        "Comment: Session key: BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEF...\n" +
        "Comment: Session key: ...C13BAB2F1F8E18FB74580D8B0\n" +
        "\n" +
        "wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu\n" +
        "623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K\n" +
        "95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==\n" +
        "-----END PGP MESSAGE-----";

    static final String TEST_MSG_PLAIN = "Hello, world!";

    public static void main(String[] args)
    {
        runTest(new Argon2S2KTest());
    }

    @Override
    public String getName()
    {
        return "Argon2S2KTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        //testExceptions();
        // S2K parameter serialization
        encodingTest();
        // Test vectors
        testDecryptAES128Message();
        testDecryptAES192Message();
        testDecryptAES256Message();
        // dynamic round-trip
        testEncryptAndDecryptMessageWithArgon2();
        checkArgon2MaxMemoryExpValue();
        checkArgon2MaxMemoryExpValueOnSecretKey();
        checkArgon2MinMemoryExpFloor();
    }

    /**
     * RFC 9106 sec. 3.1 requires the Argon2 memory size m to satisfy m &ge; 8*p,
     * i.e. memorySizeExponent &ge; 3 + ceil(log2(p)) = 3 + bitLen(p - 1). The
     * key-derivation bounds check in PGPUtil.makeKeyFromPassPhrase now enforces
     * that floor (previously it only rejected memorySizeExponent &lt; 3).
     * <p>
     * The {@link S2K.Argon2Params} constructor blocks building a sub-floor
     * specifier, so a v6 SKESK wire form with parallelism = 4 and
     * memorySizeExponent = 4 (m = 16 KiB &lt; 8*p = 32 KiB) is crafted and
     * parsed - the packet parser does not validate the floor - and the derived
     * S2K is fed to the key-derivation path, which must reject it.
     */
    private void checkArgon2MinMemoryExpFloor()
        throws Exception
    {
        byte[] body = v6SkeskBodyWithArgon2(1, 4, 4);
        S2K s2k = new SymmetricKeyEncSessionPacket(
            new BCPGInputStream(new ByteArrayInputStream(body))).getS2K();

        BcPBEDataDecryptorFactory factory = new BcPBEDataDecryptorFactory(
            TEST_MSG_PASSWORD.toCharArray(), new BcPGPDigestCalculatorProvider());

        try
        {
            factory.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_256, s2k);
            fail("memorySizeExponent below 3 + bitLen(parallelism - 1) should be rejected");
        }
        catch (PGPException e)
        {
            isEquals("memory size exponent out of range", e.getMessage());
        }
    }

    /**
     * Build the body of a v6 {@link SymmetricKeyEncSessionPacket} (the octets
     * after the packet frame) carrying an Argon2 S2K with the given parameters.
     * The surrounding SKESK fields are spec-shaped but arbitrary - only the
     * parsed S2K is used.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc">
     *     RFC 9580 sec. 5.3 - Symmetric-Key Encrypted Session Key Packet</a>
     */
    private static byte[] v6SkeskBodyWithArgon2(int passes, int parallelism, int memSizeExp)
    {
        // OCB tag is 16 octets per RFC 9580 sec. 5.13.2.
        final int ivLen = 15;
        final int sessionKeyLen = 16;
        final int authTagLen = 16;
        final int s2kOctets = 1 + 16 + 3;
        final int next5FieldsCount = 1 /* encAlgo */ + 1 /* aeadAlgo */ + 1 /* s2kCount */ + s2kOctets + ivLen;

        byte[] body = new byte[1 /* version */ + 1 /* count */ + next5FieldsCount + sessionKeyLen + authTagLen];
        int p = 0;
        body[p++] = (byte)SymmetricKeyEncSessionPacket.VERSION_6;
        body[p++] = (byte)next5FieldsCount;
        body[p++] = (byte)SymmetricKeyAlgorithmTags.AES_256;
        body[p++] = (byte)AEADAlgorithmTags.OCB;
        body[p++] = (byte)s2kOctets;

        // Argon2 S2K wire form
        body[p++] = (byte)S2K.ARGON_2;
        p += 16; // 16-octet salt - content irrelevant for the floor check
        body[p++] = (byte)passes;
        body[p++] = (byte)parallelism;
        body[p++] = (byte)memSizeExp;

        // IV + session key + auth tag stay zero; the floor check fires during
        // key derivation, before any of that is consulted.
        return body;
    }

    public void encodingTest()
        throws IOException
    {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        S2K.Argon2Params params = new S2K.Argon2Params(salt, 1, 4, 21);
        S2K argon2 = S2K.argon2S2K(params);

        isEquals(S2K.ARGON_2, argon2.getType());
        isEquals(1, argon2.getPasses());
        isEquals(4, argon2.getParallelism());
        isEquals(21, argon2.getMemorySizeExponent());
        isEquals(16, argon2.getIV().length);

        // Test actual encoding
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        BCPGOutputStream out = new BCPGOutputStream(bytes);
        argon2.encode(out);
        byte[] encoding = bytes.toByteArray();

        isEquals(20, encoding.length);
        isEquals(0x04, encoding[0]);    // Type is Argon2
        isEquals(0x01, encoding[17]);   // 1 pass
        isEquals(0x04, encoding[18]);   // 4 parallelism
        isEquals(0x15, encoding[19]);   // 0x15 = 21 mem exp
    }

    public void testDecryptAES128Message()
        throws IOException, PGPException
    {
        String plaintext = decryptSymmetricallyEncryptedMessage(TEST_MSG_AES128, TEST_MSG_PASSWORD);
        isEquals(TEST_MSG_PLAIN, plaintext);
    }

    public void testDecryptAES192Message()
        throws IOException, PGPException
    {
        String plaintext = decryptSymmetricallyEncryptedMessage(TEST_MSG_AES192, TEST_MSG_PASSWORD);
        isEquals(TEST_MSG_PLAIN, plaintext);
    }

    public void testDecryptAES256Message()
        throws IOException, PGPException
    {
        String plaintext = decryptSymmetricallyEncryptedMessage(TEST_MSG_AES256, TEST_MSG_PASSWORD);
        isEquals(TEST_MSG_PLAIN, plaintext);
    }

    public void testEncryptAndDecryptMessageWithArgon2()
        throws PGPException, IOException
    {
        String encrypted = encryptMessageSymmetricallyWithArgon2(TEST_MSG_PLAIN, TEST_MSG_PASSWORD);
        String plaintext = decryptSymmetricallyEncryptedMessage(encrypted, TEST_MSG_PASSWORD);
        isEquals(TEST_MSG_PLAIN, plaintext);
    }

    private void checkArgon2MaxMemoryExpValue()
        throws Exception
    {
        System.setProperty(Argon2Parameters.MAX_MEMORY_EXP, "10");

        try
        {
            decryptSymmetricallyEncryptedMessage(TEST_MSG_AES256, TEST_MSG_PASSWORD);
            fail("no exception");
        }
        catch (PGPException e)
        {
            isEquals("memory size exponent out of range", e.getMessage());
        }
        finally
        {
            System.getProperties().remove(Argon2Parameters.MAX_MEMORY_EXP);
        }
    }

    private void checkArgon2MaxMemoryExpValueOnSecretKey()
        throws Exception
    {
        // lock a v6 key with Argon2 (memory size exponent 16), then lower the cap and
        // check the bounds check also fires on the secret key decryption path
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        PGPKeyPair keyPair = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed25519, kp, new Date());

        BcAEADSecretKeyEncryptorBuilder encBuilder = new BcAEADSecretKeyEncryptorBuilder(
            AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256,
            S2K.Argon2Params.memoryConstrainedParameters());

        PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();

        PGPSecretKey sk = new PGPSecretKey(
            keyPair.getPrivateKey(),
            keyPair.getPublicKey(),
            digestProv.get(HashAlgorithmTags.SHA1),
            true,
            encBuilder.build(TEST_MSG_PASSWORD.toCharArray(), keyPair.getPublicKey().getPublicKeyPacket()));

        System.setProperty(Argon2Parameters.MAX_MEMORY_EXP, "10");

        try
        {
            sk.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(digestProv).build(TEST_MSG_PASSWORD.toCharArray()));
            fail("no exception");
        }
        catch (PGPException e)
        {
            isEquals("memory size exponent out of range", e.getMessage());
        }
        finally
        {
            System.getProperties().remove(Argon2Parameters.MAX_MEMORY_EXP);
        }
    }

    private String decryptSymmetricallyEncryptedMessage(String message, String password)
        throws IOException, PGPException
    {
        char[] pass = password.toCharArray();
        BcPBEDataDecryptorFactory factory = new BcPBEDataDecryptorFactory(pass, new BcPGPDigestCalculatorProvider());
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(message));
        ArmoredInputStream armorIn = new ArmoredInputStream(msgIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPPBEEncryptedData encryptedData = (PGPPBEEncryptedData)encryptedDataList.get(0);

        // decrypt
        InputStream inputStream = encryptedData.getDataStream(factory);
        objectFactory = new BcPGPObjectFactory(inputStream);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();
        InputStream decryptedIn = literalData.getDataStream();
        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
        Streams.pipeAll(decryptedIn, decryptedOut);

        String decryptedString = decryptedOut.toString();
        return decryptedString;
    }

    public String encryptMessageSymmetricallyWithArgon2(String plaintext, String password)
        throws PGPException, IOException
    {

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256));
        encGen.addMethod(new BcPBEKeyEncryptionMethodGenerator(password.toCharArray(), S2K.Argon2Params.universallyRecommendedParameters()));
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        OutputStream encOut = encGen.open(armorOut, new byte[4096]);
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.UTF8, "", new Date(), new byte[4096]);

        ByteArrayInputStream plainIn = new ByteArrayInputStream(Strings.toByteArray(plaintext));
        Streams.pipeAll(plainIn, litOut);
        litOut.close();
        encOut.close();
        armorOut.close();

        String encrypted = out.toString();
        return encrypted;
    }
}
