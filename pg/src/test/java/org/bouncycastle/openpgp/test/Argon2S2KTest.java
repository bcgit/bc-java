package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class Argon2S2KTest
    extends SimpleTest
{

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String TEST_MSG_PASSWORD = "password";

    // Test message from the crypto-refresh-05 document
    private static final String TEST_MSG_AES128 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 128-bit key\n" +
        "Comment: Session key: 01FE16BBACFD1E7B78EF3B865187374F\n" +
        "\n" +
        "wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+\n" +
        "YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH\n" +
        "XfA3pqV4mTzF\n" +
        "=uIks\n" +
        "-----END PGP MESSAGE-----";

    // Test message from the crypto-refresh-05 document
    private static final String TEST_MSG_AES192 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 192-bit key\n" +
        "Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955AF8DFE194\n" +
        "\n" +
        "wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw\n" +
        "F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys\n" +
        "LVg77Mwwfgl2n/d572WciAM=\n" +
        "=n8Ma\n" +
        "-----END PGP MESSAGE-----";

    // Test message from the crypto-refresh-05 document
    private static final String TEST_MSG_AES256 = "-----BEGIN PGP MESSAGE-----\n" +
        "Comment: Encrypted using AES with 192-bit key\n" +
        "Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955AF8DFE194\n" +
        "\n" +
        "wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw\n" +
        "F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys\n" +
        "LVg77Mwwfgl2n/d572WciAM=\n" +
        "=n8Ma\n" +
        "-----END PGP MESSAGE-----";

    private static final String TEST_MSG_PLAIN = "Hello, world!";

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
        // S2K parameter serialization
        encodingTest();
        // Test vectors
        testDecryptAES128Message();
        testDecryptAES192Message();
        testDecryptAES256Message();
        // dynamic round-trip
        testEncryptAndDecryptMessageWithArgon2();
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
