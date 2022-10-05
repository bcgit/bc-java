package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPSessionKeyTest
    extends SimpleTest
{

    // Alice's key from https://datatracker.ietf.org/doc/html/draft-bre-openpgp-samples-00#section-2.2
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "   Comment: Alice's OpenPGP Transferable Secret Key\n" +
        "\n" +
        "   lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
        "   b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj\n" +
        "   ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ\n" +
        "   CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
        "   nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
        "   a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB\n" +
        "   BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
        "   /3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF\n" +
        "   u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
        "   hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
        "   Pnn+We1aTBhaGa86AQ==\n" +
        "   =n8OM\n" +
        "   -----END PGP PRIVATE KEY BLOCK-----";

    // Test message
    private static final String PK_ENC_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
        "\n" +
        "wV4DR2b2udXyHrYSAQdAO6LtuB8LenDp1EPVSSYn1QCmTSPjeXj9Qdel7t6Ozi8w\n" +
        "kewS+0AdZcvcd2PQEuCboilRAN4TTi9SziuSDNZe//suYHL7SRnOvX6mWSZoiKBm\n" +
        "0j8BlbKlRhBzcNDj6DSKfM/KBhRaw0U9fGs01gq+RNXIHOOnzVjLK18xTNEkx72F\n" +
        "Z1/i3TYsmy8B0mMKkNYtpMk=\n" +
        "=IICf\n" +
        "-----END PGP MESSAGE-----\n";

    private static final String PK_ENC_SESSIONKEY = "C7CBDAF42537776F12509B5168793C26B93294E5ABDFA73224FB0177123E9137";
    private static final int PK_ENC_SESSIONKEY_ALG = SymmetricKeyAlgorithmTags.AES_256;

    private static final String PBE_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
        "Version: PGPainless\n" +
        "\n" +
        "jA0ECQMC8f/JlPUqzS9g0kABpxEJOYB22YqEopVRT1Qvg9ZdFIKeTLmrJZY74ph2\n" +
        "m4JOOELpXbxxSmB3x9CPn+zdULechPnqCkpvstLqb9B5\n" +
        "=AdMx\n" +
        "-----END PGP MESSAGE-----\n";
    private static final String PBE_PASSPHRASE = "sw0rdf1sh";
    private static final String PBE_ENC_SESSIONKEY = "65B189C9EE6DE250647B952B83B23C88ABFD5767293ECDBF00DFF2DA943EC59D";
    private static final int PBE_ENC_SESSIONKEY_ALG = SymmetricKeyAlgorithmTags.AES_256;

    public static void main(String[] args)
        throws Exception
    {
        PGPSessionKeyTest test = new PGPSessionKeyTest();
        Security.addProvider(new BouncyCastleProvider());
        test.performTest();
    }

    public String getName()
    {
        return "PGPSessionKeyTest";
    }

    public void performTest()
        throws Exception
    {
        verifyPublicKeyDecryptionYieldsCorrectSessionData();
        verifyPasswordBasedDecryptionYieldsCorrectSessionData();

        verifyBcPublicKeyDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully();
        verifyJcePublicKeyDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully();

        verifyBcPBEDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully();
        verifyJcePBEDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully();

        testSessionKeyFromString();

        decryptMessageWithoutEskUsingSessionKey();
    }

    private void verifyPublicKeyDecryptionYieldsCorrectSessionData()
        throws IOException, PGPException
    {
        ByteArrayInputStream keyIn = new ByteArrayInputStream(Strings.toByteArray(KEY));
        ArmoredInputStream keyArmorIn = new ArmoredInputStream(keyIn);
        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(keyArmorIn, new BcKeyFingerprintCalculator());
        Iterator<PGPSecretKey> secretKeyIterator = secretKeys.iterator();
        secretKeyIterator.next();
        PGPSecretKey key = (PGPSecretKey)secretKeyIterator.next();

        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PK_ENC_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData)encryptedDataList.iterator().next();

        BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
        PBESecretKeyDecryptor keyDecryptor = new BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
            .build(null);
        PublicKeyDataDecryptorFactory decryptorFactory = new BcPublicKeyDataDecryptorFactory(
            key.extractPrivateKey(keyDecryptor));

        PGPSessionKey sessionKey = encryptedData.getSessionKey(decryptorFactory);

        isEquals(PK_ENC_SESSIONKEY_ALG, sessionKey.getAlgorithm());
        isTrue(Arrays.equals(Hex.decode(PK_ENC_SESSIONKEY), sessionKey.getKey()));
    }

    private void verifyBcPublicKeyDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PK_ENC_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPSessionKeyEncryptedData encryptedData = encryptedDataList.extractSessionKeyEncryptedData();

        SessionKeyDataDecryptorFactory decryptorFactory = new BcSessionKeyDataDecryptorFactory(new PGPSessionKey(PK_ENC_SESSIONKEY_ALG, Hex.decode(PK_ENC_SESSIONKEY)));
        InputStream decrypted = encryptedData.getDataStream(decryptorFactory);

        objectFactory = new BcPGPObjectFactory(decrypted);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), out);

        literalData.getDataStream().close();
        isTrue(Arrays.equals(Strings.toByteArray("Hello World :)"), out.toByteArray()));
    }

    private void verifyJcePublicKeyDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PK_ENC_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPSessionKeyEncryptedData encryptedData = encryptedDataList.extractSessionKeyEncryptedData();

        SessionKeyDataDecryptorFactory decryptorFactory =
            new JceSessionKeyDataDecryptorFactoryBuilder().build(new PGPSessionKey(PK_ENC_SESSIONKEY_ALG, Hex.decode(PK_ENC_SESSIONKEY)));
        InputStream decrypted = encryptedData.getDataStream(decryptorFactory);

        objectFactory = new BcPGPObjectFactory(decrypted);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), out);

        literalData.getDataStream().close();
        isTrue(Arrays.equals(Strings.toByteArray("Hello World :)"), out.toByteArray()));
    }

    private void verifyPasswordBasedDecryptionYieldsCorrectSessionData()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PBE_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPPBEEncryptedData encryptedData = (PGPPBEEncryptedData)encryptedDataList.iterator().next();

        BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
        PBEDataDecryptorFactory decryptorFactory = new BcPBEDataDecryptorFactory(PBE_PASSPHRASE.toCharArray(), digestCalculatorProvider);

        PGPSessionKey sessionKey = encryptedData.getSessionKey(decryptorFactory);
        isEquals(PBE_ENC_SESSIONKEY_ALG, sessionKey.getAlgorithm());
        isTrue(Arrays.equals(Hex.decode(PBE_ENC_SESSIONKEY), sessionKey.getKey()));
    }

    private void verifyJcePBEDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PBE_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPSessionKeyEncryptedData encryptedData = encryptedDataList.extractSessionKeyEncryptedData();

        SessionKeyDataDecryptorFactory decryptorFactory = new JceSessionKeyDataDecryptorFactoryBuilder().build(new PGPSessionKey(PBE_ENC_SESSIONKEY_ALG, Hex.decode(PBE_ENC_SESSIONKEY)));
        InputStream decrypted = encryptedData.getDataStream(decryptorFactory);

        objectFactory = new BcPGPObjectFactory(decrypted);
        PGPCompressedData compressedData = (PGPCompressedData)objectFactory.nextObject();
        InputStream decompressed = compressedData.getDataStream();
        objectFactory = new BcPGPObjectFactory(decompressed);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), out);

        literalData.getDataStream().close();
        isTrue(Arrays.equals(Strings.toByteArray("Hello, World!\n"), out.toByteArray()));
    }

    private void verifyBcPBEDecryptorFactoryFromSessionKeyCanDecryptDataSuccessfully()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(PBE_MESSAGE));
        ArmoredInputStream msgArmorIn = new ArmoredInputStream(msgIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(msgArmorIn);
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)objectFactory.nextObject();
        PGPSessionKeyEncryptedData encryptedData = encryptedDataList.extractSessionKeyEncryptedData();

        SessionKeyDataDecryptorFactory decryptorFactory = new BcSessionKeyDataDecryptorFactory(new PGPSessionKey(PBE_ENC_SESSIONKEY_ALG, Hex.decode(PBE_ENC_SESSIONKEY)));
        InputStream decrypted = encryptedData.getDataStream(decryptorFactory);

        objectFactory = new BcPGPObjectFactory(decrypted);
        PGPCompressedData compressedData = (PGPCompressedData)objectFactory.nextObject();
        InputStream decompressed = compressedData.getDataStream();
        objectFactory = new BcPGPObjectFactory(decompressed);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), out);

        literalData.getDataStream().close();
        isTrue(Arrays.equals(Strings.toByteArray("Hello, World!\n"), out.toByteArray()));
    }

    private void testSessionKeyFromString()
    {
        String sessionKeyString = "9:FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD";
        PGPSessionKey sessionKey = PGPSessionKey.fromAsciiRepresentation(sessionKeyString);
        isEquals(9, sessionKey.getAlgorithm());
        isEquals("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD", Hex.toHexString(sessionKey.getKey()).toUpperCase());
        //isEquals(sessionKeyString, sessionKey.toString());
    }

    // Message consisting only of a symmetrically encrypted integrity protected data packet wrapping a literal data packet
    // see https://dump.sequoia-pgp.org/?data=-----BEGIN%20PGP%20MESSAGE-----%0D%0AVersion%3A%20PGPainless%0D%0A%0D%0A0j8BNtJwO2PLoRdG%2BVynivV7XpHp2Nw/S489vksUKct67CYTFpVTzB4IcJwmUGMm%0D%0Are/N1KMTznEBzy3Txa1QVBc%3D%0D%0A%3Dt%2Bpk%0D%0A-----END%20PGP%20MESSAGE-----&session_key=26BE99BC478520FBC8AB8FB84991DACE4B82CFB9B00F7D05C051D69B8CEA8A7F
    private static final String encryptedMessageWithoutESK = "" +
        "-----BEGIN PGP MESSAGE-----\n" +
        "Version: PGPainless\n" +
        "\n" +
        "0j8BNtJwO2PLoRdG+VynivV7XpHp2Nw/S489vksUKct67CYTFpVTzB4IcJwmUGMm\n" +
        "re/N1KMTznEBzy3Txa1QVBc=\n" +
        "=t+pk\n" +
        "-----END PGP MESSAGE-----";

    private static final PGPSessionKey sessionKey = PGPSessionKey.fromAsciiRepresentation(
        "9:26be99bc478520fbc8ab8fb84991dace4b82cfb9b00f7d05c051d69b8cea8a7f");

    private void decryptMessageWithoutEskUsingSessionKey()
        throws IOException, PGPException
    {
        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(encryptedMessageWithoutESK));
        ArmoredInputStream armorIn = new ArmoredInputStream(msgIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPEncryptedDataList encryptedData = (PGPEncryptedDataList)objectFactory.nextObject();
        isEquals(0, encryptedData.size()); // there is no encrypted session key packet

        // Add decryption method using a session key
        PGPSessionKeyEncryptedData sessionKeyEncData = encryptedData.extractSessionKeyEncryptedData();

        SessionKeyDataDecryptorFactory decryptorFactory = new BcSessionKeyDataDecryptorFactory(sessionKey);

        InputStream decrypted = sessionKeyEncData.getDataStream(decryptorFactory);

        objectFactory = new BcPGPObjectFactory(decrypted);
        PGPLiteralData literalData = (PGPLiteralData)objectFactory.nextObject();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), out);

        literalData.getDataStream().close();
        decrypted.close();
        armorIn.close();
        isTrue(Arrays.equals(Strings.toByteArray("Hello, World!\n"), out.toByteArray()));
    }
}
