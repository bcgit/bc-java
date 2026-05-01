package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.TimeZone;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class BcpgGeneralTest
    extends SimpleTest
{
    /*
    * Format: Binary data
    Filename: "hello.txt"
    Timestamp: 2104-06-26 14:42:55 UTC
    Content: "Hello, world!\n"
    * */
    byte[] message = Strings.toUTF8ByteArray("-----BEGIN PGP MESSAGE-----\n" +
        "\n" +
        "yx1iCWhlbGxvLnR4dPz1TW9IZWxsbywgd29ybGQhCg==\n" +
        "=3swl\n" +
        "-----END PGP MESSAGE-----");



    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcpgGeneralTest());
    }

    @Override
    public String getName()
    {
        return "BcpgGeneralTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testReadTime();
        testReadTime2();
        //testS2K();
        testExceptions();
        testECDHPublicBCPGKey();
        // Tests for PreferredAEADCiphersuites
        testPreferredAEADCiphersuites();
    }

    static int read4OctetLength(InputStream in)
        throws IOException
    {
        return (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
    }

    // StreamUtil.readTime
    static long readTime(BCPGInputStream in)
        throws IOException
    {
        return ((long)read4OctetLength(in) & 0xFFFFFFFFL) * 1000L;
    }

    public void testReadTime()
        throws IOException
    {
        Calendar calendar = Calendar.getInstance();
        calendar.set(2074, Calendar.JANUARY, 1, 0, 0, 0);
        calendar.set(Calendar.MILLISECOND, 0);

        Date tmp = calendar.getTime();
        long time = tmp.getTime() / 1000L * 1000L;
        byte[] date = Pack.intToBigEndian((int)(time / 1000L));

        ByteArrayInputStream bs = new ByteArrayInputStream(date);
        BCPGInputStream stream = new BCPGInputStream(bs);
        long rlt = readTime(stream);
        isTrue(rlt == time);

        time = Long.MAX_VALUE / 1000L * 1000L;
        date = Pack.intToBigEndian((int)(time / 1000L));
        bs = new ByteArrayInputStream(date);
        stream = new BCPGInputStream(bs);
        rlt = readTime(stream);
        byte[] date2 = Pack.intToBigEndian((int)(rlt / 1000L));
        isTrue(Arrays.areEqual(date, date2));
    }

    public void testReadTime2()
        throws Exception
    {
        PGPObjectFactory pgpObjectFactoryOfTestFile = new PGPObjectFactory(
            new ArmoredInputStream(new ByteArrayInputStream(message)), new JcaKeyFingerprintCalculator());
        PGPLiteralData ld = (PGPLiteralData)pgpObjectFactoryOfTestFile.nextObject();
        Date date = ld.getModificationTime();

        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.set(2104, Calendar.JUNE, 26, 14, 42, 55);
        calendar.set(Calendar.MILLISECOND, 0);
        Date expected = calendar.getTime();

        isTrue(date.equals(expected));
    }

    public void testPreferredAEADCiphersuites()
        throws Exception
    {
        PreferredAEADCiphersuites preferences = new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]
            {
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.GCM),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.CAMELLIA_256, AEADAlgorithmTags.OCB)
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(bOut);

        preferences.encode(bcpgOut);

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        SignatureSubpacketInputStream subpacketIn = new SignatureSubpacketInputStream(bIn);
        isEquals(subpacketIn.available(), 8);
        SignatureSubpacket subpacket = subpacketIn.readPacket();
        assert subpacket != null;
        assert subpacket instanceof PreferredAEADCiphersuites;

        PreferredAEADCiphersuites parsed = (PreferredAEADCiphersuites)subpacket;
        isTrue(Arrays.areEqual(preferences.getAlgorithms(), parsed.getAlgorithms()));
        PreferredAEADCiphersuites.Combination[] preferencesCombinations = preferences.getAlgorithms();
        PreferredAEADCiphersuites.Combination[] parsedCombinations = parsed.getAlgorithms();
        isTrue(!preferencesCombinations[0].equals(null));
        isTrue(!preferencesCombinations[0].equals(new Object()));
        isTrue(preferencesCombinations[0].equals(preferencesCombinations[0]));
        isTrue(!preferencesCombinations[0].equals(preferencesCombinations[1]));
        isTrue(!preferencesCombinations[0].equals(preferencesCombinations[2]));
        isTrue(preferencesCombinations[0].equals(parsedCombinations[0]));
        isTrue(preferences.isSupported(new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.CAMELLIA_256, AEADAlgorithmTags.OCB)));
        isTrue(!preferences.isSupported(new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)));
        isTrue(preferencesCombinations[0].hashCode() == parsedCombinations[0].hashCode());
    }

    public void testECDHPublicBCPGKey()
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
        final X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(random));
//        testException("Symmetric key algorithm must be AES-128 or stronger.", "IllegalStateException", () ->
//            new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(8, SymmetricKeyAlgorithmTags.IDEA), gen.generateKeyPair(), new Date()));
//        testException("Hash algorithm must be SHA-256 or stronger.", "IllegalStateException", () ->
//            new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(HashAlgorithmTags.SHA1, 7), gen.generateKeyPair(), new Date()));

//        new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(8, SymmetricKeyAlgorithmTags.CAMELLIA_256), gen.generateKeyPair(), new Date());
        BcPGPKeyPair kp = new BcPGPKeyPair(PGPPublicKey.ECDH, gen.generateKeyPair(), new Date());

        ECDHPublicBCPGKey publicBCPGKey = (ECDHPublicBCPGKey)kp.getPublicKey().getPublicKeyPacket().getKey();
        isTrue(publicBCPGKey.getReserved() == 1);
        isTrue(publicBCPGKey.getFormat().equals("PGP"));

        ECSecretBCPGKey secretBCPGKey = (ECSecretBCPGKey)kp.getPrivateKey().getPrivateKeyDataPacket();
        isTrue(secretBCPGKey.getFormat().equals("PGP"));
        isTrue(Arrays.areEqual(publicBCPGKey.getEncoded(), kp.getPrivateKey().getPublicKeyPacket().getKey().getEncoded()));


    }

    public void testExceptions()
        throws Exception
    {
//        final PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
//            new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256));
//        encGen.addMethod(new BcPBEKeyEncryptionMethodGenerator(Argon2S2KTest.TEST_MSG_PASSWORD.toCharArray(), S2K.Argon2Params.universallyRecommendedParameters())
//            .setSecureRandom(CryptoServicesRegistrar.getSecureRandom()));
//        final PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
//
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        final ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
//        final OutputStream encOut = encGen.open(armorOut, new byte[10]);
//        testException("generator already in open state", "IllegalStateException", () -> encGen.open(armorOut, new byte[10]));
//
//        OutputStream litOut = litGen.open(encOut, PGPLiteralData.UTF8, "", new Date(), new byte[10]);
//        testException("generator already in open state", "IllegalStateException", () -> litGen.open(encOut, PGPLiteralData.UTF8, "", new Date(), new byte[10]));
//
//
//        testException("generator already in open state", "IllegalStateException", () -> litGen.open(encOut, PGPLiteralData.UTF8, "", 10, new Date()));
//
//        ByteArrayInputStream plainIn = new ByteArrayInputStream(Strings.toByteArray(Argon2S2KTest.TEST_MSG_PLAIN));
//        Streams.pipeAll(plainIn, litOut);
//        litOut.close();
//
//        armorOut.close();

        ByteArrayInputStream msgIn = new ByteArrayInputStream(Strings.toByteArray(Argon2S2KTest.TEST_MSG_AES128));
        ArmoredInputStream armorIn = new ArmoredInputStream(msgIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        final Iterator it = objectFactory.iterator();
        testException("Cannot remove element from factory.", "UnsupportedOperationException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                it.remove();
            }
        });
        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList)it.next();
        testException(null, "NoSuchElementException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                it.next();
            }
        });

        PGPPBEEncryptedData encryptedData = (PGPPBEEncryptedData)encryptedDataList.get(0);
        isEquals(encryptedData.getAlgorithm(), SymmetricKeyAlgorithmTags.AES_128);

    }

    public void testS2K()
        throws Exception
    {
        S2K s2k = new S2K(HashAlgorithmTags.SHA1);
        SymmetricKeyEncSessionPacket packet = SymmetricKeyEncSessionPacket.createV4Packet(SymmetricKeyAlgorithmTags.AES_256, s2k, null);
//PGPObjectFactory
        packet = new SymmetricKeyEncSessionPacket(new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded())));
        isEquals(s2k.getHashAlgorithm(), packet.getS2K().getHashAlgorithm());
        isEquals(s2k.getType(), packet.getS2K().getType());
        isEquals(S2K.SIMPLE, packet.getS2K().getType());

        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        s2k = new S2K(HashAlgorithmTags.SHA1, iv);
        packet = SymmetricKeyEncSessionPacket.createV4Packet(SymmetricKeyAlgorithmTags.AES_256, s2k, null);

        packet = new SymmetricKeyEncSessionPacket(new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded())));
        isEquals(s2k.getHashAlgorithm(), packet.getS2K().getHashAlgorithm());
        isEquals(s2k.getType(), packet.getS2K().getType());
        isEquals(s2k.getIV(), packet.getS2K().getIV());
        isEquals(S2K.SALTED, packet.getS2K().getType());
    }
}
