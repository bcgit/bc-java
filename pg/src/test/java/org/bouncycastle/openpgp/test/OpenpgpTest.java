package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class OpenpgpTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenpgpTest());
    }

    @Override
    public String getName()
    {
        return "OpenpgpTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testPGPLiteralDataGenerator();
        testContruction();
        testPGPUtil();
        testPGPCompressedDataGenerator();
    }

    public void testPGPCompressedDataGenerator()
    {
        testException("unknown compression algorithm", "IllegalArgumentException", () -> new PGPCompressedDataGenerator(110));
        testException("unknown compression level:", "IllegalArgumentException", () -> new PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED, 10));
    }

    public void testPGPUtil()
        throws Exception
    {
        isEquals("SHA1", PGPUtil.getDigestName(HashAlgorithmTags.SHA1));
        isEquals("MD2", PGPUtil.getDigestName(HashAlgorithmTags.MD2));
        isEquals("MD5", PGPUtil.getDigestName(HashAlgorithmTags.MD5));
        isEquals("RIPEMD160", PGPUtil.getDigestName(HashAlgorithmTags.RIPEMD160));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA256));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256_OLD));
        isEquals("SHA384", PGPUtil.getDigestName(HashAlgorithmTags.SHA384));
        isEquals("SHA384", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_384));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA512));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512_OLD));
        isEquals("SHA224", PGPUtil.getDigestName(HashAlgorithmTags.SHA224));
        isEquals("SHA224", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_224));
        isEquals("TIGER", PGPUtil.getDigestName(HashAlgorithmTags.TIGER_192));
        testException("unknown hash algorithm tag in getDigestName: ", "PGPException", () -> PGPUtil.getDigestName(HashAlgorithmTags.MD4));

        testException("unable to map ", "IllegalArgumentException", () -> PGPUtil.getDigestIDForName("Test"));

        isEquals("SHA1withRSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        isEquals("SHA1withRSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA1));
        isEquals("SHA1withDSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1));
        isEquals("SHA1withElGamal", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, HashAlgorithmTags.SHA1));
        isEquals("SHA1withElGamal", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, HashAlgorithmTags.SHA1));
        testException("unknown algorithm tag in signature:", "PGPException", () -> PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_ENCRYPT, HashAlgorithmTags.SHA1));

        isTrue(PGPUtil.getSymmetricCipherName(SymmetricKeyAlgorithmTags.NULL) == null);
        testException("unknown symmetric algorithm: ", "IllegalArgumentException", () -> PGPUtil.getSymmetricCipherName(101));

        isTrue(!PGPUtil.isKeyBox(new byte[11]));

        isTrue(PGPUtil.makeRandomKey(SymmetricKeyAlgorithmTags.DES, CryptoServicesRegistrar.getSecureRandom()).length == 8);
        testException("unknown symmetric algorithm: ", "PGPException", ()->PGPUtil.makeRandomKey(SymmetricKeyAlgorithmTags.NULL, CryptoServicesRegistrar.getSecureRandom()));

    }

    public void testContruction()
        throws Exception
    {
        String data = "Now is the time for all good men\nTo come to the aid of the party\n";
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, new Date());

        out.write(Strings.toByteArray(data));

        out.close();
        byte[] input = bOut.toByteArray();
        //PGPLiteralData lData = new PGPLiteralData(new ByteArrayInputStream(bOut.toByteArray()));

        //PGPLiteralData
        testException("unexpected packet in stream: ", "IOException", ()-> new PGPCompressedData(new BCPGInputStream(new ByteArrayInputStream(input))));
        //testException("unexpected packet in stream: ", "IOException", ()-> new PGPEncryptedDataList(new BCPGInputStream(new ByteArrayInputStream(input))));
        testException("unexpected packet in stream: ", "IOException", ()-> new PGPMarker(new BCPGInputStream(new ByteArrayInputStream(input))));
        testException("unexpected packet in stream: ", "IOException", ()-> new PGPOnePassSignature(new BCPGInputStream(new ByteArrayInputStream(input))));
        testException("unexpected packet in stream: ", "IOException", ()-> new PGPPadding(new BCPGInputStream(new ByteArrayInputStream(input))));
        //testException("unexpected packet in stream: ", "IOException", ()-> new PGPPublicKeyRing(new BCPGInputStream(new ByteArrayInputStream(input)), new BcKeyFingerprintCalculator()));
        testException("unexpected packet in stream: ", "IOException", ()-> new PGPSignature(new BCPGInputStream(new ByteArrayInputStream(input))));
    }

    public void testPGPLiteralDataGenerator()
        throws Exception
    {
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        String data = "Now is the time for all good men\nTo come to the aid of the party\n";
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
            PGPCompressedData.ZIP);
        BCPGOutputStream bcOut = new BCPGOutputStream(
            cGen.open(new UncloseableOutputStream(bOut)));
        Date testDate = new Date((System.currentTimeMillis() / 1000) * 1000);
        lGen.open(
            new UncloseableOutputStream(bcOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.getBytes().length,
            testDate);
        testException("generator already in open state", "IllegalStateException", ()->lGen.open(
            new UncloseableOutputStream(bcOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.getBytes().length,
            testDate));
        testException("generator already in open state", "IllegalStateException", ()->lGen.open(
            new UncloseableOutputStream(bcOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            testDate,
            new byte[10]));

    }
}
