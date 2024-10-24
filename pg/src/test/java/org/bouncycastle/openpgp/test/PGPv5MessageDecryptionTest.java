package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class PGPv5MessageDecryptionTest
    extends AbstractPacketTest
{
    // LibrePGP v5 test key "emma"
    private static final String V5KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
        "\n" +
        "lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd\n" +
        "fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA\n" +
        "Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC\n" +
        "X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI\n" +
        "CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9\n" +
        "M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA\n" +
        "MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD\n" +
        "AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF\n" +
        "GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb\n" +
        "DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7\n" +
        "TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==\n" +
        "=IiS2\n" +
        "-----END PGP PRIVATE KEY BLOCK-----\n";
    // Test message using an OCB encrypted data packet created using GnuPG 2.4.4
    private static final String V5OEDMessage = "-----BEGIN PGP MESSAGE-----\n" +
        "\n" +
        "hF4D5FV8KwL/v0sSAQdAWGU5E5xLsO57USnkfhhedf5CZCzw7gGsDAkVCyC421Ew\n" +
        "d9+XWS6iJEB/+yZRYainM9d9YzFeD4PmqgrDArYD3sBBm/6BAUI8/h1+cbV+BUl5\n" +
        "1FMBCQIQT5VZWWb7s7hZ7QlJgK/M5/Ikw+CiShMQgoADRoUw78BL+XSVMKBx/79S\n" +
        "/OyxT6obt6eZLt9a7vG+SIA4Wym+IXEkqxVp3KOpIlDJoAzwKw==\n" +
        "=syKJ\n" +
        "-----END PGP MESSAGE-----\n";
    private static final String V5OEDMessageSessionKey = "9:E376D03AEFB2F6E9EFEB33FDFEFCF92A562D20585B63CE1EC09B57A33B780C3A";

    // https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-sample-ocb-encryption-and-d
    private static final byte[] MSG0_SKESK5 = Hex.decode("c33d05070203089f0b7da3e5ea647790" +
        "99e326e5400a90936cefb4e8eba08c67" +
        "73716d1f2714540a38fcac529949dac5" +
        "29d3de31e15b4aeb729e330033dbed");
    private static final byte[] MSG0_OCBED = Hex.decode("d4490107020e5ed2bc1e470abe8f1d64" +
        "4c7a6c8a567b0f7701196611a154ba9c" +
        "2574cd056284a8ef68035c623d93cc70" +
        "8a43211bb6eaf2b27f7c18d571bcd83b" +
        "20add3a08b73af15b9a098");

    @Override
    public String getName()
    {
        return "PGPv5MessageDecryptionTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        decryptSKESK5OCBED1_bc();
        decryptSKESK5OCBED1_jce();

        decryptOCBED1viaSessionKey_bc();
        decryptOCBED1viaSessionKey_jca();

        decryptPKESK3OCBED1_bc();
        decryptPKESK3OCBED1_jce();
    }

    private void decryptSKESK5OCBED1_bc()
        throws IOException, PGPException
    {
        String passphrase = "password";

        ByteArrayInputStream bIn = new ByteArrayInputStream(Arrays.concatenate(MSG0_SKESK5, MSG0_OCBED));
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPBEEncryptedData encData = (PGPPBEEncryptedData) encList.get(0);
        InputStream decIn = encData.getDataStream(
            new BcPBEDataDecryptorFactory(passphrase.toCharArray(),
                new BcPGPDigestCalculatorProvider()));
        objFac = new BcPGPObjectFactory(decIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual("Plaintext mismatch", plaintext, Strings.toUTF8ByteArray("Hello, world!\n"));
    }

    private void decryptSKESK5OCBED1_jce()
        throws IOException, PGPException
    {
        // https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-sample-ocb-encryption-and-d
        String passphrase = "password";
        ByteArrayInputStream bIn = new ByteArrayInputStream(Arrays.concatenate(MSG0_SKESK5, MSG0_OCBED));
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new JcaPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPBEEncryptedData encData = (PGPPBEEncryptedData) encList.get(0);
        InputStream decIn = encData.getDataStream(
            new JcePBEDataDecryptorFactoryBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(passphrase.toCharArray()));
        objFac = new JcaPGPObjectFactory(decIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual("Plaintext mismatch", plaintext, Strings.toUTF8ByteArray("Hello, world!\n"));
    }

    private void decryptOCBED1viaSessionKey_bc()
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5OEDMessage));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);

        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPSessionKeyEncryptedData encData = encList.extractSessionKeyEncryptedData();
        SessionKeyDataDecryptorFactory decFac = new BcSessionKeyDataDecryptorFactory(
            PGPSessionKey.fromAsciiRepresentation(V5OEDMessageSessionKey));
        InputStream decIn = encData.getDataStream(decFac);
        objFac = new BcPGPObjectFactory(decIn);
        PGPCompressedData comData = (PGPCompressedData) objFac.nextObject();
        InputStream comIn = comData.getDataStream();
        objFac = new BcPGPObjectFactory(comIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual(Strings.toUTF8ByteArray("Hello World :)"), plaintext);
    }

    private void decryptOCBED1viaSessionKey_jca()
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5OEDMessage));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new JcaPGPObjectFactory(pIn);

        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPSessionKeyEncryptedData encData = encList.extractSessionKeyEncryptedData();
        SessionKeyDataDecryptorFactory decFac = new JceSessionKeyDataDecryptorFactoryBuilder()
            .setProvider(new BouncyCastleProvider())
            .build(PGPSessionKey.fromAsciiRepresentation(V5OEDMessageSessionKey));
        InputStream decIn = encData.getDataStream(decFac);
        objFac = new JcaPGPObjectFactory(decIn);
        PGPCompressedData comData = (PGPCompressedData) objFac.nextObject();
        InputStream comIn = comData.getDataStream();
        objFac = new JcaPGPObjectFactory(comIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual(Strings.toUTF8ByteArray("Hello World :)"), plaintext);
    }

    private void decryptPKESK3OCBED1_bc()
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5OEDMessage));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID());
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        InputStream decIn = encData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
        pIn = new BCPGInputStream(decIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPCompressedData com = (PGPCompressedData) objFac.nextObject();
        InputStream comIn = com.getDataStream();
        objFac = new BcPGPObjectFactory(comIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual("Plaintext mismatch", plaintext, Strings.toUTF8ByteArray("Hello World :)"));
    }

    private void decryptPKESK3OCBED1_jce()
        throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new JcaPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V5OEDMessage));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new JcaPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID());
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        InputStream decIn = encData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(new BouncyCastleProvider())
            .build(privateKey));
        pIn = new BCPGInputStream(decIn);
        objFac = new JcaPGPObjectFactory(pIn);
        PGPCompressedData com = (PGPCompressedData) objFac.nextObject();
        InputStream comIn = com.getDataStream();
        objFac = new JcaPGPObjectFactory(comIn);
        PGPLiteralData lit = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(lit.getDataStream());
        isEncodingEqual("Plaintext mismatch", plaintext, Strings.toUTF8ByteArray("Hello World :)"));
    }

    public static void main(String[] args)
    {
        runTest(new PGPv5MessageDecryptionTest());
    }
}