package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class EncryptedMessagePacketTest
        extends AbstractPacketTest
{
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-secret-key
    final String V6_SECRET_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
            "k0mXubZvyl4GBg==\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    // https://www.rfc-editor.org/rfc/rfc9580.html#name-complete-x25519-aead-ocb-en
    final String X25519_AEAD_OCB_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO\n" +
            "WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS\n" +
            "aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l\n" +
            "yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo\n" +
            "bhF30A+IitsxxA==\n" +
            "-----END PGP MESSAGE-----";

    @Override
    public String getName()
    {
        return "PublicKeyEncryptedDataPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testX25519AEADOCBTestVector_bc();
        testX25519AEADOCBTestVector_jce();
        testPKESK6SEIPD2FromTestVector();
        testPKESK6SEIPD2();
    }

    private void testPKESK6SEIPD2FromTestVector()
            throws IOException, PGPException
    {
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-6-public-key
        byte[] pkesk = Hex.decode("c15d06210612c83f" +
                "1e706f6308fe151a" +
                "417743a1f033790e" +
                "93e9978488d1db37" +
                "8da99308851987cf" +
                "18d5f1b53f817cce" +
                "5a004cf393cc8958" +
                "bddc065f25f84af5" +
                "09b17dd3676418de" +
                "a355437956617901" +
                "e06957fbca8a6a47" +
                "a5b5153e8d3ab7");

        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-v2-seipd-packet
        byte[] seipd = Hex.decode("d269020702066164" +
                "16535be0b0716d60" +
                "e052a56c4c407f9e" +
                "b36b0efafe9ad0a0" +
                "df9b033c69a21ba9" +
                "ebd2c0ec95bf569d" +
                "25c999ee4a3de170" +
                "58f40dfa8b4c682b" +
                "e3fbbbd7b27eb0f5" +
                "9bb5005f80c7c6f4" +
                "0388c30ad406ab05" +
                "13dcd6f9fd737656" +
                "286e1177d00f888a" +
                "db31c4");

        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V6_SECRET_KEY));;
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(Arrays.concatenate(pkesk, seipd));
        pIn = new BCPGInputStream(bIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
        PGPSecretKey decKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        PGPPrivateKey privKey = decKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new BcPublicKeyDataDecryptorFactory(privKey);
        InputStream in = encData.getDataStream(decryptor);
        objFac = new BcPGPObjectFactory(in);
        PGPLiteralData literalData = (PGPLiteralData) objFac.nextObject();
        byte[] msg = Streams.readAll(literalData.getDataStream());
        isEncodingEqual(Strings.toUTF8ByteArray("Hello, world!"), msg);
        PGPPadding padding = (PGPPadding) objFac.nextObject();
        isEncodingEqual(Hex.decode("c5a293072991628147d72c8f86b7"), padding.getPadding());
    }

    private void testX25519AEADOCBTestVector_bc()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V6_SECRET_KEY));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(X25519_AEAD_OCB_MESSAGE.getBytes());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);
        PGPSecretKey decKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        PGPPrivateKey privKey = decKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new BcPublicKeyDataDecryptorFactory(privKey);
        InputStream in = encData.getDataStream(decryptor);
        objFac = new BcPGPObjectFactory(in);
        PGPLiteralData literalData = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(literalData.getDataStream());
        isEncodingEqual(Strings.toUTF8ByteArray("Hello, world!"), plaintext);
        PGPPadding padding = (PGPPadding) objFac.nextObject();
        isEncodingEqual(Hex.decode("c5a293072991628147d72c8f86b7"), padding.getPadding());
    }

    private void testX25519AEADOCBTestVector_jce()
            throws IOException, PGPException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(V6_SECRET_KEY));;
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new JcaPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();

        bIn = new ByteArrayInputStream(X25519_AEAD_OCB_MESSAGE.getBytes());
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new JcaPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

        PGPSecretKey decKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        PGPPrivateKey privKey = decKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(new BouncyCastleProvider())
                .setContentProvider(new BouncyCastleProvider())
                .build(privKey);
        InputStream in = encData.getDataStream(decryptor);
        objFac = new JcaPGPObjectFactory(in);
        PGPLiteralData literalData = (PGPLiteralData) objFac.nextObject();
        byte[] plaintext = Streams.readAll(literalData.getDataStream());
        isEncodingEqual(Strings.toUTF8ByteArray("Hello, world!"), plaintext);
        PGPPadding padding = (PGPPadding) objFac.nextObject();
        isEncodingEqual(Hex.decode("c5a293072991628147d72c8f86b7"), padding.getPadding());
    }

    private void testPKESK6SEIPD2()
            throws IOException
    {
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRk5Bu/DU62hzgRm\n" +
                "JYvBYeLA2Nrmz15g69ZN0xAB7SLDRCjjhnK6V7fGns6P1EiSCYbl1uNVBhK0MPGe\n" +
                "rU9FY4yUXTnbB6eIXdCw0loCCQIOu95D17wvJJC2a96ou9SGPIoA4Q2dMH5BMS9Z\n" +
                "veq3AGgIBdJMF8Ft8PBE30R0cba1O5oQC0Eiscw7fkNnYGuSXagqNXdOBkHDN0fk\n" +
                "VWFrxQRbxEVYUWc=\n" +
                "=u2kL\n" +
                "-----END PGP MESSAGE-----\n";
        byte[] fingerprint = Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket) pIn.readPacket();
        isEquals("PKESK version mismatch",
                PublicKeyEncSessionPacket.VERSION_6, pkesk.getVersion());
        isEncodingEqual("PKESK fingerprint mismatch",
                fingerprint, pkesk.getKeyFingerprint());
        isEquals("PKESK derived key-id mismatch",
                FingerprintUtil.keyIdFromV6Fingerprint(fingerprint), pkesk.getKeyID());
        isEquals("PKESK public key alg mismatch",
                PublicKeyAlgorithmTags.X25519, pkesk.getAlgorithm());

        SymmetricEncIntegrityPacket skesk = (SymmetricEncIntegrityPacket) pIn.readPacket();
        isEquals("SKESK version mismatch",
                SymmetricEncIntegrityPacket.VERSION_2, skesk.getVersion());
        isEquals("SKESK sym alg mismatch",
                SymmetricKeyAlgorithmTags.AES_256, skesk.getCipherAlgorithm());
        isEquals("SKESK AEAD alg mismatch",
                AEADAlgorithmTags.OCB, skesk.getAeadAlgorithm());
        isEquals("SKESK chunk size mismatch",
                0x0e, skesk.getChunkSize());
        isEncodingEqual("SKESK salt mismatch",
                Hex.decode("BBDE43D7BC2F2490B66BDEA8BBD4863C8A00E10D9D307E41312F59BDEAB70068"), skesk.getSalt());
    }

    public static void main(String[] args)
    {
        runTest(new EncryptedMessagePacketTest());
    }
}
