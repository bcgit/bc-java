package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class PGPv6MessageDecryptionTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "PGPv6MessageDecryptionTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        decryptMessageEncryptedUsingPKESKv6();
    }

    private void decryptMessageEncryptedUsingPKESKv6()
            throws IOException, PGPException
    {
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) objFac.nextObject();
        pIn.close();
        aIn.close();
        bIn.close();

        // created using rpgpie 0.1.1 (rpgp 0.14.0-alpha.0)
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRk5Bu/DU62hzgRm\n" +
                "JYvBYeLA2Nrmz15g69ZN0xAB7SLDRCjjhnK6V7fGns6P1EiSCYbl1uNVBhK0MPGe\n" +
                "rU9FY4yUXTnbB6eIXdCw0loCCQIOu95D17wvJJC2a96ou9SGPIoA4Q2dMH5BMS9Z\n" +
                "veq3AGgIBdJMF8Ft8PBE30R0cba1O5oQC0Eiscw7fkNnYGuSXagqNXdOBkHDN0fk\n" +
                "VWFrxQRbxEVYUWc=\n" +
                "=u2kL\n" +
                "-----END PGP MESSAGE-----\n";
        bIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
        aIn = new ArmoredInputStream(bIn);
        pIn = new BCPGInputStream(aIn);
        objFac = new BcPGPObjectFactory(pIn);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(0);

        isEquals(PublicKeyEncSessionPacket.VERSION_6, encData.getVersion());
        isEquals(PublicKeyAlgorithmTags.X25519, encData.getAlgorithm());
        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID()); // TODO: getKeyIdentifier()
        isNotNull("Decryption key MUST be identifiable", decryptionKey);
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new BcPublicKeyDataDecryptorFactory(privateKey);
        InputStream decrypted = encData.getDataStream(decryptor);
        PGPObjectFactory decFac = new BcPGPObjectFactory(decrypted);
        PGPLiteralData lit = (PGPLiteralData) decFac.nextObject();
        isEncodingEqual(
                "Hello World :)".getBytes(StandardCharsets.UTF_8),
                Streams.readAll(lit.getDataStream()));
    }

    public static void main(String[] args)
    {
        runTest(new PGPv6MessageDecryptionTest());
    }
}
