package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class EncryptedMessagePacketTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "PublicKeyEncryptedDataPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testPKESK6SEIPD2();
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
        ByteArrayInputStream bIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
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
