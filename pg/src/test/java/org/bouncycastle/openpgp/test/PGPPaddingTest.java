package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

public class PGPPaddingTest
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPPaddingTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        randomPaddingIsInBounds();
        fixedLenPaddingIsCorrectLength();
        negativePaddingLengthThrows();
        zeroPaddingLengthThrows();

        parsePaddedCertificate();
    }

    private void randomPaddingIsInBounds()
    {
        for (int i = 0; i < 10; i++)
        {
            PGPPadding padding = new PGPPadding();
            int len = padding.getPadding().length;
            isTrue("Padding length exceeds bounds. Min: " + PGPPadding.MIN_PADDING_LEN +
                            ", Max: " + PGPPadding.MAX_PADDING_LEN + ", Actual: " + len ,
                    len >= PGPPadding.MIN_PADDING_LEN && len <= PGPPadding.MAX_PADDING_LEN);
        }
    }

    private void fixedLenPaddingIsCorrectLength()
    {
        PGPPadding padding = new PGPPadding(42);
        isEquals("Padding length mismatch", 42, padding.getPadding().length);
    }

    private void negativePaddingLengthThrows()
    {
        testException(null, "IllegalArgumentException", () -> new PGPPadding(-1));
    }

    private void zeroPaddingLengthThrows()
    {
        testException(null, "IllegalArgumentException", () -> new PGPPadding(0));
    }

    private void parsePaddedCertificate()
            throws PGPException, IOException
    {
        PGPDigestCalculator digestCalc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        Date creationTime = new Date(1000 * (new Date().getTime() / 1000));
        Ed25519KeyPairGenerator edGen = new Ed25519KeyPairGenerator();
        edGen.init(new Ed25519KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair edPair = edGen.generateKeyPair();

        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(new X25519KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair xPair = xGen.generateKeyPair();

        PGPKeyPair primayKeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, edPair, creationTime);
        PGPKeyPair subKeyPair = new BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, xPair, creationTime);

        PGPSecretKey secretPrimaryKey = new PGPSecretKey(primayKeyPair.getPrivateKey(), primayKeyPair.getPublicKey(), digestCalc, true, null);
        PGPSecretKey secretSubKey = new PGPSecretKey(subKeyPair.getPrivateKey(), subKeyPair.getPublicKey(), digestCalc, false, null);

        PGPPublicKeyRing certificate = new PGPPublicKeyRing(Arrays.asList(secretPrimaryKey.getPublicKey(), secretSubKey.getPublicKey()));
        PGPPadding padding = new PGPPadding();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().clearHeaders().build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        certificate.encode(pOut);
        padding.encode(pOut);

        pOut.close();
        aOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);

        PGPPublicKeyRing parsed = new PGPPublicKeyRing(pIn, new BcKeyFingerprintCalculator());
        isTrue(org.bouncycastle.util.Arrays.areEqual(
                certificate.getEncoded(PacketFormat.CURRENT),
                parsed.getEncoded(PacketFormat.CURRENT)));
    }

    public static void main(String[] args)
    {
        runTest(new PGPPaddingTest());
    }
}
