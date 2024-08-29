package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class PGPv5MessageDecryptionTest
        extends AbstractPacketTest
{

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
        isEncodingEqual("Plaintext mismatch", plaintext, "Hello, world!\n".getBytes(StandardCharsets.UTF_8));
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
        isEncodingEqual("Plaintext mismatch", plaintext, "Hello, world!\n".getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args)
    {
        runTest(new PGPv5MessageDecryptionTest());
    }
}
