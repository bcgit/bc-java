package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPDetachedSignatureGenerator;
import org.bouncycastle.openpgp.api.OpenPGPDetachedSignatureProcessor;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPApi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class OpenPGPDetachedSignatureProcessorTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "OpenPGPDetachedSignatureProcessorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        performWith(new BcOpenPGPApi());
        performWith(new JcaOpenPGPApi(new BouncyCastleProvider()));
    }

    private void performWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        createVerifyV4Signature(api);
        createVerifyV6Signature(api);
    }

    private void createVerifyV4Signature(OpenPGPApi api)
            throws IOException, PGPException
    {
        OpenPGPDetachedSignatureGenerator gen = api.createDetachedSignature();
        gen.addSigningKey(
                api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY),
                null);

        byte[] plaintext = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(plaintext);

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = gen.sign(plaintextIn);
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature signature = signatures.get(0);
        isEquals(4, signature.getSignature().getVersion());
        String armored = signature.toAsciiArmoredString();
        isTrue(armored.startsWith("-----BEGIN PGP SIGNATURE-----\n"));

        // Verify detached signatures
        OpenPGPDetachedSignatureProcessor processor = api.verifyDetachedSignature();
        processor.addSignature(signature.getSignature());
        processor.addVerificationCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT));

        List<OpenPGPSignature.OpenPGPDocumentSignature> verified = processor.process(new ByteArrayInputStream(plaintext));
        isEquals(1, verified.size());
        isTrue(verified.get(0).isValid());
    }

    private void createVerifyV6Signature(OpenPGPApi api)
            throws IOException, PGPException
    {
        OpenPGPDetachedSignatureGenerator gen = api.createDetachedSignature();
        gen.addSigningKey(
                api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY),
                null);

        byte[] plaintext = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream plaintextIn = new ByteArrayInputStream(plaintext);

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = gen.sign(plaintextIn);
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature signature = signatures.get(0);
        isEquals(6, signature.getSignature().getVersion());
        String armored = signature.toAsciiArmoredString();
        isTrue(armored.startsWith("-----BEGIN PGP SIGNATURE-----\n"));

        // Verify detached signatures
        OpenPGPDetachedSignatureProcessor processor = api.verifyDetachedSignature();
        processor.addSignature(signature.getSignature());
        processor.addVerificationCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.V6_CERT));

        List<OpenPGPSignature.OpenPGPDocumentSignature> verified = processor.process(new ByteArrayInputStream(plaintext));
        isEquals(1, verified.size());
        isTrue(verified.get(0).isValid());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPDetachedSignatureProcessorTest());
    }
}
