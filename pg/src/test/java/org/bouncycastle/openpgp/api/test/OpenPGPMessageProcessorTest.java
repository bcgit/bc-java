package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class OpenPGPMessageProcessorTest
        extends AbstractPacketTest
{
    private static final byte[] PLAINTEXT = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private PGPSessionKey encryptionSessionKey;

    @Override
    public String getName()
    {
        return "OpenPGPMessageProcessorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testVerificationOfSEIPD1MessageWithTamperedCiphertext();

        roundtripUnarmoredPlaintextMessage();
        roundtripArmoredPlaintextMessage();
        roundTripCompressedMessage();
        roundTripCompressedSymEncMessageMessage();

        roundTripSymEncMessageWithMultiplePassphrases();

        roundTripV4KeyEncryptedMessageAlice();
        roundTripV4KeyEncryptedMessageBob();
        roundTripV4KeyEncryptedMessageCarol();

        roundTripV6KeyEncryptedMessage();
        encryptWithV4V6KeyDecryptWithV4();
        encryptWithV4V6KeyDecryptWithV6();

        encryptDecryptWithLockedKey();
        encryptDecryptWithMissingKey();

        inlineSignWithV4KeyAlice();
        inlineSignWithV4KeyBob();
        inlineSignWithV4KeyCarol();
        inlineSignWithV6Key();

        verifyMessageByRevokedKey();
        incompleteMessageProcessing();
    }

    private void roundtripUnarmoredPlaintextMessage()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(false)
                .setIsPadded(false);

        gen.getConfiguration().setCompressionNegotiator(conf -> CompressionAlgorithmTags.UNCOMPRESSED);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        OpenPGPMessageInputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        isEquals(MessageEncryptionMechanism.unencrypted(), plainIn.getResult().getEncryptionMethod());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundtripArmoredPlaintextMessage()
            throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .setIsPadded(false);
        gen.getConfiguration().setCompressionNegotiator(conf -> CompressionAlgorithmTags.UNCOMPRESSED);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        OpenPGPMessageInputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        OpenPGPMessageInputStream.Result result = plainIn.getResult();
        isEquals(MessageEncryptionMechanism.unencrypted(), result.getEncryptionMethod());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedMessage()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .setIsPadded(false);
        gen.getConfiguration().setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedSymEncMessageMessage()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .addEncryptionPassphrase("lal".toCharArray())
                .setSessionKeyExtractionCallback(
                        sk -> this.encryptionSessionKey = sk
                )
                .setIsPadded(false);
        gen.getConfiguration()
                .setPasswordBasedEncryptionNegotiator(conf ->
                        MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256))
                .setCompressionNegotiator(conf -> CompressionAlgorithmTags.ZIP);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();
        isNotNull(encryptionSessionKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream plainIn = new OpenPGPMessageProcessor()
                .addMessagePassphrase("lal".toCharArray())
                .process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        OpenPGPMessageInputStream.Result result = plainIn.getResult();
        isEquals(CompressionAlgorithmTags.ZIP, result.getCompressionAlgorithm());
        isTrue(Arrays.areEqual("lal".toCharArray(), result.getDecryptionPassphrase()));
        isEncodingEqual(encryptionSessionKey.getKey(), result.getSessionKey().getKey());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripSymEncMessageWithMultiplePassphrases()
            throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .addEncryptionPassphrase("orange".toCharArray())
                .addEncryptionPassphrase("violet".toCharArray())
                .setSessionKeyExtractionCallback(sk -> this.encryptionSessionKey = sk);
        gen.getConfiguration().setPasswordBasedEncryptionNegotiator(configuration ->
                MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB));

        OutputStream encOut = gen.open(bOut);
        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();

        // Try decryption with explicitly set message passphrase
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addMessagePassphrase("violet".toCharArray());
        OpenPGPMessageInputStream decIn = processor.process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isTrue(Arrays.areEqual("violet".toCharArray(), result.getDecryptionPassphrase()));
        isEncodingEqual(encryptionSessionKey.getKey(), result.getSessionKey().getKey());
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
        isEquals(result.getEncryptionMethod(),
                MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB));

        // Try decryption with wrong passphrase and then request proper one dynamically
        bOut = new ByteArrayOutputStream();
        bIn = new ByteArrayInputStream(ciphertext);
        processor = new OpenPGPMessageProcessor();
        decIn = processor.setMissingMessagePassphraseCallback(new StackPassphraseCallback("orange".toCharArray()))
                // wrong passphrase, so missing callback is invoked
                .addMessagePassphrase("yellow".toCharArray())
                .process(bIn);

        Streams.pipeAll(decIn, bOut);
        decIn.close();
        result = decIn.getResult();
        isTrue(Arrays.areEqual("orange".toCharArray(), result.getDecryptionPassphrase()));
        isEncodingEqual(encryptionSessionKey.getKey(), result.getSessionKey().getKey());
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
    }

    private void roundTripV4KeyEncryptedMessageAlice()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.ALICE_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
                result.getEncryptionMethod());
    }

    private void roundTripV4KeyEncryptedMessageBob()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.BOB_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.BOB_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
                result.getEncryptionMethod());
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
    }

    private void roundTripV4KeyEncryptedMessageCarol()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.CAROL_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.CAROL_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
                result.getEncryptionMethod());
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
    }

    private void roundTripV6KeyEncryptedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY);

        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setArmored(true)
                .addEncryptionCertificate(key)
                .setIsPadded(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addDecryptionKey(key);

        OpenPGPMessageInputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        OpenPGPMessageInputStream.Result result = plainIn.getResult();
        isEquals(MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
                result.getEncryptionMethod());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void encryptWithV4V6KeyDecryptWithV4()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT));
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.V6_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.ALICE_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
                result.getEncryptionMethod());
    }

    private void encryptWithV4V6KeyDecryptWithV6()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT));
        gen.addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.V6_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
                result.getEncryptionMethod());
    }

    private void encryptDecryptWithLockedKey()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY_LOCKED);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OpenPGPMessageOutputStream encOut = new OpenPGPMessageGenerator()
                .addEncryptionCertificate(key)
                .open(bOut);

        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();

        // Provide passphrase and key together
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        OpenPGPMessageInputStream decIn = new OpenPGPMessageProcessor()
                .addDecryptionKey(key, OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray())
                .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        PGPSessionKey sk = result.getSessionKey();

        // Provide passphrase and key separate from another
        bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        decIn = new OpenPGPMessageProcessor()
                .addDecryptionKey(key)
                .addDecryptionKeyPassphrase(OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray())
                .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
        result = decIn.getResult();
        isEncodingEqual(sk.getKey(), result.getSessionKey().getKey());

        // Provide passphrase dynamically
        bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        decIn = new OpenPGPMessageProcessor()
                .addDecryptionKey(key)
                .setMissingOpenPGPKeyPassphraseProvider(k ->
                        OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray())
                .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());

        result = decIn.getResult();
        isEncodingEqual(sk.getKey(), result.getSessionKey().getKey());
    }

    private void encryptDecryptWithMissingKey()
            throws IOException, PGPException
    {
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream encOut = new OpenPGPMessageGenerator()
                .addEncryptionCertificate(key)
                .open(bOut);

        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();

        // Provide passphrase and key together
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        OpenPGPMessageInputStream decIn = new OpenPGPMessageProcessor()
                .setMissingOpenPGPKeyProvider(id -> key)
                .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());

        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(key, result.getDecryptionKey().getCertificate());
        isNotNull(result.getSessionKey());
    }

    private void inlineSignWithV4KeyAlice()
            throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        OpenPGPKey aliceKey = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.ALICE_KEY);
        gen.addSigningKey(aliceKey);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate aliceCert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT);
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addVerificationCertificate(aliceCert);

        OpenPGPMessageInputStream verifIn = processor.process(bIn);
        Streams.pipeAll(verifIn, bOut);
        verifIn.close();
        OpenPGPMessageInputStream.Result result = verifIn.getResult();
        isEquals(MessageEncryptionMechanism.unencrypted(), result.getEncryptionMethod());
        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = result.getSignatures();
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature sig = signatures.get(0);
        isEquals(aliceCert, sig.getIssuerCertificate());

        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
    }

    private void inlineSignWithV4KeyBob()
            throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        OpenPGPKey bobKey = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.BOB_KEY);
        gen.addSigningKey(bobKey);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate bobCert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.BOB_CERT);
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addVerificationCertificate(bobCert);

        OpenPGPMessageInputStream verifIn = processor.process(bIn);
        Streams.pipeAll(verifIn, bOut);
        verifIn.close();
        OpenPGPMessageInputStream.Result result = verifIn.getResult();
        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = result.getSignatures();
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature sig = signatures.get(0);
        isEquals(bobCert, sig.getIssuerCertificate());

        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
    }

    private void inlineSignWithV4KeyCarol()
            throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        OpenPGPKey carolKey = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.CAROL_KEY);
        gen.addSigningKey(carolKey);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate carolCert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.CAROL_CERT);
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addVerificationCertificate(carolCert);

        OpenPGPMessageInputStream verifIn = processor.process(bIn);
        Streams.pipeAll(verifIn, bOut);
        verifIn.close();
        OpenPGPMessageInputStream.Result result = verifIn.getResult();
        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = result.getSignatures();
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature sig = signatures.get(0);
        isEquals(carolCert, sig.getIssuerCertificate());

        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
    }

    private void inlineSignWithV6Key()
            throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        OpenPGPKey v6Key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.V6_KEY);
        gen.addSigningKey(v6Key);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate v6Cert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.V6_CERT);
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addVerificationCertificate(v6Cert);

        OpenPGPMessageInputStream verifIn = processor.process(bIn);
        Streams.pipeAll(verifIn, bOut);
        verifIn.close();
        OpenPGPMessageInputStream.Result result = verifIn.getResult();
        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = result.getSignatures();
        isEquals(1, signatures.size());
        OpenPGPSignature.OpenPGPDocumentSignature sig = signatures.get(0);
        isEquals(v6Cert, sig.getIssuerCertificate());

        isEncodingEqual(PLAINTEXT, bOut.toByteArray());
    }

    private void verifyMessageByRevokedKey()
            throws PGPException, IOException
    {
        // Create a minimal signed message
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.ALICE_KEY);
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator();
        gen.addSigningKey(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream oOut = gen.open(bOut);
        oOut.write("Hello, World!\n".getBytes());
        oOut.close();

        // Load the certificate and import its revocation signature
        OpenPGPCertificate cert = OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT);
        cert = OpenPGPCertificate.join(cert, OpenPGPTestKeys.ALICE_REVOCATION_CERT);

        // Process the signed message using the revoked key
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addVerificationCertificate(cert);
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream oIn = processor.process(bIn);
        Streams.drain(oIn);
        oIn.close();

        OpenPGPMessageInputStream.Result result = oIn.getResult();
        OpenPGPSignature.OpenPGPDocumentSignature sig = result.getSignatures().get(0);
        // signature is no valid
        isFalse(sig.isValid());
    }

    private void incompleteMessageProcessing()
            throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .addEncryptionCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.ALICE_CERT))
                .addSigningKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.BOB_KEY));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream out = gen.open(bOut);

        out.write("Some Data".getBytes(StandardCharsets.UTF_8));
        out.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor()
                .addVerificationCertificate(OpenPGPCertificate.fromAsciiArmor(OpenPGPTestKeys.BOB_CERT))
                .addDecryptionKey(OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.ALICE_KEY));
        OpenPGPMessageInputStream in = processor.process(bIn);

        // read a single byte (not the entire message)
        in.read();

        in.close();
        OpenPGPMessageInputStream.Result result = in.getResult();
        OpenPGPSignature.OpenPGPDocumentSignature sig = result.getSignatures().get(0);
        isFalse(sig.isValid());
    }

    private void testVerificationOfSEIPD1MessageWithTamperedCiphertext()
            throws IOException, PGPException
    {
        String MSG = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQv/c0eFDZud8YCzKu0qzq7xOUeF0KiFFv58RSAookfyce9B\n" +
                "LSXH7g/F/3Pdp9EHcrtBsxYRXUdWmZHvwFRvAiwCl9unjUgRendopmuNJ5zNgB2w\n" +
                "DkuMA2J2J5HGTicvCwGrWALDG6Dc56UEFTwCsip8uKNG+Q3X5IwpU7Vztqywkt4/\n" +
                "RNp8+neu+oJELWn3mC3oZrMzYIaD2SlyVaW5Vpksjz32VGKXCm4/hGC/03tGuE1i\n" +
                "5sOZicHpeN24BD2tr3MMOdHKPXKxVPPx5T1MIJYUoYjMp7Tnml6F4Obhf+VllAli\n" +
                "mkQHj6vevbEkLcJX67pvD04PJiQqm5ea1GwOZDW/nPLih80AJWHpXME36WBzk4X2\n" +
                "bHaK3qQxyxqfpvMvWcargI3neWNLaSzqY/2eCrY/OEbAcj18W+9u7phkEoVRmrC7\n" +
                "mqIeEUXtGjWSywtJXF8tIcxOU3+IqekXLW9yFIzRrHWEzRVKzP2P5q7mwOp2ddjg\n" +
                "8vqe/DOz1r8VxN6orUue0kwBJVHfkYpW8cwX2AtIPYk90ct2qCTbCtNQul+txpRY\n" +
                "IwBVELjaaSGpdOuIHkETYssCNfqPSv0rNmaTDq78xItvhjuc4lRaKkpF9DdE\n" +
                "=I5BA\n" +
                "-----END PGP MESSAGE-----";
        OpenPGPKey key = OpenPGPKey.fromAsciiArmor(OpenPGPTestKeys.BOB_KEY);
        OpenPGPMessageProcessor processor = new OpenPGPMessageProcessor();
        processor.addDecryptionKey(key);
        OpenPGPMessageInputStream oIn = processor.process(new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8)));
        Streams.drain(oIn);
        oIn.close();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageProcessorTest());
    }
}
