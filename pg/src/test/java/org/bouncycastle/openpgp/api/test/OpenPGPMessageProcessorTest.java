package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPEncryptionNegotiator;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyMaterialProvider;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class OpenPGPMessageProcessorTest
    extends APITest
{
    private static final byte[] PLAINTEXT = Strings.toUTF8ByteArray("Hello, World!\n");

    private PGPSessionKey encryptionSessionKey;

    @Override
    public String getName()
    {
        return "OpenPGPMessageProcessorTest";
    }

    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        String javaVersion = System.getProperty("java.version");
        boolean oldJDK = javaVersion.startsWith("1.5") || javaVersion.startsWith("1.6");

        testVerificationOfSEIPD1MessageWithTamperedCiphertext(api);

        roundtripUnarmoredPlaintextMessage(api);
        roundtripArmoredPlaintextMessage(api);
        roundTripCompressedMessage(api);
        roundTripCompressedSymEncMessageMessage(api);

        roundTripSymEncMessageWithMultiplePassphrases(api);

        roundTripV4KeyEncryptedMessageAlice(api);
        roundTripV4KeyEncryptedMessageBob(api);

        roundTripV6KeyEncryptedMessage(api);
        encryptWithV4V6KeyDecryptWithV4(api);
        encryptWithV4V6KeyDecryptWithV6(api);

        if (!oldJDK)
        {
            encryptDecryptWithLockedKey(api);
            encryptDecryptWithMissingKey(api);
        }
        
        inlineSignWithV4KeyAlice(api);
        inlineSignWithV4KeyBob(api);
        inlineSignWithV6Key(api);

        verifyMessageByRevokedKey(api);
        incompleteMessageProcessing(api);
    }

    private void roundtripUnarmoredPlaintextMessage(OpenPGPApi api)
        throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(false)
            .setAllowPadding(false)
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.UNCOMPRESSED;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        OpenPGPMessageInputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        isEquals(MessageEncryptionMechanism.unencrypted(), plainIn.getResult().getEncryptionMethod());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundtripArmoredPlaintextMessage(OpenPGPApi api)
        throws PGPException, IOException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(true)
            .setAllowPadding(false)
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.UNCOMPRESSED;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        OpenPGPMessageInputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        OpenPGPMessageInputStream.Result result = plainIn.getResult();
        isEquals(MessageEncryptionMechanism.unencrypted(), result.getEncryptionMethod());

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(true)
            .setAllowPadding(false)
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.ZIP;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        InputStream plainIn = processor.process(bIn);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();

        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
    }

    private void roundTripCompressedSymEncMessageMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(true)
            .addEncryptionPassphrase("lal".toCharArray())
            .setSessionKeyExtractionCallback(new PGPEncryptedDataGenerator.SessionKeyExtractionCallback()
            {
                public void extractSessionKey(PGPSessionKey sessionKey)
                {
                    OpenPGPMessageProcessorTest.this.encryptionSessionKey = sessionKey;
                }
            })
            .setAllowPadding(false)
            .setPasswordBasedEncryptionNegotiator(new OpenPGPEncryptionNegotiator()
            {
                @Override
                public MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration)
                {
                    return MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256);
                }
            })
            .setCompressionNegotiator(new OpenPGPMessageGenerator.CompressionNegotiator()
            {
                public int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy)
                {
                    return CompressionAlgorithmTags.ZIP;
                }
            });

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();
        isNotNull(encryptionSessionKey);

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageInputStream plainIn = api.decryptAndOrVerifyMessage()
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

    private void roundTripSymEncMessageWithMultiplePassphrases(OpenPGPApi api)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .addEncryptionPassphrase("orange".toCharArray())
            .addEncryptionPassphrase("violet".toCharArray())
            .setSessionKeyExtractionCallback(new PGPEncryptedDataGenerator.SessionKeyExtractionCallback()
            {
                public void extractSessionKey(PGPSessionKey sessionKey)
                {
                    OpenPGPMessageProcessorTest.this.encryptionSessionKey = sessionKey;
                }
            })
            .setPasswordBasedEncryptionNegotiator(
                new OpenPGPEncryptionNegotiator()
                {
                    @Override
                    public MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration)
                    {
                        return MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB);
                    }
                }
            );

        OutputStream encOut = gen.open(bOut);
        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();

        // Try decryption with explicitly set message passphrase
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
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
        processor = api.decryptAndOrVerifyMessage();
        decIn = processor.setMissingMessagePassphraseCallback(new StackMessagePassphraseCallback("orange".toCharArray()))
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

    private void roundTripV4KeyEncryptedMessageAlice(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        processor.addDecryptionKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
            result.getEncryptionMethod());
    }

    private void roundTripV4KeyEncryptedMessageBob(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.BOB_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        processor.addDecryptionKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
            result.getEncryptionMethod());
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
    }

    private void roundTripV6KeyEncryptedMessage(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(true)
            .addEncryptionCertificate(key)
            .setAllowPadding(false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
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

    private void encryptWithV4V6KeyDecryptWithV4(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT));
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.V6_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
            .addDecryptionKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
            result.getEncryptionMethod());
    }

    private void encryptWithV4V6KeyDecryptWithV6(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT));
        gen.addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.V6_CERT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream enc = gen.open(bOut);
        enc.write(PLAINTEXT);
        enc.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
            .addDecryptionKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY));

        OpenPGPMessageInputStream decIn = processor.process(bIn);

        bOut = new ByteArrayOutputStream();
        Streams.pipeAll(decIn, bOut);
        isEncodingEqual(bOut.toByteArray(), PLAINTEXT);
        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256),
            result.getEncryptionMethod());
    }

    private void encryptDecryptWithLockedKey(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY_LOCKED);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OpenPGPMessageOutputStream encOut = api.signAndOrEncryptMessage()
            .addEncryptionCertificate(key)
            .open(bOut);

        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();

        // Provide passphrase and key together
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        OpenPGPMessageInputStream decIn = api.decryptAndOrVerifyMessage()
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
        decIn = api.decryptAndOrVerifyMessage()
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
        decIn = api.decryptAndOrVerifyMessage()
            .addDecryptionKey(key)
            .setMissingOpenPGPKeyPassphraseProvider(new KeyPassphraseProvider()
            {
                public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
                {
                    return OpenPGPTestKeys.V6_KEY_LOCKED_PASSPHRASE.toCharArray();
                }
            })
            .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());

        result = decIn.getResult();
        isEncodingEqual(sk.getKey(), result.getSessionKey().getKey());
    }

    private void encryptDecryptWithMissingKey(OpenPGPApi api)
        throws IOException, PGPException
    {
        final OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream encOut = api.signAndOrEncryptMessage()
            .addEncryptionCertificate(key)
            .open(bOut);

        encOut.write(PLAINTEXT);
        encOut.close();

        byte[] ciphertext = bOut.toByteArray();

        // Provide passphrase and key together
        ByteArrayInputStream bIn = new ByteArrayInputStream(ciphertext);
        bOut = new ByteArrayOutputStream();
        OpenPGPMessageInputStream decIn = api.decryptAndOrVerifyMessage()
            .setMissingOpenPGPKeyProvider(new OpenPGPKeyMaterialProvider.OpenPGPKeyProvider()
            {
                public OpenPGPKey provide(KeyIdentifier componentKeyIdentifier)
                {
                    return key;
                }
            })
            .process(bIn);
        Streams.pipeAll(decIn, bOut);
        decIn.close();
        isEncodingEqual(PLAINTEXT, bOut.toByteArray());

        OpenPGPMessageInputStream.Result result = decIn.getResult();
        isEquals(key, result.getDecryptionKey().getCertificate());
        isNotNull(result.getSessionKey());
    }

    private void inlineSignWithV4KeyAlice(OpenPGPApi api)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        OpenPGPKey aliceKey = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);
        gen.addSigningKey(aliceKey);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate aliceCert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
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

    private void inlineSignWithV4KeyBob(OpenPGPApi api)
        throws IOException, PGPException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        OpenPGPKey bobKey = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY);
        gen.addSigningKey(bobKey);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate bobCert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.BOB_CERT);
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
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

    private void inlineSignWithV6Key(OpenPGPApi api)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        OpenPGPKey v6Key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.V6_KEY);
        gen.addSigningKey(v6Key);

        OutputStream signOut = gen.open(bOut);
        signOut.write(PLAINTEXT);
        signOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        bOut = new ByteArrayOutputStream();

        OpenPGPCertificate v6Cert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.V6_CERT);
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
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

    private void verifyMessageByRevokedKey(OpenPGPApi api)
        throws PGPException, IOException
    {
        // Create a minimal signed message
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addSigningKey(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream oOut = gen.open(bOut);
        oOut.write("Hello, World!\n".getBytes());
        oOut.close();

        // Load the certificate and import its revocation signature
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);
        cert = OpenPGPCertificate.join(cert, OpenPGPTestKeys.ALICE_REVOCATION_CERT);

        // Process the signed message using the revoked key
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
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

    private void incompleteMessageProcessing(OpenPGPApi api)
        throws IOException, PGPException
    {
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .addEncryptionCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT))
            .addSigningKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream out = gen.open(bOut);

        out.write(Strings.toUTF8ByteArray("Some Data"));
        out.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
            .addVerificationCertificate(api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.BOB_CERT))
            .addDecryptionKey(api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY));
        OpenPGPMessageInputStream in = processor.process(bIn);

        // read a single byte (not the entire message)
        in.read();

        in.close();
        OpenPGPMessageInputStream.Result result = in.getResult();
        OpenPGPSignature.OpenPGPDocumentSignature sig = result.getSignatures().get(0);
        isFalse(sig.isValid());
    }

    private void testVerificationOfSEIPD1MessageWithTamperedCiphertext(OpenPGPApi api)
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
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY);
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        processor.addDecryptionKey(key);
        OpenPGPMessageInputStream oIn = processor.process(new ByteArrayInputStream(Strings.toUTF8ByteArray(MSG)));
        Streams.drain(oIn);
        try
        {
            oIn.close();
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPMessageProcessorTest());
    }
}
