package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.api.util.UTCUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class ComponentSignatureEvaluatorTest
        extends APITest {

    @Override
    public String getName()
    {
        return "ComponentSignatureEvaluatorTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws IOException, PGPException
    {
        testHistoricSignatureEvaluationWithCleanedCertificate(api);
        testSignatureEvaluationFailsForSignaturePredatingSigningKey(api);
    }

    private void testHistoricSignatureEvaluationWithCleanedCertificate(OpenPGPApi api)
            throws PGPException, IOException {
        Date t0 = UTCUtil.parse("2024-01-01 00:00:00 UTC");
        Date t1 = UTCUtil.parse("2024-01-02 00:00:00 UTC");
        Date t2 = UTCUtil.parse("2024-01-03 00:00:00 UTC");

        String userId = "Alice <alice@example.org>";
        // Create key at t0
        OpenPGPKey initialKey = api.generateKey(4, t0)
                .withPrimaryKey()
                .addSigningSubkey()
                .addUserId(userId)
                .build();
        OpenPGPCertificate initialCert = initialKey.toCertificate();

        // Generate message at t1
        OpenPGPMessageGenerator mGen = api.signAndOrEncryptMessage()
                .addSigningKey(initialKey, new SignatureParameters.Callback() {
                    @Override
                    public SignatureParameters apply(SignatureParameters parameters) {
                        return parameters.setSignatureCreationTime(t1);
                    }
                });
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = mGen.open(bOut);
        mOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        mOut.close();
        byte[] historicMessage = bOut.toByteArray();
        System.out.println(bOut.toString());

        // Message is valid with initial certificate
        ByteArrayInputStream bIn = new ByteArrayInputStream(historicMessage);
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(initialCert)
                .process(bIn);
        org.bouncycastle.util.io.Streams.drain(mIn);
        mIn.close();
        isTrue(mIn.getResult().getSignatures().get(0).isValid());

        // Create new key signatures at t2 and strip t0 signatures
        List<PGPPublicKey> strippedKeys = new ArrayList<>();
        for (PGPPublicKey k : initialCert.getPGPPublicKeyRing())
        {
            PGPPublicKey cleaned = PGPPublicKey.removeCertification(k, userId);
            if (cleaned == null)
            {
                cleaned = k;
            }
            Iterator<PGPSignature> sigs = cleaned.getSignatures();
            while (sigs.hasNext()) {
                PGPSignature sig = sigs.next();
                cleaned = PGPPublicKey.removeCertification(cleaned, sig);
            }
            strippedKeys.add(cleaned);
        }
        System.out.println(new OpenPGPCertificate(new PGPPublicKeyRing(strippedKeys)).toAsciiArmoredString());

        List<PGPPublicKey> updateKeys = new ArrayList<>();
        PGPKeyPair primaryKey = initialKey.getPrimarySecretKey().unlock().getKeyPair();
        Iterator<PGPPublicKey> strippedIterator = strippedKeys.iterator();
        PGPPublicKey updatedPrimaryKey = strippedIterator.next();

        // Reissue direct-key sig at t2
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                api.getImplementation().pgpContentSignerBuilder(
                        primaryKey.getPublicKey().getAlgorithm(),
                        org.bouncycastle.bcpg.HashAlgorithmTags.SHA3_512),
                primaryKey.getPublicKey());
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setIssuerFingerprint(true, primaryKey.getPublicKey());
        spGen.setSignatureCreationTime(true, t2);
        spGen.setKeyFlags(KeyFlags.CERTIFY_OTHER);
        sGen.setHashedSubpackets(spGen.generate());
        sGen.init(PGPSignature.DIRECT_KEY, primaryKey.getPrivateKey());
        updatedPrimaryKey = PGPPublicKey.addCertification(
                updatedPrimaryKey,
                sGen.generateCertification(updatedPrimaryKey));

        // reissue userid sig at t2
        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, primaryKey.getPrivateKey());
        updatedPrimaryKey = PGPPublicKey.addCertification(
                updatedPrimaryKey,
                userId,
                sGen.generateCertification(userId, updatedPrimaryKey));

        updateKeys.add(updatedPrimaryKey);

        // reissue signature subkey binding at t2
        PGPPublicKey signingKey = strippedIterator.next();
        PGPPrivateKey privateSigningKey = initialKey.getSecretKey(signingKey.getKeyIdentifier())
                .unlock().getKeyPair().getPrivateKey();

        PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                api.getImplementation().pgpContentSignerBuilder(signingKey.getAlgorithm(), org.bouncycastle.bcpg.HashAlgorithmTags.SHA3_512),
                signingKey);
        PGPSignatureSubpacketGenerator backSigSubPacketGen = new PGPSignatureSubpacketGenerator();
        backSigSubPacketGen.setSignatureCreationTime(t2);
        backSigSubPacketGen.setIssuerFingerprint(true, signingKey);
        backSigGen.setHashedSubpackets(backSigSubPacketGen.generate());
        backSigGen.init(PGPSignature.PRIMARYKEY_BINDING, privateSigningKey);
        PGPSignature backSig = backSigGen.generateCertification(updatedPrimaryKey, signingKey);

        spGen = new PGPSignatureSubpacketGenerator();
        spGen.setIssuerFingerprint(true, updatedPrimaryKey);
        spGen.setSignatureCreationTime(true, t2);
        spGen.setKeyFlags(KeyFlags.SIGN_DATA);
        spGen.addEmbeddedSignature(true, backSig);
        sGen.setHashedSubpackets(spGen.generate());
        sGen.init(PGPSignature.SUBKEY_BINDING, primaryKey.getPrivateKey());

        signingKey = PGPPublicKey.addCertification(signingKey, sGen.generateCertification(updatedPrimaryKey, signingKey));
        updateKeys.add(signingKey);

        // Reassemble update key
        PGPPublicKeyRing updatedKeyRing = new PGPPublicKeyRing(updateKeys);

        // Check that with complete history evaluation, historic signature is now no longer valid
        OpenPGPDefaultPolicy fullHistoryEvaluation = new OpenPGPDefaultPolicy()
                .applyStrictTemporalComponentSignatureValidityConstraints();
        OpenPGPCertificate updatedCert = new OpenPGPCertificate(
                updatedKeyRing, api.getImplementation(), fullHistoryEvaluation);
        isFalse("With full history eval, primary key MUST NOT be bound at t1",
                updatedCert.getPrimaryKey().isBoundAt(t1));
        isFalse("With full history eval, signing key MUST NOT be bound at t1",
                updatedCert.getSigningKeys().get(0).isBoundAt(t1));

        mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(updatedCert)
                .process(new ByteArrayInputStream(historicMessage));
        org.bouncycastle.util.io.Streams.drain(mIn);
        mIn.close();
        isFalse("With full history eval, historic message MUST NOT be validly signed by updated key",
                mIn.getResult().getSignatures().get(0).isValid());

        // Check that with simplified history evaluation, historic signatures remain valid
        OpenPGPDefaultPolicy simplifiedHistoryEvaluation = new OpenPGPDefaultPolicy()
                .allowRetroactiveComponentSignatureValidation();
        updatedCert = new OpenPGPCertificate(
                updatedKeyRing, api.getImplementation(), simplifiedHistoryEvaluation);
        isTrue("With simplified history eval, primary key MUST be bound at t1",
                updatedCert.getPrimaryKey()
                        .isBoundAt(t1));
        isTrue("With simplified history eval, signing key MUST be bound at t1",
                updatedCert.getSigningKeys().get(0).isBoundAt(t1));

        mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(updatedCert)
                .process(new ByteArrayInputStream(historicMessage));
        org.bouncycastle.util.io.Streams.drain(mIn);
        mIn.close();
        isTrue("With simplified history eval, historic message MUST be validly signed by updated key",
                mIn.getResult().getSignatures().get(0).isValid());
    }

    private void testSignatureEvaluationFailsForSignaturePredatingSigningKey(OpenPGPApi api)
            throws PGPException, IOException {
        Date t0 = UTCUtil.parse("2024-01-01 00:00:00 UTC");
        Date t1 = UTCUtil.parse("2024-01-02 00:00:00 UTC");
        Date t2 = UTCUtil.parse("2024-01-03 00:00:00 UTC");

        // Create key with only primary key at t0
        OpenPGPKey initialKey = api.generateKey(4, t0)
                .withPrimaryKey()
                .build();
        // Add signing subkey at t2
        PGPKeyPair kp = api.getImplementation().pgpKeyPairGeneratorProvider().get(4, t2)
                .generateSigningSubkey();
        initialKey = api.editKey(initialKey)
                .addSigningSubkey(
                        kp,
                        new SignatureParameters.Callback() {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters) {
                                parameters.setHashedSubpacketsFunction(new SignatureSubpacketsFunction() {
                                    @Override
                                    public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets) {
                                        subpackets.setKeyFlags(KeyFlags.SIGN_DATA);
                                        return subpackets;
                                    }
                                });
                                return parameters.setSignatureCreationTime(t2);
                            }
                        },
                        new SignatureParameters.Callback() {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters) {
                                return parameters.setSignatureCreationTime(t2);
                            }
                        })
                .done();
        OpenPGPCertificate initialCert = initialKey.toCertificate();
        System.out.println(initialCert.toAsciiArmoredString());

        // Generate message at t1
        OpenPGPMessageGenerator mGen = api.signAndOrEncryptMessage()
                .addSigningKey(initialKey, new SignatureParameters.Callback() {
                    @Override
                    public SignatureParameters apply(SignatureParameters parameters) {
                        return parameters.setSignatureCreationTime(t1);
                    }
                });
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = mGen.open(bOut);
        mOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        mOut.close();
        byte[] historicMessage = bOut.toByteArray();
        System.out.println(bOut.toString());

        // Message is invalid with strict temporal constraints
        OpenPGPDefaultPolicy policy = new OpenPGPDefaultPolicy()
                .applyStrictTemporalComponentSignatureValidityConstraints();
        ByteArrayInputStream bIn = new ByteArrayInputStream(historicMessage);
        OpenPGPMessageInputStream mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(new OpenPGPCertificate(initialCert.getPGPKeyRing(), api.getImplementation(), policy))
                .process(bIn);
        org.bouncycastle.util.io.Streams.drain(mIn);
        mIn.close();
        isFalse(mIn.getResult().getSignatures().get(0).isValid());

        // Message is invalid with relaxed policy allowing retroactive revalidation
        policy = new OpenPGPDefaultPolicy()
                .allowRetroactiveComponentSignatureValidation();
        bIn = new ByteArrayInputStream(historicMessage);
        mIn = api.decryptAndOrVerifyMessage()
                .addVerificationCertificate(new OpenPGPCertificate(initialCert.getPGPKeyRing(), api.getImplementation(), policy))
                .process(bIn);
        org.bouncycastle.util.io.Streams.drain(mIn);
        mIn.close();
        isFalse(mIn.getResult().getSignatures().get(0).isValid());
    }

    public static void main(String[] args)
    {
        runTest(new ComponentSignatureEvaluatorTest());
    }
}
