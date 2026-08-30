package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test: a subkey MUST NOT inherit the primary key's Key Flags. RFC9580, section 5.2.3.29
 * makes Key Flags a statement about the key the carrying signature refers to, so a Subkey Binding
 * signature that omits the subpacket says nothing about the subkey's capabilities.
 * <p>
 * Inheriting SIGN_DATA from the primary made the two capability decisions for one subkey disagree:
 * the subkey counted as signing-capable (so its data signatures were attributed and reported valid),
 * while verifyEmbeddedPrimaryKeyBinding - which reads the binding signature's own flags - saw no
 * signing capability and skipped the embedded PrimaryKeyBinding signature required by RFC9580,
 * section 10.1.3. An attacker could therefore graft a third party's public signing subkey onto their
 * own certificate with a binding they can make (no key flags, and no back signature, which they
 * cannot make) and have that party's genuine signatures reported as valid under the attacker's identity.
 */
public class OpenPGPMissingCrossCertificationTest
    extends SimpleTest
{
    private static final byte[] PLAINTEXT = "I, the victim, agree to the terms.\n".getBytes();

    public String getName()
    {
        return "OpenPGPMissingCrossCertificationTest";
    }

    public void performTest()
        throws Exception
    {
        // Binding carries no Key Flags and no back signature - must not inherit the primary's SIGN_DATA.
        isTrue("subkey with no key flags on its binding must not inherit SIGN_DATA from the primary",
            !signatureAccepted(0, false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA));

        // Binding declares SIGN_DATA but carries no back signature - the existing check must still fire.
        isTrue("signing subkey without embedded PrimaryKeyBinding signature must not be usable",
            !signatureAccepted(KeyFlags.SIGN_DATA, false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA));

        // Compatibility: a properly cross-certified signing subkey must keep working.
        isTrue("properly cross-certified signing subkey must remain valid",
            signatureAccepted(KeyFlags.SIGN_DATA, true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA));

        testSigningSubkeyTakeover();
    }

    /**
     * Build a certificate whose subkey binding carries <pre>subFlags</pre> (omitted entirely when zero) and,
     * if <pre>backSig</pre> is set, an embedded PrimaryKeyBinding signature. Sign a message with the subkey
     * and report whether the high-level API accepts a signature issued by the subkey.
     */
    private boolean signatureAccepted(int subFlags, boolean backSig, int primaryFlags)
        throws Exception
    {
        Date creationTime = new Date((System.currentTimeMillis() / 1000L) * 1000L);

        PGPKeyRingGenerator gen = keyRingGenerator("Victim <victim@example.com>", primaryFlags, creationTime);

        PGPKeyPair sub = keyPair(PGPPublicKey.RSA_SIGN, creationTime);
        PGPSignatureSubpacketGenerator subSubpackets = new PGPSignatureSubpacketGenerator();
        if (subFlags != 0)
        {
            subSubpackets.setKeyFlags(true, subFlags);
        }
        gen.addSubKey(sub, subSubpackets.generate(), null, backSig ?
            new JcaPGPContentSignerBuilder(sub.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256) : null);

        PGPSecretKeyRing secretKeys = gen.generateSecretKeyRing();
        OpenPGPCertificate cert = certificate(gen.generatePublicKeyRing());

        OpenPGPApi api = new JcaOpenPGPApi(new BouncyCastleProvider());
        byte[] message;
        try
        {
            message = inlineSign(api, new OpenPGPKey(secretKeys));
        }
        catch (Exception e)
        {
            // No usable signing subkey at all - the subkey was rejected before it could sign.
            return false;
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = verify(api, cert, message);
        for (Iterator<OpenPGPSignature.OpenPGPDocumentSignature> it = signatures.iterator(); it.hasNext(); )
        {
            OpenPGPSignature.OpenPGPDocumentSignature sig = it.next();
            if (!sig.getIssuer().isPrimaryKey() && sig.isValid())
            {
                return true;
            }
        }
        return false;
    }

    /**
     * An attacker holding only the victim's <b>public</b> signing subkey binds it to their own primary key
     * with a Subkey Binding signature carrying no Key Flags and no embedded PrimaryKeyBinding signature
     * (which they cannot produce). A signature genuinely made by the victim must not verify as valid
     * against the attacker's certificate.
     */
    private void testSigningSubkeyTakeover()
        throws Exception
    {
        Date creationTime = new Date((System.currentTimeMillis() / 1000L) * 1000L);
        OpenPGPApi api = new JcaOpenPGPApi(new BouncyCastleProvider());

        // Victim: properly cross-certified signing subkey.
        PGPKeyRingGenerator victimGen = keyRingGenerator(
            "Victim <victim@example.com>", KeyFlags.CERTIFY_OTHER, creationTime);
        PGPKeyPair victimSub = keyPair(PGPPublicKey.RSA_SIGN, creationTime);
        PGPSignatureSubpacketGenerator victimSubSubpackets = new PGPSignatureSubpacketGenerator();
        victimSubSubpackets.setKeyFlags(true, KeyFlags.SIGN_DATA);
        victimGen.addSubKey(victimSub, victimSubSubpackets.generate(), null,
            new JcaPGPContentSignerBuilder(victimSub.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256));
        PGPPublicKeyRing victimRing = victimGen.generatePublicKeyRing();

        // Attacker: own primary key, built before the victim signs so the graft is effective at signing time.
        PGPKeyPair attackerPrimary = keyPair(PGPPublicKey.RSA_SIGN, creationTime);
        PGPPublicKeyRing attackerRing = keyRingGenerator(
            attackerPrimary, "Attacker <attacker@example.com>",
            KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, creationTime).generatePublicKeyRing();

        // Graft the victim's subkey: no key flags, no back signature (unmakeable), victim's bindings stripped.
        PGPPublicKey victimSubPub = stripSignatures(subkeyOf(victimRing));
        PGPSignatureGenerator bindGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(attackerPrimary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            attackerPrimary.getPublicKey());
        bindGen.init(PGPSignature.SUBKEY_BINDING, attackerPrimary.getPrivateKey());
        PGPSignature binding = bindGen.generateCertification(attackerRing.getPublicKey(), victimSubPub);

        PGPPublicKeyRing forgedRing = PGPPublicKeyRing.insertPublicKey(
            attackerRing, PGPPublicKey.addCertification(victimSubPub, binding));
        OpenPGPCertificate forgedCert = certificate(forgedRing);

        // The victim now signs a message with their own, properly bound signing subkey.
        byte[] message = inlineSign(api, new OpenPGPKey(victimGen.generateSecretKeyRing()));

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = verify(api, forgedCert, message);
        isTrue("test setup: the grafted subkey must resolve as the signature issuer",
            signatures.size() == 1 && !signatures.get(0).getIssuer().isPrimaryKey());
        isTrue("signature by a grafted subkey with no cross-certification must not be reported valid",
            !signatures.get(0).isValid());
    }

    private PGPKeyRingGenerator keyRingGenerator(String userId, int primaryFlags, Date creationTime)
        throws Exception
    {
        return keyRingGenerator(keyPair(PGPPublicKey.RSA_SIGN, creationTime), userId, primaryFlags, creationTime);
    }

    private PGPKeyRingGenerator keyRingGenerator(PGPKeyPair primary, String userId, int primaryFlags, Date creationTime)
        throws Exception
    {
        PGPDigestCalculator sha1 = new JcaPGPDigestCalculatorProviderBuilder()
            .build().get(HashAlgorithmTags.SHA1);

        PGPSignatureSubpacketGenerator primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(true, primaryFlags);

        return new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, userId,
            sha1, primarySubpackets.generate(), null,
            new JcaPGPContentSignerBuilder(primary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            null);
    }

    private PGPKeyPair keyPair(int algorithm, Date creationTime)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, algorithm, kpg.generateKeyPair(), creationTime);
    }

    private OpenPGPCertificate certificate(PGPPublicKeyRing ring)
        throws Exception
    {
        // re-parse from the wire, as a relying party would
        return new OpenPGPCertificate(new PGPPublicKeyRing(ring.getEncoded(), new JcaKeyFingerprintCalculator()));
    }

    private PGPPublicKey stripSignatures(PGPPublicKey key)
    {
        PGPPublicKey stripped = key;
        for (Iterator<PGPSignature> it = key.getSignatures(); it.hasNext(); )
        {
            stripped = PGPPublicKey.removeCertification(stripped, it.next());
        }
        return stripped;
    }

    private PGPPublicKey subkeyOf(PGPPublicKeyRing ring)
    {
        PGPPublicKey subkey = null;
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey key = it.next();
            if (!key.isMasterKey())
            {
                subkey = key;
            }
        }
        return subkey;
    }

    private byte[] inlineSign(OpenPGPApi api, OpenPGPKey key)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addSigningKey(key);
        OutputStream sOut = gen.open(bOut);
        sOut.write(PLAINTEXT);
        sOut.close();
        return bOut.toByteArray();
    }

    private List<OpenPGPSignature.OpenPGPDocumentSignature> verify(
        OpenPGPApi api, OpenPGPCertificate cert, byte[] message)
        throws Exception
    {
        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
            .addVerificationCertificate(cert);
        OpenPGPMessageInputStream in = processor.process(new ByteArrayInputStream(message));
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        Streams.pipeAll(in, plaintext);
        in.close();

        isTrue("message content must be recovered intact", areEqual(PLAINTEXT, plaintext.toByteArray()));

        return in.getResult().getSignatures();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenPGPMissingCrossCertificationTest());
    }
}
