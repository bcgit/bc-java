package org.bouncycastle.openpgp.api.test;

import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test: a third-party certification or trust delegation must only be honoured by
 * {@link OpenPGPCertificate} when the component key that actually issued it was granted the
 * authority to certify.
 * <p>
 * RFC 9580 Section 5.2.3.29 separates the certification flag ({@link KeyFlags#CERTIFY_OTHER})
 * from the data-signing flag ({@link KeyFlags#SIGN_DATA}), which is what lets a certificate keep
 * its certification primary key offline while a signing subkey is online. Accepting a
 * certification from a {@code SIGN_DATA}-only subkey would promote the online subkey to the
 * offline primary key's authority to bind identities and delegate introducer trust.
 * <p>
 * The certification-capable primary key and a subkey explicitly carrying {@code CERTIFY_OTHER}
 * must keep working - the check is on the granted capability, not on being the primary key.
 * See {@code OpenPGPCertificateComponent.mayHaveIssued}.
 */
public class OpenPGPThirdPartyCertificationAuthorityTest
    extends SimpleTest
{
    private static final String AUTHORITY_UID = "Offline Authority <authority@example.com>";
    private static final String SUBJECT_UID = "Subject <subject@example.com>";

    public String getName()
    {
        return "OpenPGPThirdPartyCertificationAuthorityTest";
    }

    public void performTest()
        throws Exception
    {
        Date now = new Date((System.currentTimeMillis() / 1000L) * 1000L);
        Date keyTime = new Date(now.getTime() - 3600L * 1000L);
        Date certificationTime = new Date(now.getTime() - 1800L * 1000L);

        BcOpenPGPApi api = new BcOpenPGPApi();

        // the classic profile is exactly the split this check protects: a CERTIFY_OTHER primary
        // key, a SIGN_DATA-only signing subkey and an encryption subkey
        OpenPGPKey authority = api.generateKey(PublicKeyPacket.VERSION_6, keyTime)
            .classicKey(AUTHORITY_UID).build();
        OpenPGPKey subject = api.generateKey(PublicKeyPacket.VERSION_6, keyTime)
            .classicKey(SUBJECT_UID).build();

        OpenPGPCertificate authorityCert = authority.toCertificate();
        PGPPublicKey subjectPrimary = subject.getPGPPublicKeyRing().getPublicKey();

        PGPKeyPair signOnly = signingSubkeyOf(authority, now);
        isTrue("signing subkey must carry SIGN_DATA",
            authority.getKey(signOnly.getKeyIdentifier()).isSigningKey(certificationTime));
        isTrue("signing subkey must not carry CERTIFY_OTHER",
            !authority.getKey(signOnly.getKeyIdentifier()).isCertificationKey(certificationTime));

        // a signing subkey's certification of a third party's user-id is not the authority's
        isTrue("SIGN_DATA-only subkey must not certify a third-party user-id",
            !certificationAccepted(subject, subjectPrimary, signOnly, authorityCert, certificationTime, now));

        // nor is its direct-key signature a delegation of the authority's introducer trust
        isTrue("SIGN_DATA-only subkey must not delegate trust",
            !delegationAccepted(subject, subjectPrimary, signOnly, authorityCert, certificationTime, now));

        // the compatibility assertion: the authority's own certification primary key still works
        PGPKeyPair primaryPair = authority.getPrimarySecretKey().unlock().getKeyPair();
        isTrue("certification primary key must still certify",
            certificationAccepted(subject, subjectPrimary, primaryPair, authorityCert, certificationTime, now));
        isTrue("certification primary key must still delegate trust",
            delegationAccepted(subject, subjectPrimary, primaryPair, authorityCert, certificationTime, now));

        // and the rule is the granted capability, not primary-key-only: a subkey explicitly bound
        // with CERTIFY_OTHER is an authority for both
        OpenPGPKey delegatingAuthority = keyWithCertifyingSubkey(api, keyTime);
        OpenPGPCertificate delegatingCert = delegatingAuthority.toCertificate();
        PGPKeyPair certifyingSubkey = certifyingSubkeyOf(delegatingAuthority, certificationTime);
        isTrue("certifying subkey must not be the primary key",
            certifyingSubkey.getKeyIdentifier() != null
                && !delegatingAuthority.getKey(certifyingSubkey.getKeyIdentifier()).isPrimaryKey());
        isTrue("CERTIFY_OTHER subkey must certify a third-party user-id",
            certificationAccepted(subject, subjectPrimary, certifyingSubkey, delegatingCert, certificationTime, now));
        isTrue("CERTIFY_OTHER subkey must delegate trust",
            delegationAccepted(subject, subjectPrimary, certifyingSubkey, delegatingCert, certificationTime, now));
    }

    /**
     * Certify the subject's user-id with the given issuer key pair and report whether the
     * certificate accepts the result as a certification by the given third-party certificate.
     */
    private boolean certificationAccepted(OpenPGPKey subject, PGPPublicKey subjectPrimary, PGPKeyPair issuer,
                                          OpenPGPCertificate thirdParty, Date creationTime, Date evaluationTime)
        throws Exception
    {
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(issuer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            issuer.getPublicKey());
        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, issuer.getPrivateKey());

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setIssuerFingerprint(true, issuer.getPublicKey());
        sigGen.setHashedSubpackets(hashed.generate());

        PGPSignature certification = sigGen.generateCertification(SUBJECT_UID, subjectPrimary);
        PGPPublicKeyRing ring = PGPPublicKeyRing.insertPublicKey(subject.getPGPPublicKeyRing(),
            PGPPublicKey.addCertification(subjectPrimary, SUBJECT_UID, certification));

        OpenPGPCertificate.OpenPGPSignatureChain chain = new OpenPGPCertificate(ring)
            .getUserId(SUBJECT_UID).getCertificationBy(thirdParty, evaluationTime);
        return chain != null && chain.isValid();
    }

    /**
     * Issue a full-trust, depth-one direct-key signature over the subject's primary key with the
     * given issuer key pair and report whether the certificate accepts it as a delegation.
     */
    private boolean delegationAccepted(OpenPGPKey subject, PGPPublicKey subjectPrimary, PGPKeyPair issuer,
                                       OpenPGPCertificate thirdParty, Date creationTime, Date evaluationTime)
        throws Exception
    {
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(issuer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            issuer.getPublicKey());
        sigGen.init(PGPSignature.DIRECT_KEY, issuer.getPrivateKey());

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, creationTime);
        hashed.setIssuerFingerprint(true, issuer.getPublicKey());
        hashed.setTrust(true, 1, 120);
        sigGen.setHashedSubpackets(hashed.generate());

        PGPSignature delegation = sigGen.generateCertification(subjectPrimary);
        PGPPublicKeyRing ring = PGPPublicKeyRing.insertPublicKey(subject.getPGPPublicKeyRing(),
            PGPPublicKey.addCertification(subjectPrimary, delegation));

        OpenPGPCertificate.OpenPGPSignatureChain chain = new OpenPGPCertificate(ring)
            .getDelegationBy(thirdParty, evaluationTime);
        return chain != null && chain.isValid();
    }

    /**
     * Build a key whose signing subkey is bound with CERTIFY_OTHER in place of SIGN_DATA, so that
     * the binding still carries the required primary-key back-signature.
     */
    private OpenPGPKey keyWithCertifyingSubkey(BcOpenPGPApi api, Date keyTime)
        throws PGPException
    {
        return api.generateKey(PublicKeyPacket.VERSION_6, keyTime)
            .withPrimaryKey()
            .addUserId(AUTHORITY_UID)
            .addSigningSubkey(
                KeyPairGeneratorCallback.Util.signingKey(),
                SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                {
                    public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                    {
                        subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                        subpackets.setKeyFlags(KeyFlags.CERTIFY_OTHER);
                        return subpackets;
                    }
                }),
                null)
            .build();
    }

    private PGPKeyPair signingSubkeyOf(OpenPGPKey key, Date evaluationTime)
        throws Exception
    {
        return subkeyOf(key, evaluationTime, false);
    }

    private PGPKeyPair certifyingSubkeyOf(OpenPGPKey key, Date evaluationTime)
        throws Exception
    {
        return subkeyOf(key, evaluationTime, true);
    }

    private PGPKeyPair subkeyOf(OpenPGPKey key, Date evaluationTime, boolean certifying)
        throws Exception
    {
        for (Iterator<OpenPGPKey.OpenPGPSecretKey> it = key.getSecretKeys().values().iterator(); it.hasNext(); )
        {
            OpenPGPKey.OpenPGPSecretKey candidate = it.next();
            if (candidate.isPrimaryKey())
            {
                continue;
            }
            if (certifying ? candidate.isCertificationKey(evaluationTime)
                : (candidate.isSigningKey(evaluationTime) && !candidate.isCertificationKey(evaluationTime)))
            {
                return candidate.unlock().getKeyPair();
            }
        }
        fail("key does not carry the expected " + (certifying ? "certifying" : "signing-only") + " subkey");
        return null;
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPThirdPartyCertificationAuthorityTest());
    }
}
