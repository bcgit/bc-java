package org.bouncycastle.cert.plants.examples;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.plants.MTCCertAuth;
import org.bouncycastle.cert.plants.MTCContentSigner;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.bc.BcMTCCosigner;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.bc.BcMTCSignatureVerifier;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;

/**
 * End-to-end Merkle Tree Certificate walkthrough using a single CA cosigner.
 *
 * <p>The example builds an in-memory issuance log holding two entries, issues
 * a <em>standalone certificate</em> (Section 6.2 of the draft) for entry
 * index 0 over the subtree {@code [0, 2)}, then has a relying party validate
 * it through {@link MerkleTreeCertificateValidator}. The whole flow is exercised against
 * the lightweight bindings in {@code org.bouncycastle.cert.plants.bc} so no
 * JCA provider needs to be registered.</p>
 *
 * <p>The walkthrough is illustrative — production callers should rotate
 * checkpoints, fetch landmark sequences and use multiple cosigners as
 * described in Section 7.3 of the draft. Here we use a single CA cosigner
 * with {@code minCosignatures = 1} for clarity.</p>
 */
public class MerkleTreeCertificateExample
{
    /** Trust anchor ID assigned to our example CA. */
    private static final String CA_TRUST_ANCHOR_ID = "32473.1";

    /** Log number used in the cert's 64-bit serial (top 16 bits). */
    private static final long LOG_NUMBER = 1L;

    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // 1. CA keypair and identity bundle. MTCCertAuth carries the CA's
        //    trust anchor ID plus its hash + cosigner-signature algorithm
        //    OIDs, so the same object serves both the issuer side (issuer
        //    name, serial, log ID derivation) and the relying-party side
        //    (the MTCCertificationAuthority value the validator needs).
        AsymmetricCipherKeyPair caKp = generateEd25519KeyPair(random);
        MTCCertAuth ca = new MTCCertAuth(
            CA_TRUST_ANCHOR_ID,
            new BcSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MerkleTreeHash hashFunc = ca.getHashFunc();
        System.out.println("CA trust anchor ID:    " + ca.getDottedCaId());
        System.out.println("Issuance log ID:       " + TrustAnchorIDs.toDottedDecimal(ca.logId(LOG_NUMBER)));

        // 2. End-entity keypair.
        AsymmetricCipherKeyPair eeKp = generateEd25519KeyPair(random);
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());

        // 3. Issue the EE certificate. The cert's issuer carries the CA's
        //    trust anchor ID; the validator recovers the issuance log ID by
        //    appending the log_number from the serial. The result is a
        //    standalone certificate (Section 6.2 of the draft) over the
        //    minimal subtree [0, 2): the EE's entry at index 0 with a
        //    sibling leaf at index 1.
        //
        //    MTCContentSigner captures the TBSCertificate bytes streamed by
        //    the X509v3CertificateBuilder, derives the MerkleTreeCertEntry
        //    leaf hash, asks the CA cosigner to sign the subtree, and emits
        //    the encoded MTCProof as the cert's signatureValue.
        byte[] siblingHash = hashFunc.hashLeaf("sibling-leaf-1".getBytes());
        MTCLog log = new MTCLog(ca, LOG_NUMBER, /*start=*/ 0L, /*end=*/ 2L);
        ContentSigner mtcSigner = new MTCContentSigner(
            log, siblingHash,
            new BcMTCCosigner(ca.getCaId(), caKp.getPrivate()));

        X509CertificateHolder cert = buildEECert(
            ca.issuerName(),
            ca.certSerial(log, /*index=*/ 0L),
            eeSpki,
            mtcSigner);

        System.out.println("Cert encoded length:   " + cert.getEncoded().length + " bytes");

        // 4. Relying-party side: build a cosigner verifier provider that maps
        //    the CA's trust anchor ID to the CA's public key + Ed25519
        //    algorithm, then assemble ValidationParams and validate.
        BcMTCSignatureVerifier caVerifier = new BcMTCSignatureVerifier(
            MTCSignatureAlgorithm.ED25519, caKp.getPublic());
        BcMTCCosignerVerifierProvider cosigners =
            BcMTCCosignerVerifierProvider.singleCosigner(ca.getCaId(), caVerifier);

        // Lift the MTCCertificationAuthority info from our identity bundle —
        // in production the relying party would parse it out of the CA
        // certificate's id-pe-mtcCertificationAuthority extension.
        MTCCertificationAuthority authority = ca.authorityInfo(BigInteger.ZERO);

        MerkleTreeCertificateValidator.ValidationParams params =
            new MerkleTreeCertificateValidator.ValidationParams(
                cosigners, hashFunc, /*minCosignatures=*/ 1, authority);

        boolean valid = MerkleTreeCertificateValidator.validateCertificate(cert, params);
        System.out.println("Validation result:     " + (valid ? "PASS" : "FAIL"));
    }

    // --- Builders -----------------------------------------------------------

    private static AsymmetricCipherKeyPair generateEd25519KeyPair(SecureRandom random)
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(random));
        return gen.generateKeyPair();
    }

    /**
     * Builds an EE certificate via {@link X509v3CertificateBuilder} with a
     * critical BasicConstraints(cA=false) extension. The supplied
     * {@link ContentSigner} provides the cert's signatureAlgorithm via
     * {@link ContentSigner#getAlgorithmIdentifier()} and is responsible for
     * producing the bytes that land in signatureValue — for an MTC cert that
     * means encoding an {@code MTCProof} computed over the TBSCertificate the
     * builder streams into {@link ContentSigner#getOutputStream()}.
     */
    private static X509CertificateHolder buildEECert(
        X500Name issuer, BigInteger serial,
        SubjectPublicKeyInfo spki,
        ContentSigner signer)
        throws CertIOException
    {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            issuer, serial,
            new Date(now), new Date(now + 24L * 60 * 60 * 1000),
            new X500Name("CN=mtc-example-ee"), spki);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        return builder.build(signer);
    }

}
