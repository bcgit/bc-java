package org.bouncycastle.cert.plants.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
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
import org.bouncycastle.cert.plants.MerkleTreeCertificateValidator;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.TrustAnchorIDs;
import org.bouncycastle.cert.plants.jcajce.JcaMTCCosigner;
import org.bouncycastle.cert.plants.jcajce.JcaMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.jcajce.JcaSha256MerkleTreeHash;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;

/**
 * End-to-end Merkle Tree Certificate walkthrough using a single CA cosigner —
 * JCA-backed counterpart of {@link MerkleTreeCertificateExample}. The flow is
 * identical; only the building blocks change. Hash, cosigner and cosigner
 * verifier come from {@code org.bouncycastle.cert.plants.jcajce} and are
 * driven through {@link java.security.Signature} / {@link java.security.KeyPair}
 * etc. via {@link BouncyCastleProvider}.
 *
 * <p>The walkthrough is illustrative — production callers should rotate
 * checkpoints, fetch landmark sequences and use multiple cosigners as
 * described in Section 7.3 of the draft. Here we use a single CA cosigner
 * with {@code minCosignatures = 1} for clarity.</p>
 */
public class MerkleTreeCertificateJcaExample
{
    /** Trust anchor ID assigned to our example CA. */
    private static final String CA_TRUST_ANCHOR_ID = "32473.1";

    /** Log number used in the cert's 64-bit serial (top 16 bits). */
    private static final long LOG_NUMBER = 1L;

    /** Provider name used for all JCA lookups in this example. */
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. CA keypair and identity bundle. MTCCertAuth carries the CA's
        //    trust anchor ID plus its hash + cosigner-signature algorithm
        //    OIDs, so the same object serves both the issuer side (issuer
        //    name, serial, log ID derivation) and the relying-party side
        //    (the MTCCertificationAuthority value the validator needs).
        KeyPair caKp = generateEd25519KeyPair();
        MTCCertAuth ca = new MTCCertAuth(
            CA_TRUST_ANCHOR_ID,
            new JcaSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MerkleTreeHash hashFunc = ca.getHashFunc();
        System.out.println("CA trust anchor ID:    " + ca.getDottedCaId());
        System.out.println("Issuance log ID:       " + TrustAnchorIDs.toDottedDecimal(ca.logId(LOG_NUMBER)));

        // 2. End-entity keypair. A JCA PublicKey already encodes as a DER
        //    SubjectPublicKeyInfo, so SubjectPublicKeyInfo.getInstance(...)
        //    on its encoding gives us what the X509v3CertificateBuilder wants.
        KeyPair eeKp = generateEd25519KeyPair();
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded());

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
            new JcaMTCCosigner.Builder()
                .setProvider(PROVIDER)
                .build(ca.getCaId(), caKp.getPrivate()));

        X509CertificateHolder cert = buildEECert(
            ca.issuerName(),
            ca.certSerial(log, /*index=*/ 0L),
            eeSpki,
            mtcSigner);

        System.out.println("Cert encoded length:   " + cert.getEncoded().length + " bytes");

        // 4. Relying-party side: build a cosigner verifier provider that maps
        //    the CA's trust anchor ID to the CA's public key + Ed25519
        //    algorithm, then assemble ValidationParams and validate.
        JcaMTCCosignerVerifierProvider cosigners = new JcaMTCCosignerVerifierProvider.Builder()
            .setProvider(PROVIDER)
            .addCosigner(ca.getCaId(), caKp.getPublic())
            .build();

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

    private static KeyPair generateEd25519KeyPair()
        throws Exception
    {
        return KeyPairGenerator.getInstance("Ed25519", PROVIDER).generateKeyPair();
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
