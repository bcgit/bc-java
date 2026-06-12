package org.bouncycastle.cert.plants.examples;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.plants.MTCCertAuth;
import org.bouncycastle.cert.plants.MTCContentSigner;
import org.bouncycastle.cert.plants.MTCCosignerVerifier;
import org.bouncycastle.cert.plants.MTCLog;
import org.bouncycastle.cert.plants.MTCSignatureVerifierProvider;
import org.bouncycastle.cert.plants.MerkleTreeHash;
import org.bouncycastle.cert.plants.bc.BcMTCCosigner;
import org.bouncycastle.cert.plants.bc.BcMTCCosignerVerifierProvider;
import org.bouncycastle.cert.plants.bc.BcSha256MerkleTreeHash;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;

/**
 * Verifies a single Merkle Tree certificate against a single trusted cosigner
 * via the standard
 * {@link X509CertificateHolder#isSignatureValid(ContentVerifierProvider)}
 * entry point, with {@link MTCSignatureVerifierProvider} as the adapter that
 * translates the X.509 verification flow into an MTC subtree-hash recovery
 * plus cosignature check.
 *
 * <p>The example issues a standalone MTC certificate (Section 6.2 of the
 * draft) in-memory over the minimal subtree {@code [0, 2)} (so it is
 * self-contained) and then validates it with a single call to
 * {@code cert.isSignatureValid(provider)}. {@link MTCSignatureVerifierProvider}
 * captures the TBSCertificate streamed by the holder, parses the
 * {@code MTCProof} from the supplied signature value, climbs one Merkle level
 * with the inclusion proof to recover the subtree hash, encodes the
 * {@code CosignedMessage}, and verifies the cosignature against the wrapped
 * {@link MTCCosignerVerifier}.</p>
 *
 * <p>{@link org.bouncycastle.cert.plants.MerkleTreeCertificateValidator#validateCertificate}
 * remains the full policy-driven entry point (revocation, trusted subtrees,
 * {@code minCosignatures > 1}); this example is the simplest path for the
 * single-cosigner case where the relying party just wants
 * {@code cert.isSignatureValid(...)} to work.</p>
 */
public class MTCSingleCertVerifyExample
{
    private static final String CA_TRUST_ANCHOR_ID = "32473.1";
    private static final long LOG_NUMBER = 1L;

    public static void main(String[] args)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        // --- Issuer side ----------------------------------------------------
        // Build a standalone MTC cert (Section 6.2) over the subtree [0, 2)
        // so the verifier side has something to validate. The CA is its own
        // cosigner (Section 5.4).
        AsymmetricCipherKeyPair caKp = generateEd25519KeyPair(random);
        MTCCertAuth ca = new MTCCertAuth(
            CA_TRUST_ANCHOR_ID,
            new BcSha256MerkleTreeHash(),
            MTCObjectIdentifiers.id_alg_mtcProof);
        MerkleTreeHash hashFunc = ca.getHashFunc();
        MTCLog log = new MTCLog(ca, LOG_NUMBER, 0L, 2L);
        byte[] siblingHash = hashFunc.hashLeaf("sibling-leaf-1".getBytes());

        AsymmetricCipherKeyPair eeKp = generateEd25519KeyPair(random);
        SubjectPublicKeyInfo eeSpki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(eeKp.getPublic());

        ContentSigner mtcSigner = new MTCContentSigner(
            log, siblingHash,
            new BcMTCCosigner(ca.getCaId(), caKp.getPrivate()));
        X509CertificateHolder cert = buildEECert(
            ca.issuerName(), ca.certSerial(log, 0L), eeSpki, mtcSigner);
        System.out.println("Issued cert:           " + cert.getEncoded().length + " bytes");

        // --- Verifier side --------------------------------------------------
        // The relying party trusts the CA as its own cosigner. Build the
        // lightweight verifier, then wrap it in MTCSignatureVerifierProvider
        // in *certificate mode* — passing the MTCCertAuth so the adapter has
        // the hash function and CA identity needed to recompute the subtree
        // hash and the CosignedMessage from the TBSCertificate.
        MTCCosignerVerifier cosignerVerifier =
            BcMTCCosignerVerifierProvider.singleCosigner(ca.getCaId(), caKp.getPublic())
                .get(ca.getCaId());
        ContentVerifierProvider provider = new MTCSignatureVerifierProvider(ca, cosignerVerifier);

        // One-line MTC verification through the standard X.509 holder API.
        boolean valid = cert.isSignatureValid(provider);
        System.out.println("isSignatureValid:      " + valid);

        // Tamper a byte of the encoded cert (the last byte lands inside the
        // final cosigner signature in the MTCProof) and confirm the adapter
        // rejects it. Any modification to the TBSCertificate would fail too,
        // since the cosignature commits to the recomputed subtree hash that
        // depends on the TBS bytes.
        byte[] tamperedBytes = cert.getEncoded();
        tamperedBytes[tamperedBytes.length - 1] ^= 0x01;
        X509CertificateHolder tamperedCert = new X509CertificateHolder(tamperedBytes);
        boolean tamperedValid = tamperedCert.isSignatureValid(provider);
        System.out.println("isSignatureValid bad:  " + tamperedValid);
    }

    private static AsymmetricCipherKeyPair generateEd25519KeyPair(SecureRandom random)
    {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(random));
        return gen.generateKeyPair();
    }

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
