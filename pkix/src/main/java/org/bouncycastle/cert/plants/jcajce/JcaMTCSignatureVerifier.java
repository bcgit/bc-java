package org.bouncycastle.cert.plants.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.plants.MTCSignatureAlgorithm;
import org.bouncycastle.cert.plants.MTCSignatureVerifier;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Exceptions;

/**
 * JCA-side implementation of {@link MTCSignatureVerifier}.
 *
 * <p>Bound to a {@link PublicKey} and one of the algorithm identifiers defined
 * by Section 6.1 of draft-ietf-plants-merkle-tree-certs:
 * {@code "ECDSA-P256-SHA256"}, {@code "ECDSA-P384-SHA384"}, {@code "Ed25519"},
 * {@code "ML-DSA-44"}, {@code "ML-DSA-65"}, {@code "ML-DSA-87"}.</p>
 *
 * <p>The the draft identifiers are mapped to JCA Signature names internally —
 * the plain (r||s) ECDSA encoding used by MTCProof requires
 * {@code SHA256WITHPLAIN-ECDSA} / {@code SHA384WITHPLAIN-ECDSA}, which BC's
 * JCE provider registers (DER-encoded {@code SHA256withECDSA} is wire-incompatible
 * with the MTCProof signature byte format).</p>
 */
public class JcaMTCSignatureVerifier
    implements MTCSignatureVerifier
{
    /**
     * Placeholder algorithm identifier returned by {@link #getAlgorithmIdentifier()}.
     * MTC's cosigner signature scheme is identified at the MTCProof / cert level
     * by {@code id-alg-mtcProof}; the underlying cosigner-specific signature
     * algorithm is bound at construction.
     */
    private static final AlgorithmIdentifier MTC_SIG_ALG =
        new AlgorithmIdentifier(MTCObjectIdentifiers.id_alg_mtcProof);

    private final PublicKey publicKey;
    private final String algorithm;
    private final JcaJceHelper helper;

    private Signature activeSignature;

    public JcaMTCSignatureVerifier(PublicKey publicKey, String algorithm)
    {
        this(publicKey, algorithm, new DefaultJcaJceHelper());
    }

    public JcaMTCSignatureVerifier(PublicKey publicKey, String algorithm, String providerName)
    {
        this(publicKey, algorithm, new NamedJcaJceHelper(providerName));
    }

    public JcaMTCSignatureVerifier(PublicKey publicKey, String algorithm, Provider provider)
    {
        this(publicKey, algorithm, new ProviderJcaJceHelper(provider));
    }

    public JcaMTCSignatureVerifier(PublicKey publicKey, String algorithm, JcaJceHelper helper)
    {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
        this.helper = helper;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return MTC_SIG_ALG;
    }

    public OutputStream getOutputStream()
    {
        try
        {
            final Signature sig = helper.createSignature(jcaAlgorithm(algorithm));
            sig.initVerify(publicKey);
            this.activeSignature = sig;
            return new OutputStream()
            {
                public void write(int b)
                    throws IOException
                {
                    try
                    {
                        sig.update((byte)b);
                    }
                    catch (SignatureException e)
                    {
                        throw new IOException(e.getMessage(), e);
                    }
                }

                public void write(byte[] buf, int off, int len)
                    throws IOException
                {
                    try
                    {
                        sig.update(buf, off, len);
                    }
                    catch (SignatureException e)
                    {
                        throw new IOException(e.getMessage(), e);
                    }
                }
            };
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException(
                "unable to initialise MTC signature with algorithm " + algorithm + ": " + e.getMessage(), e);
        }
    }

    public boolean verify(byte[] expected)
    {
        if (activeSignature == null)
        {
            throw new IllegalStateException("getOutputStream() must be called before verify()");
        }
        try
        {
            return activeSignature.verify(expected);
        }
        catch (SignatureException e)
        {
            throw Exceptions.illegalStateException(
                "unable to verify MTC signature with algorithm " + algorithm + ": " + e.getMessage(), e);
        }
    }

    /**
     * Maps a draft algorithm identifier to the JCA Signature algorithm name.
     */
    static String jcaAlgorithm(String mtcAlgorithm)
    {
        if (MTCSignatureAlgorithm.ECDSA_P256_SHA256.equals(mtcAlgorithm))
        {
            return "SHA256WITHPLAIN-ECDSA";
        }
        if (MTCSignatureAlgorithm.ECDSA_P384_SHA384.equals(mtcAlgorithm))
        {
            return "SHA384WITHPLAIN-ECDSA";
        }
        if (MTCSignatureAlgorithm.ED25519.equals(mtcAlgorithm))
        {
            return "Ed25519";
        }
        if (MTCSignatureAlgorithm.ML_DSA_44.equals(mtcAlgorithm)
            || MTCSignatureAlgorithm.ML_DSA_65.equals(mtcAlgorithm)
            || MTCSignatureAlgorithm.ML_DSA_87.equals(mtcAlgorithm))
        {
            return mtcAlgorithm;
        }
        throw new IllegalArgumentException("Unsupported algorithm: " + mtcAlgorithm);
    }
}
