package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.slhdsa.SLHDSAEngine;

/**
 * Pre-hash ("HashSLH-DSA") SLH-DSA (FIPS 205) signer/verifier.
 * <p>
 * By default the pre-hash function is the one named by the key's parameter set (SHA-256, SHA-512,
 * SHAKE128 or SHAKE256, the ones with HashSLH-DSA object identifiers). {@link #HashSLHDSASigner(Digest)}
 * allows any of the other pre-hash functions FIPS 205 sec. 10.2 permits and ACVP tests; there are no
 * object identifiers for those signatures, so identifying them to a verifier is up to the caller.
 * </p>
 * <p>
 * As well as the streaming {@link Signer} API, {@link #generateSignature(byte[])} and
 * {@link #verifySignature(byte[], byte[])} accept a hash of the message computed elsewhere.
 * </p>
 */
public class HashSLHDSASigner
    implements Signer
{
    private final Digest preHashDigest;
    private final byte[] preHashOIDEncoding;

    private byte[] msgPrefix;
    private byte[] optRand;
    private SLHDSAPublicKeyParameters pubKey;
    private SLHDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private Digest digest;

    private byte[] pkSeed, pkRoot, skSeed, skPrf;

    /**
     * Create a signer whose pre-hash function is the one named by the parameter set of the
     * key it is initialised with.
     */
    public HashSLHDSASigner()
    {
        this.preHashDigest = null;
        this.preHashOIDEncoding = null;
    }

    /**
     * Create a signer using the passed in pre-hash function, whatever the parameter set of the
     * key it is initialised with. The digest must be one of SHA-224, SHA-256, SHA-384, SHA-512,
     * SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 (256 bit output)
     * or SHAKE256 (512 bit output). Its object identifier is absorbed into the signature as FIPS 205
     * Algorithm 23 requires.
     * <p>
     * FIPS 205 sec. 10.2 requires the pre-hash function to provide at least 8n bits of classical
     * security strength (128, 192 or 256 bits for the 128, 192 and 256 parameter sets) against
     * collision and second preimage attacks, so, for example, SHA-256 is only suitable with the
     * 128 bit parameter sets. This is not enforced here, as ACVP tests other pairings as well.
     * </p>
     * <p>
     * The digest is used directly, not copied, so must not be shared with another user.
     * </p>
     *
     * @param preHashDigest the digest to pre-hash the message with.
     * @throws IllegalArgumentException if the digest is not one of the above.
     */
    public HashSLHDSASigner(Digest preHashDigest)
    {
        if (preHashDigest == null)
        {
            throw new NullPointerException("preHashDigest cannot be null");
        }

        this.preHashDigest = preHashDigest;
        this.preHashOIDEncoding = Utils.getPreHashOIDEncoding(preHashDigest);
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        ParametersWithContext withContext = null;
        if (param instanceof ParametersWithContext)
        {
            withContext = (ParametersWithContext)param;
            param = ((ParametersWithContext)param).getParameters();

            if (withContext.getContextLength() > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }

        SLHDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                privKey = ((SLHDSAPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (SLHDSAPrivateKeyParameters)param;
                random = null;
            }

            parameters = privKey.getParameters();

            skSeed = privKey.getSeed();
            skPrf = privKey.getPrf();
            pkSeed = privKey.getPublicSeed();
            pkRoot = privKey.getRoot();

            // generate randomizer
            optRand = new byte[parameters.getN()];
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            skSeed = null;
            skPrf = null;
            pkSeed = pubKey.getSeed();
            pkRoot = pubKey.getRoot();

            parameters = pubKey.getParameters();
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("SLH-DSA",
            parameters.getClassicalSecurityStrength(), forSigning ? (CipherParameters)privKey : (CipherParameters)pubKey, forSigning));

        initDigest(parameters, withContext);
    }

    private void initDigest(SLHDSAParameters parameters, ParametersWithContext withContext)
    {
        byte[] digestOIDEncoding;
        if (preHashDigest != null)
        {
            digest = preHashDigest;
            digest.reset();
            digestOIDEncoding = preHashOIDEncoding;
        }
        else
        {
            digest = createDigest(parameters);
            digestOIDEncoding = Utils.getPreHashOIDEncoding(digest);
        }

        int ctxLength = withContext == null ? 0 : withContext.getContextLength();

        msgPrefix = new byte[2 + ctxLength + digestOIDEncoding.length];
        msgPrefix[0] = 1;
        msgPrefix[1] = (byte)ctxLength;
        if (withContext != null)
        {
            withContext.copyContextTo(msgPrefix, 2, ctxLength);
        }
        System.arraycopy(digestOIDEncoding, 0, msgPrefix, 2 + ctxLength, digestOIDEncoding.length);
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public byte[] generateSignature() throws CryptoException, DataLengthException
    {
        if (privKey == null)
        {
            throw new IllegalStateException("HashSLHDSASigner not initialised for signature generation.");
        }

        return generateSignatureFromHash(finishPreHash());
    }

    public boolean verifySignature(byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("HashSLHDSASigner not initialised for verification");
        }

        return verifySignatureFromHash(finishPreHash(), signature);
    }

    /**
     * Sign a message that has already been hashed externally (FIPS 205 Algorithm 23 with PH_M
     * supplied by the caller). The hash must have been produced with the pre-hash function this
     * signer uses: the digest passed to the constructor, or else the one named by the parameter
     * set of the key it was initialised with.
     *
     * @param hash the digest of the message.
     * @return the SLH-DSA signature.
     * @throws IllegalArgumentException if the hash is the wrong length for the pre-hash function.
     */
    public byte[] generateSignature(byte[] hash)
        throws CryptoException, DataLengthException
    {
        if (privKey == null)
        {
            throw new IllegalStateException("HashSLHDSASigner not initialised for signature generation.");
        }
        if (hash == null)
        {
            throw new NullPointerException("hash must not be null");
        }
        checkHashLength(hash);

        return generateSignatureFromHash(hash);
    }

    /**
     * Verify a signature over a message that has already been hashed externally; companion to
     * {@link #generateSignature(byte[])}.
     *
     * @param hash the digest of the message.
     * @param signature the candidate signature.
     * @return true if the signature is valid.
     * @throws IllegalArgumentException if the hash is the wrong length for the pre-hash function.
     */
    public boolean verifySignature(byte[] hash, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("HashSLHDSASigner not initialised for verification");
        }
        if (hash == null || signature == null)
        {
            throw new NullPointerException("hash and signature must not be null");
        }
        checkHashLength(hash);

        return verifySignatureFromHash(hash, signature);
    }

    private void checkHashLength(byte[] hash)
    {
        int expected = digest.getDigestSize();
        if (hash.length != expected)
        {
            throw new IllegalArgumentException("hash length wrong for " + digest.getAlgorithmName()
                + ": expected " + expected + " bytes, got " + hash.length);
        }
    }

    private byte[] finishPreHash()
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    private byte[] generateSignatureFromHash(byte[] hash)
    {
        if (random != null)
        {
            random.nextBytes(optRand);
        }
        else
        {
            System.arraycopy(privKey.getPublicSeed(), 0, optRand, 0, optRand.length);
        }

        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, msgPrefix, hash, optRand);
    }

    private boolean verifySignatureFromHash(byte[] hash, byte[] signature)
    {
        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, msgPrefix, hash, signature);
    }

    public void reset()
    {
        digest.reset();
    }

    protected byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, null, message, optRand);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, null, message, signature);
    }

    private static Digest createDigest(SLHDSAParameters parameters)
    {
        switch (parameters.getType())
        {
        case SLHDSAParameters.TYPE_PURE:
            String name = parameters.getName();
            if (name.startsWith("sha2"))
            {
                if (SLHDSAParameters.sha2_128f == parameters
                    || SLHDSAParameters.sha2_128s == parameters)
                {
                    return SHA256Digest.newInstance();
                }
                else
                {
                    return new SHA512Digest();
                }
            }
            else
            {
                if (SLHDSAParameters.shake_128f == parameters
                    || SLHDSAParameters.shake_128s == parameters)
                {
                    return new SHAKEDigest(128);
                }
                else
                {
                    return new SHAKEDigest(256);
                }
            }
        case SLHDSAParameters.TYPE_SHA2_256:
            return SHA256Digest.newInstance();
        case SLHDSAParameters.TYPE_SHA2_512:
            return new SHA512Digest();
        case SLHDSAParameters.TYPE_SHAKE128:
            return new SHAKEDigest(128);
        case SLHDSAParameters.TYPE_SHAKE256:
            return new SHAKEDigest(256);
        default:
            throw new IllegalArgumentException("unknown parameters type");
        }
    }
}

