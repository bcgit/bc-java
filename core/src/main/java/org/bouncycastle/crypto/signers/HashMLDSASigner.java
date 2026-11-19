package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.mldsa.MLDSAEngine;

/**
 * Pre-hash ("HashML-DSA" / "ExtHash") ML-DSA (FIPS 204) signer/verifier.
 * <p>
 * As with {@link MLDSASigner}, {@link #verifySignature(byte[])} (and the externally-hashed
 * {@link #verifySignature(byte[], byte[])}) return <code>false</code> both for a
 * cryptographically wrong signature and for one that is structurally malformed per FIPS 204
 * Algorithm 8; only an incorrectly sized externally-supplied hash (the {@code hash} argument to
 * the two-argument overload) throws {@link IllegalArgumentException}. See
 * <a href="https://github.com/bcgit/bc-java/issues/2367">github #2367</a>.
 * </p>
 * <p>
 * By default the pre-hash function is the one named by the key's parameter set (SHA-512, the only
 * one with a HashML-DSA object identifier). {@link #HashMLDSASigner(Digest)} allows any of the
 * other pre-hash functions FIPS 204 sec. 5.4 permits and ACVP tests; there are no object
 * identifiers for those signatures, so identifying them to a verifier is up to the caller.
 * </p>
 */
public class HashMLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private MLDSAPublicKeyParameters pubKey;
    private MLDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private final Digest preHashDigest;
    private final byte[] preHashOIDEncoding;

    private MLDSAEngine engine;
    private Digest digest;
    private byte[] digestOIDEncoding;

    private byte[] rho, k, t0, t1, s1, s2;

    /**
     * Create a signer whose pre-hash function is the one named by the parameter set of the
     * key it is initialised with (SHA-512).
     */
    public HashMLDSASigner()
    {
        this.preHashDigest = null;
        this.preHashOIDEncoding = null;
    }

    /**
     * Create a signer using the passed in pre-hash function, whatever the parameter set of the
     * key it is initialised with. The digest must be one of SHA-224, SHA-256, SHA-384, SHA-512,
     * SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 (256 bit output)
     * or SHAKE256 (512 bit output). Its object identifier is absorbed into the signature as FIPS 204
     * Algorithm 4 requires.
     * <p>
     * FIPS 204 sec. 5.4 requires the pre-hash function to provide at least the parameter set's
     * classical security strength (128, 192 or 256 bits for ML-DSA-44, -65 and -87) against
     * collision and second preimage attacks, so, for example, SHA-256 is only suitable with
     * ML-DSA-44. This is not enforced here, as ACVP tests other pairings as well.
     * </p>
     * <p>
     * The digest is used directly, not copied, so must not be shared with another user.
     * </p>
     *
     * @param preHashDigest the digest to pre-hash the message with.
     * @throws IllegalArgumentException if the digest is not one of the above.
     */
    public HashMLDSASigner(Digest preHashDigest)
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
        byte[] ctx = EMPTY_CONTEXT;

        this.rho = this.k = this.t0 = this.t1 = this.s1 = this.s2 = null;
        
        if (param instanceof ParametersWithContext)
        {
            ParametersWithContext withContext = (ParametersWithContext)param;
            ctx = withContext.getContext();
            param = withContext.getParameters();

            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }

        MLDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MLDSAPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MLDSAPrivateKeyParameters)param;
                random = null;
            }

            parameters = privKey.getParameters();
            engine = MLDSAEngine.getInstance(parameters, random);

            this.rho = privKey.getRho();
            this.t0 = privKey.getT0();
            this.k = privKey.getK();
            this.s1 = privKey.getS1();
            this.s2 = privKey.getS2();

            engine.initSign(privKey.getTr(), true, ctx);
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            parameters = pubKey.getParameters();
            engine = MLDSAEngine.getInstance(parameters, null);

            this.rho = pubKey.getRho();
            this.t1 = pubKey.getT1();

            engine.initVerify(rho, t1, true, ctx);
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ML-DSA",
            parameters.getClassicalSecurityStrength(), forSigning ? (CipherParameters)privKey : (CipherParameters)pubKey, forSigning));

        initDigest(parameters);
    }

    private void initDigest(MLDSAParameters parameters)
    {
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
        return generateSignatureFromMsgDigest(finishPreHash());
    }

    public boolean verifySignature(byte[] signature)
    {
        SHAKEDigest msgDigest = finishPreHash();

        return engine.verifyInternal(signature, signature.length, msgDigest, rho, t1);
    }

    /**
     * Sign a message that has already been hashed externally. See FIPS 204 sec. 5.4
     * (HashML-DSA): the caller supplies the digest of the message and the signer
     * absorbs it together with the DER encoding of the digest algorithm's OID
     * (the digest passed to the constructor, or else the one derived from the parameter
     * set this signer was initialised with) into the mu computation, just as the
     * streaming form would. The supplied hash must have been produced with that
     * digest algorithm.
     *
     * @param hash the digest of the message.
     * @return the ML-DSA signature.
     */
    public byte[] generateSignature(byte[] hash)
        throws CryptoException, DataLengthException
    {
        if (privKey == null)
        {
            throw new IllegalStateException("HashMLDSASigner not initialised for signing");
        }
        if (hash == null)
        {
            throw new NullPointerException("hash must not be null");
        }
        checkHashLength(hash);

        return generateSignatureFromMsgDigest(buildExternalMsgDigest(digestOIDEncoding, hash));
    }

    /**
     * Verify a signature over a message that has already been hashed externally;
     * companion to {@link #generateSignature(byte[])}.
     *
     * @param hash the digest of the message.
     * @param signature the candidate signature.
     * @return true if the signature is valid.
     */
    public boolean verifySignature(byte[] hash, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("HashMLDSASigner not initialised for verification");
        }
        if (hash == null || signature == null)
        {
            throw new NullPointerException("hash and signature must not be null");
        }
        checkHashLength(hash);

        SHAKEDigest msgDigest = buildExternalMsgDigest(digestOIDEncoding, hash);
        return engine.verifyInternal(signature, signature.length, msgDigest, rho, t1);
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

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
    }

    private byte[] generateSignatureFromMsgDigest(SHAKEDigest msgDigest)
        throws CryptoException, DataLengthException
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }
        byte[] mu = engine.generateMu(msgDigest);

        return engine.generateSignature(mu, msgDigest, rho, k, t0, s1, s2, rnd);
    }

    private SHAKEDigest buildExternalMsgDigest(byte[] hashOidEncoding, byte[] hash)
    {
        SHAKEDigest msgDigest = engine.getShake256Digest();
        msgDigest.update(hashOidEncoding, 0, hashOidEncoding.length);
        msgDigest.update(hash, 0, hash.length);
        return msgDigest;
    }

    private SHAKEDigest finishPreHash()
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return buildExternalMsgDigest(digestOIDEncoding, hash);
    }

//    TODO: these are probably no longer correct and also need to be marked as protected
//    protected byte[] internalGenerateSignature(byte[] message, byte[] random)
//    {
//        MLDSAEngine engine = privKey.getParameters().getEngine(random);
//
//        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, random);
//    }
//
//    protected boolean internalVerifySignature(byte[] message, byte[] signature)
//    {
//        MLDSAEngine engine = pubKey.getParameters().getEngine(random);
//
//        return engine.verifyInternal(signature, signature.length, message, message.length, pubKey.rho, pubKey.t1);
//    }

    private static Digest createDigest(MLDSAParameters parameters)
    {
        switch (parameters.getType())
        {
        case MLDSAParameters.TYPE_PURE:
        case MLDSAParameters.TYPE_SHA2_512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("unknown parameters type");
        }
    }
}
