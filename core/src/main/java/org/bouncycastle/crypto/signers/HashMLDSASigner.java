package org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
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
import org.bouncycastle.pqc.crypto.DigestUtils;
import org.bouncycastle.util.Exceptions;

public class HashMLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private MLDSAPublicKeyParameters pubKey;
    private MLDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private MLDSAEngine engine;
    private Digest digest;
    private byte[] digestOIDEncoding;

    private byte[] rho, k, t0, t1, s1, s2;

    public HashMLDSASigner()
    {
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

        initDigest(parameters);
    }

    private void initDigest(MLDSAParameters parameters)
    {
        digest = createDigest(parameters);

        ASN1ObjectIdentifier oid = DigestUtils.getDigestOid(digest.getAlgorithmName());
        try
        {
            digestOIDEncoding = oid.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("oid encoding failed", e);
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
     * (derived from the parameter set this signer was initialised with) into the
     * mu computation, just as the streaming form would. The supplied hash must
     * have been produced with the digest algorithm matching the configured
     * parameter set.
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
