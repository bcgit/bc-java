package org.bouncycastle.crypto.signers.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.LMSigParameters;

/**
 * The digest an LMS or HSS message is absorbed into before it is signed or verified, carrying the
 * one-time key or signature the operation will use. Obtain one from
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedSigner#generateLMSContext()} or
 * {@link org.bouncycastle.crypto.signers.LMSContextBasedVerifier#generateLMSContext(byte[])},
 * feed it the message through the {@link Digest} methods, then hand it back to the key. Its
 * contents are read by {@link LMSEngine} only.
 */
public class LMSContext
    implements Digest
{
    private final byte[] C;
    private final LMOtsPrivateKey key;
    private final LMSigParameters sigParams;
    private final byte[][] path;
    private final LMOtsPublicKey publicKey;
    private final Object signature;

    private LMSSignedPubKey[] signedPubKeys;
    private volatile Digest digest;

    LMSContext(LMOtsPrivateKey key, LMSigParameters sigParams, Digest digest, byte[] C, byte[][] path)
    {
        this.key = key;
        this.sigParams = sigParams;
        this.digest = digest;
        this.C = C;
        this.path = path;
        this.publicKey = null;
        this.signature = null;
    }

    LMSContext(LMOtsPublicKey publicKey, Object signature, Digest digest)
    {
        this.publicKey = publicKey;
        this.signature = signature;
        this.digest = digest;
        this.C = null;
        this.key = null;
        this.sigParams = null;
        this.path = null;
    }

    byte[] getC()
    {
        return C;
    }

    byte[] getQ()
    {
        byte[] Q = new byte[LM_OTS.MAX_HASH + 2];

        digest.doFinal(Q, 0);
        
        digest = null;

        return Q;
    }

    byte[][] getPath()
    {
        return path;
    }

    LMOtsPrivateKey getPrivateKey()
    {
        return key;
    }

    LMOtsPublicKey getPublicKey()
    {
        return publicKey;
    }

    LMSigParameters getSigParams()
    {
        return sigParams;
    }

    Object getSignature()
    {
        return signature;
    }

    LMSSignedPubKey[] getSignedPubKeys()
    {
        return signedPubKeys;
    }

    LMSContext withSignedPublicKeys(LMSSignedPubKey[] signedPubKeys)
    {
        this.signedPubKeys = signedPubKeys;

        return this;
    }

    public String getAlgorithmName()
    {
        return digest.getAlgorithmName();
    }

    public int getDigestSize()
    {
        return digest.getDigestSize();
    }

    public void update(byte in)
    {
        digest.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        digest.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        return digest.doFinal(out, outOff);
    }

    public void reset()
    {
        digest.reset();
    }
}
