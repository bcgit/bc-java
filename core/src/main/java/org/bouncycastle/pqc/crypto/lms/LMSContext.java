package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

import static org.bouncycastle.pqc.crypto.lms.LM_OTS.MAX_HASH;

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

    public LMSContext(LMOtsPrivateKey key, LMSigParameters sigParams, Digest digest, byte[] C, byte[][] path)
    {
        this.key = key;
        this.sigParams = sigParams;
        this.digest = digest;
        this.C = C;
        this.path = path;
        this.publicKey = null;
        this.signature = null;
    }

    public LMSContext(LMOtsPublicKey publicKey, Object signature, Digest digest)
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
        byte[] Q = new byte[MAX_HASH + 2];

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

    public LMOtsPublicKey getPublicKey()
    {
        return publicKey;
    }

    LMSigParameters getSigParams()
    {
        return sigParams;
    }

    public Object getSignature()
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
