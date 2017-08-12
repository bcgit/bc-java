package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;

/**
 * This interface is implemented by Signature classes returned by the PQC provider where the signature
 * algorithm is one where the private key is updated for each signature generated. Examples of these
 * are algorithms such as GMSS, XMSS, and XMSS^MT.
 */
public interface StateAwareSignature
{
    void initVerify(PublicKey publicKey)
        throws InvalidKeyException;

    void initVerify(Certificate certificate)
        throws InvalidKeyException;

    void initSign(PrivateKey privateKey)
        throws InvalidKeyException;

    void initSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException;

    byte[] sign()
        throws SignatureException;

    int sign(byte[] outbuf, int offset, int len)
        throws SignatureException;

    boolean verify(byte[] signature)
        throws SignatureException;

    boolean verify(byte[] signature, int offset, int length)
        throws SignatureException;

    void update(byte b)
        throws SignatureException;

    void update(byte[] data)
        throws SignatureException;

    void update(byte[] data, int off, int len)
        throws SignatureException;

    String getAlgorithm();

    /**
     * Return the current version of the private key with the updated state.
     * <p>
     * <b>Note:</b> calling this method will effectively disable the Signature object from being used for further
     *  signature generation without another call to init().
     * </p>
     * @return an updated private key object, which can be used for later signature generation.
     */
   PrivateKey getUpdatedPrivateKey();
}
