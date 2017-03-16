package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;


/**
 * Implements the sign and verify functions for a Signature Scheme using a hash function to allow processing of large messages.
 */
public class DigestingMessageSigner
    implements Signer
{
    private final Digest messDigest;
    private final MessageSigner messSigner;
    private boolean forSigning;

    public DigestingMessageSigner(MessageSigner messSigner, Digest messDigest)
    {
        this.messSigner = messSigner;
        this.messDigest = messDigest;
    }

    public void init(boolean forSigning,
                     CipherParameters param)
    {

        this.forSigning = forSigning;
        AsymmetricKeyParameter k;

        if (param instanceof ParametersWithRandom)
        {
            k = (AsymmetricKeyParameter)((ParametersWithRandom)param).getParameters();
        }
        else
        {
            k = (AsymmetricKeyParameter)param;
        }

        if (forSigning && !k.isPrivate())
        {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!forSigning && k.isPrivate())
        {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();

        messSigner.init(forSigning, param);
    }


    /**
     * This function signs the message that has been updated, making use of the
     * private key.
     *
     * @return the signature of the message.
     */
    public byte[] generateSignature()
    {
        if (!forSigning)
        {
            throw new IllegalStateException("DigestingMessageSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hash, 0);

        return messSigner.generateSignature(hash);
    }

    public void update(byte b)
    {
        messDigest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        messDigest.update(in, off, len);
    }

    public void reset()
    {
        messDigest.reset();
    }

    /**
     * This function verifies the signature of the message that has been
     * updated, with the aid of the public key.
     *
     * @param signature the signature of the message is given as a byte array.
     * @return true if the signature has been verified, false otherwise.
     */
    public boolean verifySignature(byte[] signature)
    {
        if (forSigning)
        {
            throw new IllegalStateException("DigestingMessageSigner not initialised for verification");
        }

        byte[] hash = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hash, 0);

        return messSigner.verifySignature(hash, signature);
    }
}
