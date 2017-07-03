package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


/**
 * Implements the sign and verify functions for a Signature Scheme using a hash function to allow processing of large messages.
 * <p>
 *  This class can be used with algorithms where the state associated with the private key changes as each signature is
 *  generated. Calling getUpdatedPrivateKey() will recover the private key that can be used to initialize a signer
 *  next time around.
 * </p>
 */
public class DigestingStateAwareMessageSigner
    extends DigestingMessageSigner
{
    private final StateAwareMessageSigner signer;

    public DigestingStateAwareMessageSigner(StateAwareMessageSigner messSigner, Digest messDigest)
    {
        super(messSigner, messDigest);

        this.signer = messSigner;
    }

    /**
     * Return the current version of the private key with the updated state.
     * <p>
     * <b>Note:</b> calling this method will effectively disable the Signer from being used for further
     *  signature generation without another call to init().
     * </p>
     * @return an updated private key object, which can be used for later signature generation.
     */
    public AsymmetricKeyParameter getUpdatedPrivateKey()
    {
        return signer.getUpdatedPrivateKey();
    }
}
