package org.bouncycastle.pqc.crypto;


import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Base interface for a PQC stateful signature algorithm.
 */
public interface StateAwareMessageSigner
    extends MessageSigner
{
    /**
     * Return the current version of the private key with the updated state.
     * <p>
     * <b>Note:</b> calling this method will effectively disable the Signer from being used for further
     *  signature generation without another call to init().
     * </p>
     * @return an updated private key object, which can be used for later signature generation.
     */
    public AsymmetricKeyParameter getUpdatedPrivateKey();
}
