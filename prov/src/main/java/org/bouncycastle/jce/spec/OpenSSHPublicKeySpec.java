package org.bouncycastle.jce.spec;

/**
 * Holds an OpenSSH encoded public key.
 * @deprecated use org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec
 */
public class OpenSSHPublicKeySpec
    extends org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec
{
    /**
     * Construct and instance and determine the OpenSSH public key type.
     * The current types are ssh-rsa, ssh-ed25519, ssh-dss and ecdsa-*
     * <p>
     * It does not validate the key beyond identifying the type.
     *
     * @param encodedKey
     */
    public OpenSSHPublicKeySpec(byte[] encodedKey)
    {
        super(encodedKey);
    }
}
