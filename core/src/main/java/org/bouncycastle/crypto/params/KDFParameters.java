package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;

/**
 * Parameters for the key derivation functions that derive keying material from a shared secret and
 * an optional block of additional input: KDF1 and KDF2 of IEEE P1363a / ISO 18033-2 (KDF2 being the
 * ANSI X9.63 KDF, where the additional input is the SharedInfo), and the NIST SP 800-56A concatenation
 * KDF (where it is the OtherInfo).
 * <p>
 * For historical reasons the additional input is referred to as the "IV".
 * </p>
 */
public class KDFParameters
    implements DerivationParameters
{
    byte[]  iv;
    byte[]  shared;

    /**
     * Base constructor.
     *
     * @param shared the shared secret the keying material is derived from.
     * @param iv the additional input to the key derivation function, or null if there is none.
     * @throws NullPointerException if shared is null.
     */
    public KDFParameters(
        byte[]  shared,
        byte[]  iv)
    {
        if (shared == null)
        {
            throw new NullPointerException("'shared' cannot be null");
        }

        this.shared = shared;
        this.iv = iv;
    }

    /**
     * Return the shared secret the keying material is derived from.
     *
     * @return the shared secret, never null.
     */
    public byte[] getSharedSecret()
    {
        // TODO Consider returning a clone (and cloning in the constructor)
        return shared;
    }

    /**
     * Return the additional input to the key derivation function.
     *
     * @return the additional input, or null if there is none.
     */
    public byte[] getIV()
    {
        // TODO Consider returning a clone (and cloning in the constructor)
        return iv;
    }
}
