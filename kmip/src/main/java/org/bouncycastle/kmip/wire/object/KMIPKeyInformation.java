package org.bouncycastle.kmip.wire.object;

import org.bouncycastle.kmip.wire.attribute.KMIPUniqueIdentifier;

public class KMIPKeyInformation
    extends KMIPObject
{

    /**
     * Unique identifier of the encryption key.
     */
    private KMIPUniqueIdentifier uniqueIdentifier;

    /**
     * Optional cryptographic parameters associated with the encryption key.
     */
    private KMIPCryptographicParameters cryptographicParameters;

    /**
     * Constructs a new EncryptionKeyInformation with the specified parameters.
     *
     * @param uniqueIdentifier        The unique identifier of the encryption key.
     * @param cryptographicParameters Optional cryptographic parameters.
     */
    public KMIPKeyInformation(KMIPUniqueIdentifier uniqueIdentifier,
                              KMIPCryptographicParameters cryptographicParameters)
    {
        this.uniqueIdentifier = uniqueIdentifier;
        this.cryptographicParameters = cryptographicParameters;
    }

    // Getters and Setters

    public KMIPUniqueIdentifier getUniqueIdentifier()
    {
        return uniqueIdentifier;
    }

    public void setUniqueIdentifier(KMIPUniqueIdentifier uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public KMIPCryptographicParameters getCryptographicParameters()
    {
        return cryptographicParameters;
    }

    public void setCryptographicParameters(KMIPCryptographicParameters KMIPCryptographicParameters)
    {
        this.cryptographicParameters = KMIPCryptographicParameters;
    }
}

