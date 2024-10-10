package org.bouncycastle.crypto.split;

public class KMIPKeyInformation
{

    /**
     * Unique identifier of the encryption key.
     */
    private String uniqueIdentifier;

    /**
     * Optional cryptographic parameters associated with the encryption key.
     */
    private KMIPCryptographicParameters KMIPCryptographicParameters;

    /**
     * Constructs a new EncryptionKeyInformation with the specified parameters.
     *
     * @param uniqueIdentifier        The unique identifier of the encryption key.
     * @param KMIPCryptographicParameters Optional cryptographic parameters.
     */
    public KMIPKeyInformation(String uniqueIdentifier,
                              KMIPCryptographicParameters KMIPCryptographicParameters)
    {
        this.uniqueIdentifier = uniqueIdentifier;
        this.KMIPCryptographicParameters = KMIPCryptographicParameters;
    }

    // Getters and Setters

    public String getUniqueIdentifier()
    {
        return uniqueIdentifier;
    }

    public void setUniqueIdentifier(String uniqueIdentifier)
    {
        this.uniqueIdentifier = uniqueIdentifier;
    }

    public KMIPCryptographicParameters getCryptographicParameters()
    {
        return KMIPCryptographicParameters;
    }

    public void setCryptographicParameters(KMIPCryptographicParameters KMIPCryptographicParameters)
    {
        this.KMIPCryptographicParameters = KMIPCryptographicParameters;
    }
}

