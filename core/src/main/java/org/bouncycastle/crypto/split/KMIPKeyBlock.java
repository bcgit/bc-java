package org.bouncycastle.crypto.split;

/**
 * Represents a Key Block object, a structure used to encapsulate all information
 * associated with a cryptographic key.
 * <p>
 * The Key Block may contain the following properties:
 * - Key Format Type: Indicates the format of the key (e.g., RSA, AES).
 * - Key Compression Type: Indicates the format of the elliptic curve public key.
 * - Key Value: The actual key data, which may be wrapped (encrypted) or in plaintext.
 * - Cryptographic Algorithm: The algorithm used for the cryptographic key.
 * - Cryptographic Length: The length of the cryptographic key in bits.
 * - Key Wrapping Data: Data structure that is present if the key is wrapped.
 */
public class KMIPKeyBlock
{

    /**
     * The format type of the key (e.g., RSA, AES).
     */
    private int KMIPKeyFormatType;

    /**
     * The compression type of the key (e.g., compressed, uncompressed).
     */
    private int KMIPKeyCompressionType;

    /**
     * The key value, which can be a wrapped key (byte array) or plaintext (object structure).
     */
    private Object keyValue;  // Could be byte[] for wrapped keys or a specific structure for plaintext keys.

    /**
     * The cryptographic algorithm used for the key (e.g., RSA, AES).
     */
    private KMIPCryptographicAlgorithm KMIPCryptographicAlgorithm;

    /**
     * The length of the cryptographic key in bits.
     */
    private Integer cryptographicLength;

    /**
     * Data structure containing key wrapping information, if the key is wrapped.
     */
    private KMIPKeyWrappingData KMIPKeyWrappingData;

    /**
     * Constructs a new KeyBlock with the specified parameters.
     *
     * @param KMIPKeyFormatType          The format type of the key.
     * @param KMIPKeyCompressionType     The compression type of the key (optional).
     * @param keyValue               The key value (wrapped or plaintext).
     * @param KMIPCryptographicAlgorithm The cryptographic algorithm used for the key.
     * @param cryptographicLength    The length of the cryptographic key in bits (optional).
     * @param KMIPKeyWrappingData        The key wrapping data, if the key is wrapped (optional).
     */
    public KMIPKeyBlock(int KMIPKeyFormatType, int KMIPKeyCompressionType,
                        Object keyValue, KMIPCryptographicAlgorithm KMIPCryptographicAlgorithm,
                        Integer cryptographicLength, KMIPKeyWrappingData KMIPKeyWrappingData)
    {
        this.KMIPKeyFormatType = KMIPKeyFormatType;
        this.KMIPKeyCompressionType = KMIPKeyCompressionType;
        this.keyValue = keyValue;
        this.KMIPCryptographicAlgorithm = KMIPCryptographicAlgorithm;
        this.cryptographicLength = cryptographicLength;
        this.KMIPKeyWrappingData = KMIPKeyWrappingData;
    }

    // Getters and Setters

    public int getKeyFormatType()
    {
        return KMIPKeyFormatType;
    }

    public void setKeyFormatType(int KMIPKeyFormatType)
    {
        this.KMIPKeyFormatType = KMIPKeyFormatType;
    }

    public int getKeyCompressionType()
    {
        return KMIPKeyCompressionType;
    }

    public void setKeyCompressionType(int KMIPKeyCompressionType)
    {
        this.KMIPKeyCompressionType = KMIPKeyCompressionType;
    }

    public Object getKeyValue()
    {
        return keyValue;
    }

    public void setKeyValue(Object keyValue)
    {
        this.keyValue = keyValue;
    }

    public KMIPCryptographicAlgorithm getCryptographicAlgorithm()
    {
        return KMIPCryptographicAlgorithm;
    }

    public void setCryptographicAlgorithm(KMIPCryptographicAlgorithm KMIPCryptographicAlgorithm)
    {
        this.KMIPCryptographicAlgorithm = KMIPCryptographicAlgorithm;
    }

    public Integer getCryptographicLength()
    {
        return cryptographicLength;
    }

    public void setCryptographicLength(Integer cryptographicLength)
    {
        this.cryptographicLength = cryptographicLength;
    }

    public KMIPKeyWrappingData getKeyWrappingData()
    {
        return KMIPKeyWrappingData;
    }

    public void setKeyWrappingData(KMIPKeyWrappingData KMIPKeyWrappingData)
    {
        this.KMIPKeyWrappingData = KMIPKeyWrappingData;
    }
}


