package org.bouncycastle.kmip.wire.object;

import org.bouncycastle.kmip.wire.enumeration.KMIPEncodingOption;
import org.bouncycastle.kmip.wire.enumeration.KMIPWrappingMethod;

/**
 * Represents the Key Wrapping Data structure, which contains optional information
 * about the cryptographic key wrapping mechanism used to wrap the Key Value.
 * <p>
 * This structure is used within a Key Block and may contain the following fields:
 * - Wrapping Method: The method used to wrap the Key Value.
 * - Encryption Key Information: Unique Identifier value of the encryption key and associated cryptographic parameters.
 * - MAC/Signature Key Information: Unique Identifier value of the MAC/signature key and associated cryptographic parameters.
 * - MAC/Signature: A MAC or signature of the Key Value.
 * - IV/Counter/Nonce: Required by the wrapping method if applicable.
 * - Encoding Option: Specifies the encoding of the Key Material within the wrapped Key Value structure.
 */
public class KMIPKeyWrappingData
{

    /**
     * The method used to wrap the Key Value (e.g., AES, RSA).
     */
    private KMIPWrappingMethod wrappingMethod;

    /**
     * Information about the encryption key used to encrypt the Key Value.
     */
    private KMIPKeyInformation encryptionKeyInfo;

    /**
     * Information about the MAC/signature key used for MAC/signing the Key Value.
     */
    private KMIPKeyInformation macSignatureKeyInfo;

    /**
     * A MAC or signature of the Key Value.
     */
    private byte[] macSignature;

    /**
     * Initialization vector, counter, or nonce, if required by the wrapping method.
     */
    private byte[] ivCounterNonce;

    /**
     * Specifies the encoding of the Key Material within the wrapped Key Value structure.
     */
    private KMIPEncodingOption encodingOption;

    /**
     * Constructs a new KeyWrappingData with the specified parameters.
     *
     * @param wrappingMethod      The method used to wrap the Key Value.
     * @param encryptionKeyInfo   Information about the encryption key (optional).
     * @param macSignatureKeyInfo Information about the MAC/signature key (optional).
     * @param macSignature        A MAC or signature of the Key Value (optional).
     * @param ivCounterNonce      IV, counter, or nonce if required by the wrapping method (optional).
     * @param encodingOption  The encoding option for the Key Value (optional).
     */
    public KMIPKeyWrappingData(KMIPWrappingMethod wrappingMethod,
                               KMIPKeyInformation encryptionKeyInfo,
                               KMIPKeyInformation macSignatureKeyInfo,
                               byte[] macSignature,
                               byte[] ivCounterNonce,
                               KMIPEncodingOption encodingOption)
    {
        this.wrappingMethod = wrappingMethod;
        this.encryptionKeyInfo = encryptionKeyInfo;
        this.macSignatureKeyInfo = macSignatureKeyInfo;
        this.macSignature = macSignature;
        this.ivCounterNonce = ivCounterNonce;
        this.encodingOption = encodingOption;
    }

    // Getters and Setters

    public KMIPWrappingMethod getWrappingMethod()
    {
        return wrappingMethod;
    }

    public void setWrappingMethod(KMIPWrappingMethod KMIPWrappingMethod)
    {
        this.wrappingMethod = KMIPWrappingMethod;
    }

    public KMIPKeyInformation getEncryptionKeyInfo()
    {
        return encryptionKeyInfo;
    }

    public void setEncryptionKeyInfo(KMIPKeyInformation encryptionKeyInfo)
    {
        this.encryptionKeyInfo = encryptionKeyInfo;
    }

    public KMIPKeyInformation getMacSignatureKeyInfo()
    {
        return macSignatureKeyInfo;
    }

    public void setMacSignatureKeyInfo(KMIPKeyInformation macSignatureKeyInfo)
    {
        this.macSignatureKeyInfo = macSignatureKeyInfo;
    }

    public byte[] getMacSignature()
    {
        return macSignature;
    }

    public void setMacSignature(byte[] macSignature)
    {
        this.macSignature = macSignature;
    }

    public byte[] getIvCounterNonce()
    {
        return ivCounterNonce;
    }

    public void setIvCounterNonce(byte[] ivCounterNonce)
    {
        this.ivCounterNonce = ivCounterNonce;
    }

    public KMIPEncodingOption getEncodingOption()
    {
        return encodingOption;
    }

    public void setEncodingOption(KMIPEncodingOption KMIPEncodingOption)
    {
        this.encodingOption = KMIPEncodingOption;
    }
}
