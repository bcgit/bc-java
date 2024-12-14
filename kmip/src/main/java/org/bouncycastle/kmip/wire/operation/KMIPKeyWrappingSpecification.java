package org.bouncycastle.kmip.wire.operation;

import org.bouncycastle.kmip.wire.enumeration.KMIPEncodingOption;
import org.bouncycastle.kmip.wire.enumeration.KMIPWrappingMethod;
import org.bouncycastle.kmip.wire.object.KMIPKeyInformation;

/**
 * Represents the Key Wrapping Specification structure for wrapping a key.
 * This structure includes the wrapping method, encryption or MAC/signature key info,
 * attribute names, and encoding option.
 */
public class KMIPKeyWrappingSpecification
{

    // Enumeration for Wrapping Method.
    private KMIPWrappingMethod wrappingMethod;

    // Optional Encryption Key Information (required if MAC/Signature Key Information is omitted).
    private KMIPKeyInformation encryptionKeyInformation;

    // Optional MAC/Signature Key Information (required if Encryption Key Information is omitted).
    private KMIPKeyInformation macSignatureKeyInformation;

    // Optional list of attribute names to be wrapped with the key material.
    private String[] attributeNames;

    // Optional Encoding Option (if not present, the wrapped Key Value will be TTLV encoded).
    private KMIPEncodingOption encodingOption;

    // Constructor
    public KMIPKeyWrappingSpecification(KMIPWrappingMethod wrappingMethod, KMIPKeyInformation encryptionKeyInformation,
                                    KMIPKeyInformation macSignatureKeyInformation, String[] attributeNames,
                                    KMIPEncodingOption encodingOption)
    {
        this.wrappingMethod = wrappingMethod;
        this.encryptionKeyInformation = encryptionKeyInformation;
        this.macSignatureKeyInformation = macSignatureKeyInformation;
        this.attributeNames = attributeNames;
        this.encodingOption = encodingOption;
    }

    // Getters and Setters
    public KMIPWrappingMethod getWrappingMethod()
    {
        return wrappingMethod;
    }

    public void setWrappingMethod(KMIPWrappingMethod wrappingMethod)
    {
        this.wrappingMethod = wrappingMethod;
    }

    public KMIPKeyInformation getEncryptionKeyInformation()
    {
        return encryptionKeyInformation;
    }

    public void setEncryptionKeyInformation(KMIPKeyInformation encryptionKeyInformation)
    {
        this.encryptionKeyInformation = encryptionKeyInformation;
    }

    public KMIPKeyInformation getMacSignatureKeyInformation()
    {
        return macSignatureKeyInformation;
    }

    public void setMacSignatureKeyInformation(KMIPKeyInformation macSignatureKeyInformation)
    {
        this.macSignatureKeyInformation = macSignatureKeyInformation;
    }

    public String[] getAttributeNames()
    {
        return attributeNames;
    }

    public void setAttributeNames(String[] attributeNames)
    {
        this.attributeNames = attributeNames;
    }

    public KMIPEncodingOption getEncodingOption()
    {
        return encodingOption;
    }

    public void setEncodingOption(KMIPEncodingOption encodingOption)
    {
        this.encodingOption = encodingOption;
    }
}

