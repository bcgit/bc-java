package org.bouncycastle.kmip.wire.object;

import org.bouncycastle.kmip.wire.enumeration.KMIPBlockCipherMode;
import org.bouncycastle.kmip.wire.enumeration.KMIPCryptographicAlgorithm;
import org.bouncycastle.kmip.wire.enumeration.KMIPDigitalSignatureAlgorithm;
import org.bouncycastle.kmip.wire.enumeration.KMIPHashingAlgorithm;
import org.bouncycastle.kmip.wire.enumeration.KMIPKeyRoleType;
import org.bouncycastle.kmip.wire.enumeration.KMIPMaskGenerator;
import org.bouncycastle.kmip.wire.enumeration.KMIPPaddingMethod;

/**
 * Class representing the Cryptographic Parameters attribute structure.
 */
public class KMIPCryptographicParameters
{
    private KMIPBlockCipherMode blockCipherMode; // Block Cipher Mode
    private org.bouncycastle.kmip.wire.enumeration.KMIPPaddingMethod KMIPPaddingMethod; // Padding Method
    private KMIPHashingAlgorithm hashingAlgorithm; // Hashing Algorithm
    private KMIPKeyRoleType keyRoleType; // Key Role Type
    private KMIPDigitalSignatureAlgorithm digitalSignatureAlgorithm; // Digital Signature Algorithm
    private KMIPCryptographicAlgorithm cryptographicAlgorithm; // Cryptographic Algorithm
    private boolean randomIV; // Random IV
    private int ivLength; // IV Length
    private int tagLength; // Tag Length
    private int fixedFieldLength; // Fixed Field Length
    private int invocationFieldLength; // Invocation Field Length
    private int counterLength; // Counter Length
    private int initialCounterValue; // Initial Counter Value
    private int saltLength; // Salt Length
    private KMIPMaskGenerator maskGenerator; // Mask Generator
    private KMIPHashingAlgorithm maskGeneratorHashingAlgorithm; // Mask Generator Hashing Algorithm
    private byte[] pSource; // P Source
    private int trailerField; // Trailer Field

    // Constructor
    public KMIPCryptographicParameters()
    {
        // Default constructor
    }

    // Getters and Setters for each field

    public KMIPBlockCipherMode getBlockCipherMode()
    {
        return blockCipherMode;
    }

    public void setBlockCipherMode(KMIPBlockCipherMode blockCipherMode)
    {
        this.blockCipherMode = blockCipherMode;
    }

    public KMIPPaddingMethod getPaddingMethod()
    {
        return KMIPPaddingMethod;
    }

    public void setPaddingMethod(KMIPPaddingMethod KMIPPaddingMethod)
    {
        this.KMIPPaddingMethod = KMIPPaddingMethod;
    }

    public KMIPHashingAlgorithm getHashingAlgorithm()
    {
        return hashingAlgorithm;
    }

    public void setHashingAlgorithm(KMIPHashingAlgorithm hashingAlgorithm)
    {
        this.hashingAlgorithm = hashingAlgorithm;
    }

    public KMIPKeyRoleType getKeyRoleType()
    {
        return keyRoleType;
    }

    public void setKeyRoleType(KMIPKeyRoleType KMIPKeyRoleType)
    {
        this.keyRoleType = KMIPKeyRoleType;
    }

    public KMIPDigitalSignatureAlgorithm getDigitalSignatureAlgorithm()
    {
        return digitalSignatureAlgorithm;
    }

    public void setDigitalSignatureAlgorithm(KMIPDigitalSignatureAlgorithm digitalSignatureAlgorithm)
    {
        this.digitalSignatureAlgorithm = digitalSignatureAlgorithm;
    }

    public KMIPCryptographicAlgorithm getCryptographicAlgorithm()
    {
        return cryptographicAlgorithm;
    }

    public void setCryptographicAlgorithm(KMIPCryptographicAlgorithm cryptographicAlgorithm)
    {
        this.cryptographicAlgorithm = cryptographicAlgorithm;
    }

    public boolean getRandomIV()
    {
        return randomIV;
    }

    public void setRandomIV(boolean randomIV)
    {
        this.randomIV = randomIV;
    }

    public int getIvLength()
    {
        return ivLength;
    }

    public void setIvLength(int ivLength)
    {
        this.ivLength = ivLength;
    }

    public int getTagLength()
    {
        return tagLength;
    }

    public void setTagLength(int tagLength)
    {
        this.tagLength = tagLength;
    }

    public int getFixedFieldLength()
    {
        return fixedFieldLength;
    }

    public void setFixedFieldLength(int fixedFieldLength)
    {
        this.fixedFieldLength = fixedFieldLength;
    }

    public int getInvocationFieldLength()
    {
        return invocationFieldLength;
    }

    public void setInvocationFieldLength(int invocationFieldLength)
    {
        this.invocationFieldLength = invocationFieldLength;
    }

    public int getCounterLength()
    {
        return counterLength;
    }

    public void setCounterLength(int counterLength)
    {
        this.counterLength = counterLength;
    }

    public int getInitialCounterValue()
    {
        return initialCounterValue;
    }

    public void setInitialCounterValue(int initialCounterValue)
    {
        this.initialCounterValue = initialCounterValue;
    }

    public int getSaltLength()
    {
        return saltLength;
    }

    public void setSaltLength(int saltLength)
    {
        this.saltLength = saltLength;
    }

    public KMIPMaskGenerator getMaskGenerator()
    {
        return maskGenerator;
    }

    public void setMaskGenerator(KMIPMaskGenerator maskGenerator)
    {
        this.maskGenerator = maskGenerator;
    }

    public KMIPHashingAlgorithm getMaskGeneratorHashingAlgorithm()
    {
        return maskGeneratorHashingAlgorithm;
    }

    public void setMaskGeneratorHashingAlgorithm(KMIPHashingAlgorithm maskGeneratorKMIPHashingAlgorithm)
    {
        this.maskGeneratorHashingAlgorithm = maskGeneratorKMIPHashingAlgorithm;
    }

    public byte[] getPSource()
    {
        return pSource;
    }

    public void setPSource(byte[] pSource)
    {
        this.pSource = pSource;
    }

    public int getTrailerField()
    {
        return trailerField;
    }

    public void setTrailerField(int trailerField)
    {
        this.trailerField = trailerField;
    }
}

