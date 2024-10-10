package org.bouncycastle.crypto.split;

/**
 * Class representing the Cryptographic Parameters attribute structure.
 */
public class KMIPCryptographicParameters
{

    // Other Enums can be defined similarly: PaddingMethod, HashingAlgorithm, etc.

    private int blockCipherMode; // Block Cipher Mode
    private PaddingMethod paddingMethod; // Padding Method
    private int KMIPHashingAlgorithm; // Hashing Algorithm
    private int KMIPKeyRoleType; // Key Role Type
    private int digitalSignatureAlgorithm; // Digital Signature Algorithm
    private KMIPCryptographicAlgorithm KMIPCryptographicAlgorithm; // Cryptographic Algorithm
    private boolean randomIV; // Random IV
    private int ivLength; // IV Length
    private int tagLength; // Tag Length
    private int fixedFieldLength; // Fixed Field Length
    private int invocationFieldLength; // Invocation Field Length
    private int counterLength; // Counter Length
    private int initialCounterValue; // Initial Counter Value
    private int saltLength; // Salt Length
    private int maskGenerator; // Mask Generator
    private int maskGeneratorKMIPHashingAlgorithm; // Mask Generator Hashing Algorithm
    private byte[] pSource; // P Source
    private int trailerField; // Trailer Field

    // Constructor
    public KMIPCryptographicParameters()
    {
        // Default constructor
    }

    // Getters and Setters for each field

    public int getBlockCipherMode()
    {
        return blockCipherMode;
    }

    public void setBlockCipherMode(int blockCipherMode)
    {
        this.blockCipherMode = blockCipherMode;
    }

    public PaddingMethod getPaddingMethod()
    {
        return paddingMethod;
    }

    public void setPaddingMethod(PaddingMethod paddingMethod)
    {
        this.paddingMethod = paddingMethod;
    }

    public int getHashingAlgorithm()
    {
        return KMIPHashingAlgorithm;
    }

    public void setHashingAlgorithm(int KMIPHashingAlgorithm)
    {
        this.KMIPHashingAlgorithm = KMIPHashingAlgorithm;
    }

    public int getKeyRoleType()
    {
        return KMIPKeyRoleType;
    }

    public void setKeyRoleType(int KMIPKeyRoleType)
    {
        this.KMIPKeyRoleType = KMIPKeyRoleType;
    }

    public int getDigitalSignatureAlgorithm()
    {
        return digitalSignatureAlgorithm;
    }

    public void setDigitalSignatureAlgorithm(int digitalSignatureAlgorithm)
    {
        this.digitalSignatureAlgorithm = digitalSignatureAlgorithm;
    }

    public KMIPCryptographicAlgorithm getCryptographicAlgorithm()
    {
        return KMIPCryptographicAlgorithm;
    }

    public void setCryptographicAlgorithm(KMIPCryptographicAlgorithm KMIPCryptographicAlgorithm)
    {
        this.KMIPCryptographicAlgorithm = KMIPCryptographicAlgorithm;
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

    public int getMaskGenerator()
    {
        return maskGenerator;
    }

    public void setMaskGenerator(int maskGenerator)
    {
        this.maskGenerator = maskGenerator;
    }

    public int getMaskGeneratorHashingAlgorithm()
    {
        return maskGeneratorKMIPHashingAlgorithm;
    }

    public void setMaskGeneratorHashingAlgorithm(int maskGeneratorKMIPHashingAlgorithm)
    {
        this.maskGeneratorKMIPHashingAlgorithm = maskGeneratorKMIPHashingAlgorithm;
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

