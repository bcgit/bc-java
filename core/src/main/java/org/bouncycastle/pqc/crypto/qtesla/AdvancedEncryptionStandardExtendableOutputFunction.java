package org.bouncycastle.pqc.crypto.qtesla;

import java.util.Arrays;

public class AdvancedEncryptionStandardExtendableOutputFunction
{

    private byte[] buffer;
    private int bufferPosition;
    private long remainingLength;
    private byte[] key;
    private byte[] plaintext;

    public AdvancedEncryptionStandardExtendableOutputFunction()
    {

        this.buffer = new byte[16];
        this.key = new byte[32];
        this.plaintext = new byte[16];

    }

    public int getBufferPosition()
    {

        return this.bufferPosition;

    }

    public void setBufferPosition(int bufferPosition)
    {

        this.bufferPosition = bufferPosition;

    }

    public long getRemainingLength()
    {

        return this.remainingLength;

    }

    public void setRemainingLength(long remainingLength)
    {

        this.remainingLength = remainingLength;

    }

    public byte[] getBuffer()
    {

        return this.buffer;

    }

    /**********************************************************************************************
     * Description:	Set A Part of Buffer to "character"
     *
     * @param        offset        Starting Point of the Buffer
     * @param        length        Length of the Buffer to be Set
     * @param        character    Content to be Set
     *
     * @return none
     **********************************************************************************************/
    public void setBuffer(int bufferOffset, int length, byte character)
    {

        Arrays.fill(this.buffer, bufferOffset, bufferOffset + length, character);

    }

    public byte[] getKey()
    {

        return this.key;

    }

    /**********************************************************************************************
     * Description:	Copy A Part of the Source Key to A Part of the Destination Key
     *
     * @param        key            Source Key
     * @param        keyOffset    Starting Point of the Source and Destination Key
     * @param        length        Length of the Part to be Copied
     *
     * @return none
     **********************************************************************************************/
    public void setKey(byte[] key, short keyOffset, short length)
    {

        System.arraycopy(this.key, keyOffset, plaintext, keyOffset, length);

    }

    public byte[] getPlaintext()
    {

        return this.plaintext;

    }

    /**********************************************************************************************
     * Description:	Set A Part of Plaintext to "character"
     *
     * @param        offset        Starting Point of the Plaintext
     * @param        length        Length of the Plaintext to be Set
     * @param        character    Content to be Set
     *
     * @return none
     **********************************************************************************************/
    public void setPlaintext(int plaintextOffset, int length, byte character)
    {

        Arrays.fill(this.plaintext, plaintextOffset, plaintextOffset + length, character);

    }

    /*************************************************************************************************
     * Description:	Copy A Part of the Source Plaintext to A Part of the Destination Plaintext
     *
     * @param        key            Source Plaintext
     * @param        keyOffset    Starting Point of the Source and Destination Plaintext
     * @param        length        Length of the Part to be Copied
     *
     * @return none
     *************************************************************************************************/
    public void setPlaintext(byte[] plaintext, short plaintextOffset, short length)
    {

        System.arraycopy(this.plaintext, plaintextOffset, plaintext, plaintextOffset, length);

    }

    /**********************************************************************************************
     * Description:	Get An Element of Plaintext with A Certain Index
     *
     * @param        index
     *
     * @return The (index + 1)-th Element of Plaintext
     **********************************************************************************************/
    public byte getPlaintextElement(short index)
    {

        return this.plaintext[index];

    }

    /**********************************************************************************************
     * Description:	Set An Element of Plaintext with A Certain Index to "character"
     *
     * @param        index
     * @param        character    Content to be Set
     *
     * @return none
     **********************************************************************************************/
    public void setPlaintextElement(short index, byte character)
    {

        this.plaintext[index] = character;

    }

}
