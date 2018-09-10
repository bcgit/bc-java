package org.bouncycastle.pqc.crypto.qtesla;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class RandomNumberGenerator
{

    public static final short RANDOM_NUMBER_GENERATOR_SUCCESS = 0;
    public static final short RANDOM_NUMBER_GENERATOR_BAD_MAXIMUM_LENGTH = -1;
    public static final short RANDOM_NUMBER_GENERATOR_BAD_OUTPUT_BUFFER = -2;
    public static final short RANDOM_NUMBER_GENERATOR_BAD_REQUEST_LENGTH = -3;

    private AdvancedEncryptionStandard256CounterDeterministicRandomBitGenerator drbgse;

    public RandomNumberGenerator()
    {

        this.drbgse = new AdvancedEncryptionStandard256CounterDeterministicRandomBitGenerator();

    }

    /***************************************************************************************************************************************************************
     * Description:	Advanced-Encryption-Standard-256-application in Electronic Code Book mode
     *
     * @param        key:			256-bit Advanced-Encryption-Standard key
     * @param        plaintext:		128-bit plaintext value
     * @param        ciphertext:		128-bit ciphertext value
     *
     * @return none
     ***************************************************************************************************************************************************************/
    private void advancedEncryptionStandard256ElectronicCodeBook(byte[] key, byte[] plaintext, byte[] ciphertext, short ciphertextOffset)
        throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException
    {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, ciphertextOffset);

    }

    private void advancedEncryptionStandard256CounterDeterministicRandomBitGeneratorUpdate(byte[] providedData, byte[] key, byte[] value)
        throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException
    {

        byte[] temporary = new byte[48];

        for (short i = 0; i < 3; i++)
        {

            for (short j = 15; j >= 0; j--)
            {

                if (value[j] == 0xFF)
                {

                    value[j] = 0x00;

                }
                else
                {

                    value[j]++;

                    break;

                }

            }

            advancedEncryptionStandard256ElectronicCodeBook(key, value, temporary, (short)(16 * i));

        }

        if (providedData != null)
        {

            for (short i = 0; i < 48; i++)
            {

                temporary[i] ^= providedData[i];

            }

        }

        System.arraycopy(temporary, 0, key, 0, 32);
        System.arraycopy(temporary, 32, value, 0, 16);

    }

    /***************************************************************************************************************************************************************
     * Description:	Initiate the seed expander
     *
     * @param        stateOfSeedExpander:	Current state of an instance of the seed expander
     * @param        seed:					32-byte random value
     * @param        diversifier:			8-byte diversifier
     * @param        maximumLength:			Maximum number of bytes generated under "seed" and "diversifier"
     *
     * @return RANDOM_NUMBER_GENERATOR_SUCCESS
     ***************************************************************************************************************************************************************/
    public short initiateSeedExpander(

        AdvancedEncryptionStandardExtendableOutputFunction stateOfSeedExpander,
        byte[] seed,
        byte[] diversifier,
        long maximumLength)
    {

        if (maximumLength > 0xFFFFFFFFFL)
        {

            return RANDOM_NUMBER_GENERATOR_BAD_MAXIMUM_LENGTH;

        }

        stateOfSeedExpander.setRemainingLength(maximumLength);
        stateOfSeedExpander.setKey(seed, (short)0, (short)32);
        stateOfSeedExpander.setPlaintext(diversifier, (short)0, (short)8);
        stateOfSeedExpander.setPlaintextElement((short)11, (byte)(maximumLength % 256));
        maximumLength >>= Byte.SIZE;
        stateOfSeedExpander.setPlaintextElement((short)10, (byte)(maximumLength % 256));
        maximumLength >>= Byte.SIZE;
        stateOfSeedExpander.setPlaintextElement((short)9, (byte)(maximumLength % 256));
        maximumLength >>= Byte.SIZE;
        stateOfSeedExpander.setPlaintextElement((short)8, (byte)(maximumLength % 256));
        stateOfSeedExpander.setPlaintext((short)12, (short)4, (byte)0x0);
        stateOfSeedExpander.setBufferPosition((short)16);
        stateOfSeedExpander.setBuffer((short)0, (short)16, (byte)0x0);

        return RANDOM_NUMBER_GENERATOR_SUCCESS;

    }

    /***************************************************************************************************************************************************************
     * Description:	Seed expander
     *
     * @param        stateOfSeedExpander:			Current state of an instance of the seed expander
     * @param        extendableOutputFunctionData:	Data of the extendable output function
     * @param        numberOfByteToReturn
     *
     * @return RANDOM_NUMBER_GENERATOR_SUCCESS
     * 				RANDOM_NUMBER_GENERATOR_BAD_OUTPUT_BUFFER
     * 				RANDOM_NUMBER_GENERATOR_BAD_REQUEST_LENGTH
     ***************************************************************************************************************************************************************/
    public short seedExpander(AdvancedEncryptionStandardExtendableOutputFunction stateOfSeedExpander, byte[] extendableOutputFunctionData, long numberOfByteToReturn)

        throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException
    {

        int offset = 0;

        if (extendableOutputFunctionData == null)
        {

            return RANDOM_NUMBER_GENERATOR_BAD_OUTPUT_BUFFER;

        }

        if (numberOfByteToReturn >= stateOfSeedExpander.getRemainingLength())
        {

            return RANDOM_NUMBER_GENERATOR_BAD_REQUEST_LENGTH;

        }

        stateOfSeedExpander.setRemainingLength(stateOfSeedExpander.getRemainingLength() - numberOfByteToReturn);

        while (numberOfByteToReturn > 0)
        {

            if (numberOfByteToReturn <= (16 - stateOfSeedExpander.getBufferPosition()))
            {

                System.arraycopy(
                    extendableOutputFunctionData, offset,
                    stateOfSeedExpander.getBuffer(), stateOfSeedExpander.getBufferPosition(),
                    (int)numberOfByteToReturn
                );

                stateOfSeedExpander.setBufferPosition((int)(stateOfSeedExpander.getBufferPosition() + numberOfByteToReturn));

                return RANDOM_NUMBER_GENERATOR_SUCCESS;

            }

            System.arraycopy(
                stateOfSeedExpander.getBuffer(), stateOfSeedExpander.getBufferPosition(),
                extendableOutputFunctionData, offset,
                16 - stateOfSeedExpander.getBufferPosition()
            );

            numberOfByteToReturn -= 16 - stateOfSeedExpander.getBufferPosition();
            offset += 16 - stateOfSeedExpander.getBufferPosition();

            advancedEncryptionStandard256ElectronicCodeBook(
                stateOfSeedExpander.getKey(), stateOfSeedExpander.getPlaintext(), stateOfSeedExpander.getBuffer(), (short)0
            );

            stateOfSeedExpander.setBufferPosition((short)0);

            /* Increment the counter */
            for (short i = 15; i >= 12; i--)
            {

                if (stateOfSeedExpander.getPlaintextElement(i) == 0xFF)
                {

                    stateOfSeedExpander.setPlaintextElement(i, (byte)0x0);

                }
                else
                {

                    stateOfSeedExpander.setPlaintextElement(i, (byte)(stateOfSeedExpander.getPlaintextElement(i) + 1));
                    break;

                }

            }

        }

        return RANDOM_NUMBER_GENERATOR_SUCCESS;

    }

    public void initiateRandomByte(byte[] entropyInput, byte[] personalizationString, short securityStrength)
    {

        byte[] seedMaterial = new byte[48];

        System.arraycopy(entropyInput, 0, seedMaterial, 0, 48);

        if (personalizationString != null)
        {

            for (short i = 0; i < 48; i++)
            {

                seedMaterial[i] ^= personalizationString[i];

            }

        }

        this.drbgse.setKey(0, 32, (byte)0x0);

        this.drbgse.setValue(0, 16, (byte)0x0);

        try
        {
            advancedEncryptionStandard256CounterDeterministicRandomBitGeneratorUpdate(seedMaterial, this.drbgse.getKey(), this.drbgse.getValue());
        }
        catch (BadPaddingException e)
        {
            e.printStackTrace();
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }
        catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
        catch (ShortBufferException e)
        {
            e.printStackTrace();
        }

        this.drbgse.setReseedCounter((short)1);

    }

    public short randomByte(byte[] extendableOutputFunctionData, int extendableOutputFunctionDataOffset, int numberOfByteToReturn)
    {

        byte[] block = new byte[16];
        short i = 0;

        while (numberOfByteToReturn > 0)
        {

            for (short j = 15; j >= 0; j--)
            {

                if (this.drbgse.getValueElement((short)j) == 0xFF)
                {

                    this.drbgse.setValueElement((short)j, (byte)0x0);

                }
                else
                {

                    this.drbgse.setValueElement(j, (byte)(this.drbgse.getValueElement(j) + 1));

                    break;

                }

            }

            try
            {
                advancedEncryptionStandard256ElectronicCodeBook(this.drbgse.getKey(), this.drbgse.getValue(), block, (short)0);
            }
            catch (BadPaddingException e)
            {
                e.printStackTrace();
            }
            catch (IllegalBlockSizeException e)
            {
                e.printStackTrace();
            }
            catch (InvalidKeyException e)
            {
                e.printStackTrace();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
            catch (NoSuchPaddingException e)
            {
                e.printStackTrace();
            }
            catch (ShortBufferException e)
            {
                e.printStackTrace();
            }

            if (numberOfByteToReturn > 15)
            {

                System.arraycopy(extendableOutputFunctionData, extendableOutputFunctionDataOffset + i, block, 0, 16);
                i += 16;
                numberOfByteToReturn -= 16;

            }
            else
            {

                System.arraycopy(block, 0, extendableOutputFunctionData, extendableOutputFunctionDataOffset + i, numberOfByteToReturn);
                numberOfByteToReturn = 0;

            }

        }

        try
        {
            advancedEncryptionStandard256CounterDeterministicRandomBitGeneratorUpdate(null, this.drbgse.getKey(), this.drbgse.getValue());
        }
        catch (BadPaddingException e)
        {
            e.printStackTrace();
        }
        catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }
        catch (IllegalBlockSizeException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        catch (NoSuchPaddingException e)
        {
            e.printStackTrace();
        }
        catch (ShortBufferException e)
        {
            e.printStackTrace();
        }

        this.drbgse.setReseedCounter((short)(this.drbgse.getReseedCounter() + 1));

        return RANDOM_NUMBER_GENERATOR_SUCCESS;

    }

}
