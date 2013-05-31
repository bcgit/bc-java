package javax.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The NullCipher class is a class that provides an
 * "identity cipher" -- one that does not tranform the plaintext.  As
 * a consequence, the ciphertext is identical to the plaintext.  All
 * initialization methods do nothing, while the blocksize is set to 1
 * byte.
 *
 * @since JCE1.2
 */
public class NullCipher
    extends Cipher
{
    static private class NullCipherSpi
        extends CipherSpi
    {
        /**
         * Sets the mode of this cipher - no op.
         */
        protected void engineSetMode(
            String  mode)
        throws NoSuchAlgorithmException
        {
        }
    
        /**
         * Sets the padding mechanism of this cipher - no op.
         */
        protected void engineSetPadding(
            String  padding)
        throws NoSuchPaddingException
        {
        }
    
        /**
         * Returns the block size (in bytes) - 1
         */
        protected int engineGetBlockSize()
        {
            return 1;
        }

        /**
         * Returns the length in bytes that an output buffer would
         * need to be in order to hold the result of the next <code>update</code>
         * or <code>doFinal</code> operation, given the input length
         * <code>inputLen</code> (in bytes).
         *
         * @param inputLen the input length (in bytes)
         * @return the required output buffer size (in bytes)
         */
        protected int engineGetOutputSize(
            int  inputLen)
        {
            return inputLen;
        }

        /**
         * Returns the initialization vector (IV) in a new buffer. 
         *
         * @return null
         */
        protected byte[] engineGetIV()
        {
            return null;
        }
    
        /**
         * Returns the parameters used with this cipher - null
         */
        protected AlgorithmParameters engineGetParameters()
        {
            return null;
        }

        /**
         * Initializes this cipher with a key and a source
         * of randomness - no op.
         */
        protected void engineInit(
            int             opmode,
            Key             key,
            SecureRandom    random)
        throws InvalidKeyException
        {
        }
    
        /**
         * Initializes this cipher with a key, a set of
         * algorithm parameters, and a source of randomness - no op.
         */
        protected void engineInit(
            int                     opmode,
            Key                     key,
            AlgorithmParameterSpec  params,
            SecureRandom            random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
        {
        }
    
        /**
         * Initializes this cipher with a key, a set of
         * algorithm parameters, and a source of randomness - no op.
         */
        protected void engineInit(
            int                 opmode,
            Key                 key,
            AlgorithmParameters params,
            SecureRandom        random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
        {
        }
    
        /**
         * Continues a multiple-part encryption or decryption operation
         * (depending on how this cipher was initialized), processing another data
         * part - in this case just return a copy of the input.
         */
        protected byte[] engineUpdate(
            byte[]      input,
            int         inputOffset,
            int         inputLen)
        {
            if (input == null)
            {
                return null;
            }

            byte[] tmp = new byte[inputLen];

            System.arraycopy(input, inputOffset, tmp, 0, inputLen);

            return tmp;
        }
    
        /**
         * Continues a multiple-part encryption or decryption operation
         * (depending on how this cipher was initialized), processing another data
         * part - in this case just copy the input to the output.
         */
        protected int engineUpdate(
            byte[]      input,
            int         inputOffset,
            int         inputLen,
            byte[]      output,
            int         outputOffset)
        throws ShortBufferException
        {
            if (input == null)
            {
                return 0;
            }

            if ((output.length - outputOffset) < inputLen)
            {
                throw new ShortBufferException("output buffer to short for NullCipher");
            }

            System.arraycopy(input, inputOffset, output, outputOffset, inputLen);

            return inputLen;
        }
    
        /**
         * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
         * The data is encrypted or decrypted, depending on how this cipher was initialized
         * - in this case just return a copy of the input.
         */
        protected byte[] engineDoFinal(
            byte[]      input,
            int         inputOffset,
            int         inputLen)
        throws IllegalBlockSizeException, BadPaddingException
        {
            if (input == null)
            {
                return new byte[0];
            }

            byte[] tmp = new byte[inputLen];

            System.arraycopy(input, inputOffset, tmp, 0, inputLen);

            return tmp;
        }

        /**
         * Encrypts or decrypts data in a single-part operation,
         * or finishes a multiple-part operation.
         * The data is encrypted or decrypted, depending on how this cipher was
         * initialized.
         */
        protected int engineDoFinal(
            byte[]      input,
            int         inputOffset,
            int         inputLen,
            byte[]      output,
            int         outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
        {
            if (input == null)
            {
                return 0;
            }

            if ((output.length - outputOffset) < inputLen)
            {
                throw new ShortBufferException("output buffer too short for NullCipher");
            }

            System.arraycopy(input, inputOffset, output, outputOffset, inputLen);

            return inputLen;
        }
    
        /**
         * Returns the key size of the given key object - 0
         */
        protected int engineGetKeySize(
            Key     key)
        throws InvalidKeyException
        {
            return 0;
        }
    }

    public NullCipher()
    {
        super(new NullCipherSpi(), null, "NULL");
    }
}
