package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

/**
 * GCM-SIV Mode.
 * <p>It should be noted that the specified limit of 2<sup>36</sup> bytes is not supported. This is because all bytes are
 * cached in a <b>ByteArrayOutputStream</b> object (which has a limit of a little less than 2<sup>31</sup> bytes),
 * and are output on the <b>doFinal</b>() call (which can only process a maximum of 2<sup>31</sup> bytes).</p>
 * <p>The practical limit of 2<sup>31</sup> - 24 bytes is policed, and attempts to breach the limit will be rejected</p>
 * <p>In order to properly support the higher limit, an extended form of <b>ByteArrayOutputStream</b> would be needed
 * which would use multiple arrays to store the data. In addition, a new <b>doOutput</b> method would be required (similar
 * to that in <b>XOF</b> digests), which would allow the data to be output over multiple calls. Alternatively an extended
 * form of <b>ByteArrayInputStream</b> could be used to deliver the data.</p>
 */
 public class GCMSIVBlockCipher
         implements AEADBlockCipher {
     /**
      * The buffer length.
      */
     private static final int BUFLEN = 16;

     /**
      * The halfBuffer length.
      */
     private static final int HALFBUFLEN = BUFLEN >> 1;

     /**
      * The nonce length.
      */
     private static final int NONCELEN = 12;

     /**
      * The maximum data length (AEAD/PlainText). Due to implementation constraints this is restricted to the maximum
      * array length (https://programming.guide/java/array-maximum-length.html) minus the BUFLEN to allow for the MAC
      */
     private static final int MAX_DATALEN = Integer.MAX_VALUE - 8 - BUFLEN;

     /**
      * The top bit mask.
      */
     private static final byte MASK = (byte) 0x80;

     /**
      * The addition constant.
      */
     private static final byte ADD = (byte) 0xE1;

     /**
      * The initialisation flag.
      */
     private static final int INIT = 1;

     /**
      * The aeadComplete flag.
      */
     private static final int AEAD_COMPLETE = 2;

     /**
      * The cipher.
      */
     private final BlockCipher theCipher;

     /**
      * The multiplier.
      */
     private final GCMMultiplier theMultiplier;

     /**
      * The gHash buffer.
      */
     private final byte[] theGHash = new byte[BUFLEN];

     /**
      * The reverse buffer.
      */
     private final byte[] theReverse = new byte[BUFLEN];

     /**
      * The aeadHasher.
      */
     private final GCMSIVHasher theAEADHasher;

     /**
      * The dataHasher.
      */
     private final GCMSIVHasher theDataHasher;

     /**
      * The plainDataStream.
      */
     private GCMSIVCache thePlain;

     /**
      * The encryptedDataStream (decryption only).
      */
     private GCMSIVCache theEncData;

     /**
      * Are we encrypting?
      */
     private boolean forEncryption;

     /**
      * The initialAEAD.
      */
     private byte[] theInitialAEAD;

     /**
      * The nonce.
      */
     private byte[] theNonce;

     /**
      * The flags.
      */
     private int theFlags;

     // defined fixed
     private byte[]      macBlock = new byte[16];

     /**
      * Constructor.
      */
     public GCMSIVBlockCipher()
     {
         this(new AESEngine());
     }

     /**
      * Constructor.
      * @param pCipher the underlying cipher
      */
     public GCMSIVBlockCipher(final BlockCipher pCipher)
     {
         this(pCipher, new Tables4kGCMMultiplier());
     }

     /**
      * Constructor.
      * @param pCipher the underlying cipher
      * @param pMultiplier the multiplier
      */
     public GCMSIVBlockCipher(final BlockCipher pCipher,
                              final GCMMultiplier pMultiplier)
     {
         /* Ensure that the cipher is the correct size */
         if (pCipher.getBlockSize() != BUFLEN)
         {
             throw new IllegalArgumentException("Cipher required with a block size of " + BUFLEN + ".");
         }

         /* Store parameters */
         theCipher = pCipher;
         theMultiplier = pMultiplier;

         /* Create the hashers */
         theAEADHasher = new GCMSIVHasher();
         theDataHasher = new GCMSIVHasher();
     }

     public BlockCipher getUnderlyingCipher()
     {
         return theCipher;
     }

     public void init(final boolean pEncrypt,
                      final CipherParameters cipherParameters) throws IllegalArgumentException
     {
         /* Set defaults */
         byte[] myInitialAEAD = null;
         byte[] myNonce = null;
         KeyParameter myKey = null;

         /* Access parameters */
         if (cipherParameters instanceof AEADParameters)
         {
             final AEADParameters myAEAD = (AEADParameters) cipherParameters;
             myInitialAEAD = myAEAD.getAssociatedText();
             myNonce = myAEAD.getNonce();
             myKey = myAEAD.getKey();
         }
         else if (cipherParameters instanceof ParametersWithIV)
         {
             final ParametersWithIV myParms = (ParametersWithIV) cipherParameters;
             myNonce = myParms.getIV();
             myKey = (KeyParameter) myParms.getParameters();
         }
         else
         {
             throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
         }

         /* Check nonceSize */
         if (myNonce == null || myNonce.length != NONCELEN)
         {
             throw new IllegalArgumentException("Invalid nonce");
         }

         /* Check keysize */
         if (myKey == null
             || (myKey.getKey().length != BUFLEN
                 && myKey.getKey().length != (BUFLEN << 1)))
         {
             throw new IllegalArgumentException("Invalid key");
         }

         /* Reset details */
         forEncryption = pEncrypt;
         theInitialAEAD = myInitialAEAD;
         theNonce = myNonce;

         /* Initialise the keys */
         deriveKeys(myKey);
         resetStreams();
     }

     public String getAlgorithmName()
     {
         return theCipher.getAlgorithmName() + "-GCM-SIV";
     }

     /**
      * check AEAD status.
      * @param pLen the aeadLength
      */
     private void checkAEADStatus(final int pLen)
     {
         /* Check we are initialised */
         if ((theFlags & INIT) == 0)
         {
             throw new IllegalStateException("Cipher is not initialised");
         }

         /* Check AAD is allowed */
         if ((theFlags & AEAD_COMPLETE) != 0)
         {
             throw new IllegalStateException("AEAD data cannot be processed after ordinary data");
         }

         /* Make sure that we haven't breached AEAD data limit */
         if (theAEADHasher.getBytesProcessed() + Long.MIN_VALUE
              > (MAX_DATALEN - pLen) + Long.MIN_VALUE)
         {
             throw new IllegalStateException("AEAD byte count exceeded");
         }
     }

     /**
      * check status.
      * @param pLen the dataLength
      */
     private void checkStatus(final int pLen)
     {
         /* Check we are initialised */
         if ((theFlags & INIT) == 0)
         {
             throw new IllegalStateException("Cipher is not initialised");
         }

         /* Complete the AEAD section if this is the first data */
         if ((theFlags & AEAD_COMPLETE) == 0)
         {
             theAEADHasher.completeHash();
             theFlags |= AEAD_COMPLETE;
         }

         /* Make sure that we haven't breached data limit */
         long dataLimit = MAX_DATALEN;
         long currBytes = thePlain.size();
         if (!forEncryption)
         {
             dataLimit += BUFLEN;
             currBytes = theEncData.size();
         }
         if (currBytes + Long.MIN_VALUE
               > (dataLimit - pLen) + Long.MIN_VALUE)
         {
             throw new IllegalStateException("byte count exceeded");
         }
     }

     public void processAADByte(final byte pByte)
     {
         /* Check that we can supply AEAD */
         checkAEADStatus(1);

         /* Process the aead */
         theAEADHasher.updateHash(pByte);
     }

     public void processAADBytes(final byte[] pData,
                                 final int pOffset,
                                 final int pLen)
     {
         /* Check that we can supply AEAD */
         checkAEADStatus(pLen);

         /* Check input buffer */
         checkBuffer(pData, pOffset, pLen, false);

         /* Process the aead */
         theAEADHasher.updateHash(pData, pOffset, pLen);
     }

     public int processByte(final byte pByte,
                            final byte[] pOutput,
                            final int pOutOffset) throws DataLengthException
     {
         /* Check that we have initialised */
         checkStatus(1);

         /* Store the data */
         if (forEncryption)
         {
             thePlain.write(pByte);
             theDataHasher.updateHash(pByte);
         }
         else
         {
             theEncData.write(pByte);
         }

         /* No data returned */
         return 0;
     }

     public int processBytes(final byte[] pData,
                             final int pOffset,
                             final int pLen,
                             final byte[] pOutput,
                             final int pOutOffset) throws DataLengthException
     {
         /* Check that we have initialised */
         checkStatus(pLen);

         /* Check input buffer */
         checkBuffer(pData, pOffset, pLen, false);

         /* Store the data */
         if (forEncryption)
         {
             thePlain.write(pData, pOffset, pLen);
             theDataHasher.updateHash(pData, pOffset, pLen);
         }
         else
         {
             theEncData.write(pData, pOffset, pLen);
         }

         /* No data returned */
         return 0;
     }

     public int doFinal(final byte[] pOutput,
                        final int pOffset) throws IllegalStateException, InvalidCipherTextException
     {
         /* Check that we have initialised */
         checkStatus(0);

         /* Check output buffer */
         checkBuffer(pOutput, pOffset, getOutputSize(0), true);

         /* If we are encrypting */
         if (forEncryption)
         {
             /* Derive the tag */
             final byte[] myTag = calculateTag();

             /* encrypt the plain text */
             final int myDataLen = BUFLEN + encryptPlain(myTag, pOutput, pOffset);

             /* Add the tag to the output */
             System.arraycopy(myTag, 0, pOutput, pOffset + thePlain.size(), BUFLEN);

             System.arraycopy(myTag, 0, macBlock, 0, macBlock.length);

             /* Reset the streams */
             resetStreams();
             return myDataLen;

             /* else we are decrypting */
         }
         else
         {
             /* decrypt to plain text */
             decryptPlain();

             /* Release plain text */
             final int myDataLen = thePlain.size();
             final byte[] mySrc = thePlain.getBuffer();
             System.arraycopy(mySrc, 0, pOutput, pOffset, myDataLen);

             /* Reset the streams */
             resetStreams();
             return myDataLen;
         }
     }

     public byte[] getMac()
     {
         return Arrays.clone(macBlock);
     }

     public int getUpdateOutputSize(final int pLen)
     {
         return 0;
     }

     public int getOutputSize(final int pLen)
     {
         if (forEncryption) {
             return pLen + thePlain.size() + BUFLEN;
         }
         final int myCurr = pLen + theEncData.size();
         return myCurr > BUFLEN ? myCurr - BUFLEN : 0;
     }

     public void reset()
     {
         resetStreams();
     }

     /**
      * Reset Streams.
      */
     private void resetStreams()
     {
         /* Clear the plainText buffer */
         if (thePlain != null)
         {
             thePlain.clearBuffer();
         }

         /* Reset hashers */
         theAEADHasher.reset();
         theDataHasher.reset();

         /* Recreate streams (to release memory) */
         thePlain = new GCMSIVCache();
         theEncData = forEncryption ? null : new GCMSIVCache();

         /* Initialise AEAD if required */
         theFlags &= ~AEAD_COMPLETE;
         Arrays.fill(theGHash, (byte) 0);
         if (theInitialAEAD != null)
         {
             theAEADHasher.updateHash(theInitialAEAD, 0, theInitialAEAD.length);
         }
      }

     /**
      * Obtain buffer length (allowing for null).
      * @param pBuffer the buffere
      * @return the length
      */
     private static int bufLength(final byte[] pBuffer)
     {
         return pBuffer == null ? 0 : pBuffer.length;
     }

     /**
      * Check buffer.
      * @param pBuffer the buffer
      * @param pOffset the offset
      * @param pLen the length
      * @param pOutput is this an output buffer?
      */
     private static void checkBuffer(final byte[] pBuffer,
                                     final int pOffset,
                                     final int pLen,
                                     final boolean pOutput)
     {
         /* Access lengths */
         final int myBufLen = bufLength(pBuffer);
         final int myLast = pOffset + pLen;

         /* Check for negative values and buffer overflow */
         final boolean badLen = pLen < 0 || pOffset < 0 || myLast < 0;
         if (badLen || myLast > myBufLen)
         {
             throw pOutput
                     ? new OutputLengthException("Output buffer too short.")
                     : new DataLengthException("Input buffer too short.");
         }
     }

     /**
      * encrypt data stream.
      * @param pCounter the counter
      * @param pTarget the target buffer
      * @param pOffset the target offset
      * @return the length of data encrypted
      */
     private int encryptPlain(final byte[] pCounter,
                              final byte[] pTarget,
                              final int pOffset)
     {
         /* Access buffer and length */
         final byte[] mySrc = thePlain.getBuffer();
         final byte[] myCounter = Arrays.clone(pCounter);
         myCounter[BUFLEN - 1] |= MASK;
         final byte[] myMask = new byte[BUFLEN];
         int myRemaining = thePlain.size();
         int myOff = 0;

         /* While we have data to process */
         while (myRemaining > 0)
         {
             /* Generate the next mask */
             theCipher.processBlock(myCounter, 0, myMask, 0);

             /* Xor data into mask */
             final int myLen = Math.min(BUFLEN, myRemaining);
             xorBlock(myMask, mySrc, myOff, myLen);

             /* Copy encrypted data to output */
             System.arraycopy(myMask, 0, pTarget, pOffset + myOff, myLen);

             /* Adjust counters */
             myRemaining -= myLen;
             myOff += myLen;
             incrementCounter(myCounter);
         }

         /* Return the amount of data processed */
         return thePlain.size();
     }

     /**
      * decrypt data stream.
      * @throws InvalidCipherTextException on data too short or mac check failed
      */
     private void decryptPlain() throws InvalidCipherTextException
     {
         /* Access buffer and length */
         final byte[] mySrc = theEncData.getBuffer();
         int myRemaining = theEncData.size() - BUFLEN;

         /* Check for insufficient data */
         if (myRemaining < 0)
         {
             throw new InvalidCipherTextException("Data too short");
         }

         /* Access counter */
         final byte[] myExpected = Arrays.copyOfRange(mySrc, myRemaining, myRemaining + BUFLEN);
         final byte[] myCounter = Arrays.clone(myExpected);
         myCounter[BUFLEN - 1] |= MASK;
         final byte[] myMask = new byte[BUFLEN];
         int myOff = 0;

         /* While we have data to process */
         while (myRemaining > 0)
         {
             /* Generate the next mask */
             theCipher.processBlock(myCounter, 0, myMask, 0);

             /* Xor data into mask */
             final int myLen = Math.min(BUFLEN, myRemaining);
             xorBlock(myMask, mySrc, myOff, myLen);

             /* Write data to plain dataStream */
             thePlain.write(myMask, 0, myLen);
             theDataHasher.updateHash(myMask, 0, myLen);

             /* Adjust counters */
             myRemaining -= myLen;
             myOff += myLen;
             incrementCounter(myCounter);
         }

         /* Derive and check the tag */
         final byte[] myTag = calculateTag();
         if (!Arrays.constantTimeAreEqual(myTag, myExpected))
         {
             reset();
             throw new InvalidCipherTextException("mac check failed");
         }

         System.arraycopy(myTag, 0, macBlock, 0, macBlock.length);
     }

     /**
      * calculate tag.
      * @return the calculated tag
      */
     private byte[] calculateTag()
     {
         /* Complete the hash */
         theDataHasher.completeHash();
         final byte[] myPolyVal = completePolyVal();

         /* calculate polyVal */
         final byte[] myResult = new byte[BUFLEN];

         /* Fold in the nonce */
         for (int i = 0; i < NONCELEN; i++)
         {
             myPolyVal[i] ^= theNonce[i];
         }

         /* Clear top bit */
         myPolyVal[BUFLEN - 1] &= (MASK - 1);

         /* Calculate tag and return it */
         theCipher.processBlock(myPolyVal, 0, myResult, 0);
         return myResult;
     }

     /**
      * complete polyVAL.
      * @return the calculated value
      */
     private byte[] completePolyVal()
     {
         /* Build the polyVal result */
         final byte[] myResult = new byte[BUFLEN];
         gHashLengths();
         fillReverse(theGHash, 0, BUFLEN, myResult);
         return myResult;
     }

     /**
      * process lengths.
      */
     private void gHashLengths()
     {
         /* Create reversed bigEndian buffer to keep it simple */
         final byte[] myIn = new byte[BUFLEN];
         Pack.longToBigEndian(Bytes.SIZE * theDataHasher.getBytesProcessed(), myIn, 0);
         Pack.longToBigEndian(Bytes.SIZE * theAEADHasher.getBytesProcessed(), myIn, Longs.BYTES);

         /* hash value */
         gHASH(myIn);
     }

     /**
      * perform the next GHASH step.
      * @param pNext the next value
      */
     private void gHASH(final byte[] pNext)
     {
         xorBlock(theGHash, pNext);
         theMultiplier.multiplyH(theGHash);
     }

     /**
      * Byte reverse a buffer.
      * @param pInput the input buffer
      * @param pOffset the offset
      * @param pLength the length of data (<= BUFLEN)
      * @param pOutput the output buffer
      */
     private static void fillReverse(final byte[] pInput,
                                     final int pOffset,
                                     final int pLength,
                                     final byte[] pOutput)
     {
         /* Loop through the buffer */
         for (int i = 0, j = BUFLEN - 1; i < pLength; i++, j--)
         {
             /* Copy byte */
             pOutput[j] = pInput[pOffset + i];
         }
     }

     /**
      * xor a full block buffer.
      * @param pLeft the left operand and result
      * @param pRight the right operand
      */
     private static void xorBlock(final byte[] pLeft,
                                  final byte[] pRight)
     {
         /* Loop through the bytes */
         for (int i = 0; i < BUFLEN; i++)
         {
             pLeft[i] ^= pRight[i];
         }
     }

     /**
      * xor a partial block buffer.
      * @param pLeft the left operand and result
      * @param pRight the right operand
      * @param pOffset the offset in the right operand
      * @param pLength the length of data in the right operand
      */
     private static void xorBlock(final byte[] pLeft,
                                  final byte[] pRight,
                                  final int pOffset,
                                  final int pLength)
                                  {
         /* Loop through the bytes */
         for (int i = 0; i < pLength; i++)
         {
             pLeft[i] ^= pRight[i + pOffset];
         }
     }

     /**
      * increment the counter.
      * @param pCounter the counter to increment
      */
     private static void incrementCounter(final byte[] pCounter)
     {
         /* Loop through the bytes incrementing counter */
         for (int i = 0; i < Integers.BYTES; i++)
         {
             if (++pCounter[i] != 0)
             {
                 break;
             }
         }
     }

     /**
      * multiply by X.
      * @param pValue the value to adjust
      */
     private static void mulX(final byte[] pValue)
     {
         /* Loop through the bytes */
         byte myMask = (byte) 0;
         for (int i = 0; i < BUFLEN; i++)
         {
             final byte myValue = pValue[i];
             pValue[i] = (byte) (((myValue >> 1) & ~MASK) | myMask);
             myMask = (myValue & 1) == 0 ? 0 : MASK;
         }

         /* Xor in addition if last bit was set */
         if (myMask != 0)
         {
             pValue[0] ^= ADD;
         }
     }

     /**
      * Derive Keys.
      * @param pKey the keyGeneration key
      */
     private void deriveKeys(final KeyParameter pKey)
     {
         /* Create the buffers */
         final byte[] myIn = new byte[BUFLEN];
         final byte[] myOut = new byte[BUFLEN];
         final byte[] myResult = new byte[BUFLEN];
         final byte[] myEncKey = new byte[pKey.getKey().length];

         /* Prepare for encryption */
         System.arraycopy(theNonce, 0, myIn, BUFLEN - NONCELEN, NONCELEN);
         theCipher.init(true, pKey);

         /* Derive authentication key */
         int myOff = 0;
         theCipher.processBlock(myIn, 0, myOut, 0);
         System.arraycopy(myOut, 0, myResult, myOff, HALFBUFLEN);
         myIn[0]++;
         myOff += HALFBUFLEN;
         theCipher.processBlock(myIn, 0, myOut, 0);
         System.arraycopy(myOut, 0, myResult, myOff, HALFBUFLEN);

         /* Derive encryption key */
         myIn[0]++;
         myOff = 0;
         theCipher.processBlock(myIn, 0, myOut, 0);
         System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
         myIn[0]++;
         myOff += HALFBUFLEN;
         theCipher.processBlock(myIn, 0, myOut, 0);
         System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);

         /* If we have a 32byte key */
         if (myEncKey.length == BUFLEN << 1)
         {
             /* Derive remainder of encryption key */
             myIn[0]++;
             myOff += HALFBUFLEN;
             theCipher.processBlock(myIn, 0, myOut, 0);
             System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
             myIn[0]++;
             myOff += HALFBUFLEN;
             theCipher.processBlock(myIn, 0, myOut, 0);
             System.arraycopy(myOut, 0, myEncKey, myOff, HALFBUFLEN);
         }

         /* Initialise the Cipher */
         theCipher.init(true, new KeyParameter(myEncKey));

         /* Initialise the multiplier */
         fillReverse(myResult, 0, BUFLEN, myOut);
         mulX(myOut);
         theMultiplier.init(myOut);
         theFlags |= INIT;
     }

     /**
      * GCMSIVCache.
      */
     private static class GCMSIVCache
             extends ByteArrayOutputStream
     {
         /**
          * Constructor.
          */
         GCMSIVCache()
         {
         }

         /**
          * Obtain the buffer.
          * @return the buffer
          */
         byte[] getBuffer()
         {
             return this.buf;
         }

         /**
          * Clear the buffer.
          */
         void clearBuffer()
         {
             Arrays.fill(getBuffer(), (byte) 0);
         }
     }

     /**
      * Hash Control.
      */
     private class GCMSIVHasher
     {
         /**
          * Cache.
          */
         private final byte[] theBuffer = new byte[BUFLEN];

         /**
          * Single byte cache.
          */
         private final byte[] theByte = new byte[1];

         /**
          * Count of active bytes in cache.
          */
         private int numActive;

         /**
          * Count of hashed bytes.
          */
         private long numHashed;

         /**
          * Obtain the count of bytes hashed.
          * @return the count
          */
         long getBytesProcessed()
         {
             return numHashed;
         }

         /**
          * Reset the hasher.
          */
         void reset()
         {
             numActive = 0;
             numHashed = 0;
         }

         /**
          * update hash.
          * @param pByte the byte
          */
         void updateHash(final byte pByte)
         {
             theByte[0] = pByte;
             updateHash(theByte, 0, 1);
         }

         /**
          * update hash.
          * @param pBuffer the buffer
          * @param pOffset the offset within the buffer
          * @param pLen the length of data
          */
         void updateHash(final byte[] pBuffer,
                         final int pOffset,
                         final int pLen)
         {
             /* If we should process the cache */
             final int mySpace = BUFLEN - numActive;
             int numProcessed = 0;
             int myRemaining = pLen;
             if (numActive > 0
                     && pLen >= mySpace)
             {
                 /* Copy data into the cache and hash it */
                 System.arraycopy(pBuffer, pOffset, theBuffer, numActive, mySpace);
                 fillReverse(theBuffer, 0, BUFLEN, theReverse);
                 gHASH(theReverse);

                 /* Adjust counters */
                 numProcessed += mySpace;
                 myRemaining -= mySpace;
                 numActive = 0;
             }

             /* While we have full blocks */
             while (myRemaining >= BUFLEN)
             {
                 /* Access the next data */
                 fillReverse(pBuffer, pOffset + numProcessed, BUFLEN, theReverse);
                 gHASH(theReverse);

                 /* Adjust counters */
                 numProcessed += mySpace;
                 myRemaining -= mySpace;
             }

             /* If we have remaining data */
             if (myRemaining > 0)
             {
                 /* Copy data into the cache */
                 System.arraycopy(pBuffer, pOffset + numProcessed, theBuffer, numActive, myRemaining);
                 numActive += myRemaining;
             }

             /* Adjust the number of bytes processed */
             numHashed += pLen;
         }

         /**
          * complete hash.
          */
         void completeHash()
         {
             /* If we have remaining data */
             if (numActive > 0)
             {
                 /* Access the next data */
                 Arrays.fill(theReverse, (byte) 0);
                 fillReverse(theBuffer, 0, numActive, theReverse);

                 /* hash value */
                 gHASH(theReverse);
             }
         }
     }
 }
