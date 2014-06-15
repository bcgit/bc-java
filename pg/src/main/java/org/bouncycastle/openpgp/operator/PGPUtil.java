package org.bouncycastle.openpgp.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Strings;

/**
 * Basic utility class
 */
class PGPUtil
    implements HashAlgorithmTags
{
    static byte[] makeKeyFromPassPhrase(
        PGPDigestCalculator digestCalculator,
        int     algorithm,
        S2K     s2k,
        char[]  passPhrase)
        throws PGPException
    {
        // TODO: Never used
        String    algName = null;
        int        keySize = 0;

        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            keySize = 192;
            algName = "DES_EDE";
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            keySize = 128;
            algName = "IDEA";
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            keySize = 128;
            algName = "CAST5";
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            keySize = 128;
            algName = "Blowfish";
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            keySize = 128;
            algName = "SAFER";
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            algName = "DES";
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            keySize = 128;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            keySize = 192;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            keySize = 256;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            algName = "Twofish";
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            keySize = 128;
            algName = "Camellia";
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            keySize = 192;
            algName = "Camellia";
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            keySize = 256;
            algName = "Camellia";
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        byte[]    pBytes = Strings.toUTF8ByteArray(passPhrase);
        byte[]    keyBytes = new byte[(keySize + 7) / 8];

        int    generatedBytes = 0;
        int    loopCount = 0;

        if (s2k != null)
        {
            if (s2k.getHashAlgorithm() != digestCalculator.getAlgorithm())
            {
                throw new PGPException("s2k/digestCalculator mismatch");
            }
        }
        else
        {
            if (digestCalculator.getAlgorithm() != HashAlgorithmTags.MD5)
            {
                throw new PGPException("digestCalculator not for MD5");
            }
        }

        OutputStream dOut = digestCalculator.getOutputStream();

        try
        {
            while (generatedBytes < keyBytes.length)
            {
                if (s2k != null)
                {
                    for (int i = 0; i != loopCount; i++)
                    {
                        dOut.write(0);
                    }

                    byte[]    iv = s2k.getIV();

                    switch (s2k.getType())
                    {
                    case S2K.SIMPLE:
                        dOut.write(pBytes);
                        break;
                    case S2K.SALTED:
                        dOut.write(iv);
                        dOut.write(pBytes);
                        break;
                    case S2K.SALTED_AND_ITERATED:
                        long    count = s2k.getIterationCount();
                        dOut.write(iv);
                        dOut.write(pBytes);

                        count -= iv.length + pBytes.length;

                        while (count > 0)
                        {
                            if (count < iv.length)
                            {
                                dOut.write(iv, 0, (int)count);
                                break;
                            }
                            else
                            {
                                dOut.write(iv);
                                count -= iv.length;
                            }

                            if (count < pBytes.length)
                            {
                                dOut.write(pBytes, 0, (int)count);
                                count = 0;
                            }
                            else
                            {
                                dOut.write(pBytes);
                                count -= pBytes.length;
                            }
                        }
                        break;
                    default:
                        throw new PGPException("unknown S2K type: " + s2k.getType());
                    }
                }
                else
                {
                    for (int i = 0; i != loopCount; i++)
                    {
                        dOut.write((byte)0);
                    }

                    dOut.write(pBytes);
                }

                dOut.close();

                byte[]    dig = digestCalculator.getDigest();

                if (dig.length > (keyBytes.length - generatedBytes))
                {
                    System.arraycopy(dig, 0, keyBytes, generatedBytes, keyBytes.length - generatedBytes);
                }
                else
                {
                    System.arraycopy(dig, 0, keyBytes, generatedBytes, dig.length);
                }

                generatedBytes += dig.length;

                loopCount++;
            }
        }
        catch (IOException e)
        {
            throw new PGPException("exception calculating digest: " + e.getMessage(), e);
        }

        for (int i = 0; i != pBytes.length; i++)
        {
            pBytes[i] = 0;
        }

        return keyBytes;
    }

    public static byte[] makeKeyFromPassPhrase(
        PGPDigestCalculatorProvider digCalcProvider,
        int     algorithm,
        S2K     s2k,
        char[]  passPhrase)
        throws PGPException
    {
        PGPDigestCalculator digestCalculator;

        if (s2k != null)
        {
            digestCalculator = digCalcProvider.get(s2k.getHashAlgorithm());
        }
        else
        {
            digestCalculator = digCalcProvider.get(HashAlgorithmTags.MD5);
        }

        return makeKeyFromPassPhrase(digestCalculator, algorithm, s2k, passPhrase);
    }
}
