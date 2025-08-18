package org.bouncycastle.openpgp.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
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
        int algorithm,
        S2K s2k,
        char[] passPhrase)
        throws PGPException
    {
        int keySize;

        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
        case SymmetricKeyAlgorithmTags.CAST5:
        case SymmetricKeyAlgorithmTags.BLOWFISH:
        case SymmetricKeyAlgorithmTags.SAFER:
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
        case SymmetricKeyAlgorithmTags.TWOFISH:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            keySize = 256;
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        byte[] pBytes = Strings.toUTF8ByteArray(passPhrase);
        byte[] keyBytes = new byte[(keySize + 7) / 8];

        int generatedBytes = 0;
        int loopCount = 0;

        if (s2k != null)
        {
            if (s2k.getType() == S2K.ARGON_2)
            {
                Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withSalt(s2k.getIV())
                    .withIterations(s2k.getPasses())
                    .withParallelism(s2k.getParallelism())
                    .withMemoryPowOfTwo(s2k.getMemorySizeExponent())
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13);

                Argon2BytesGenerator argon2 = new Argon2BytesGenerator();
                argon2.init(builder.build());
                argon2.generateBytes(passPhrase, keyBytes);

                return keyBytes;
            }
            else if (s2k.getHashAlgorithm() != digestCalculator.getAlgorithm())
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
            byte[] iv = s2k != null? s2k.getIV() : null;
            while (generatedBytes < keyBytes.length)
            {
                for (int i = 0; i != loopCount; i++)
                {
                    dOut.write(0);
                }

                if (s2k != null)
                {
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
                        long count = s2k.getIterationCount();
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
                    dOut.write(pBytes);
                }

                dOut.close();

                byte[] dig = digestCalculator.getDigest();
                int toCopy = Math.min(dig.length, keyBytes.length - generatedBytes);
                System.arraycopy(dig, 0, keyBytes, generatedBytes, toCopy);
                generatedBytes += toCopy;

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
        int algorithm,
        S2K s2k,
        char[] passPhrase)
        throws PGPException
    {
        PGPDigestCalculator digestCalculator;

        if (s2k != null && s2k.getType() != S2K.ARGON_2)
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
