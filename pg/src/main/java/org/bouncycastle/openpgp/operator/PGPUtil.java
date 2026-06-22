package org.bouncycastle.openpgp.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * Basic utility class
 */
class PGPUtil
    implements HashAlgorithmTags
{
    // Property names mirror org.bouncycastle.crypto.params.Argon2Parameters.MAX_MEMORY_EXP / MAX_PASSES /
    // MAX_PARALLELISM. They are referenced here as plain strings (rather than via the Argon2Parameters
    // constants) so that this top-level operator class does not import org.bouncycastle.crypto.* - the
    // Argon2 cost clamp is policy on untrusted packet data and must run here, before any backend.
    private static final String MAX_MEMORY_EXP = "org.bouncycastle.argon2.max_memory_exp";
    private static final String MAX_PASSES = "org.bouncycastle.argon2.max_passes";
    private static final String MAX_PARALLELISM = "org.bouncycastle.argon2.max_parallelism";

    static byte[] makeKeyFromPassPhrase(
        PGPDigestCalculator digestCalculator,
        PGPS2KCalculator s2kCalculator,
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
                if (s2kCalculator == null)
                {
                    throw new PGPException("no PGPS2KCalculator configured for Argon2 S2K");
                }
                int memorySizeExponent = s2k.getMemorySizeExponent();
                // The passes, parallelism and memory-size fields are one-byte values taken verbatim from
                // the (unauthenticated) S2K packet, and Argon2 must run before the message can be
                // authenticated. Clamp all three to conservative, property-overridable maxima so a single
                // decrypt attempt cannot be driven into a huge allocation or unbounded CPU work. The clamp
                // stays here (above the backend) so the .bc / .jcajce calculators cannot diverge on it.
                // TODO: memory lower bound should really be 3 + log2(parallelism)
                if (memorySizeExponent < 3 || memorySizeExponent > Properties.asInteger(MAX_MEMORY_EXP, 24))
                {
                    throw new PGPException("memory size exponent out of range");
                }
                if (s2k.getPasses() < 1 || s2k.getPasses() > Properties.asInteger(MAX_PASSES, 10))
                {
                    throw new PGPException("passes out of range");
                }
                if (s2k.getParallelism() < 1 || s2k.getParallelism() > Properties.asInteger(MAX_PARALLELISM, 16))
                {
                    throw new PGPException("parallelism out of range");
                }

                return s2kCalculator.makeKey(passPhrase, s2k, keyBytes.length);
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
        PGPS2KCalculator s2kCalculator,
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

        return makeKeyFromPassPhrase(digestCalculator, s2kCalculator, algorithm, s2k, passPhrase);
    }
}
