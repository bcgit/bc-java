package org.bouncycastle.bcpg;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;


/**
 * Parameter specifier for the PGP string-to-key password based key derivation function.
 * <p>
 * In iterated mode, S2K takes a single byte iteration count specifier, which is converted to an
 * actual iteration count using a formula that grows the iteration count exponentially as the byte
 * value increases.
 * </p><p>
 * e.g. <code>0x01</code> == 1088 iterations, and <code>0xFF</code> == 65,011,712 iterations.
 * </p>
 */
public class S2K
    extends BCPGObject
{
    private static final int EXPBIAS = 6;

    /**
     * Simple key generation. A single non-salted iteration of a hash function
     */
    public static final int SIMPLE = 0;
    /**
     * Salted key generation. A single iteration of a hash function with a (unique) salt
     */
    public static final int SALTED = 1;
    /**
     * Salted and iterated key generation. Multiple iterations of a hash function, with a salt
     */
    public static final int SALTED_AND_ITERATED = 3;
    /**
     * Memory-hard, salted key generation using Argon2 hash algorithm.
     */
    public static final int ARGON_2 = 4;

    public static final int GNU_DUMMY_S2K = 101;

    public static final int GNU_PROTECTION_MODE_NO_PRIVATE_KEY = 1;
    public static final int GNU_PROTECTION_MODE_DIVERT_TO_CARD = 2;

    int type;
    int algorithm;
    byte[] iv;
    int itCount = -1;
    int passes = -1;
    int protectionMode = -1;
    int parallelism;
    int memorySizeExponent;

    S2K(
        InputStream in)
        throws IOException
    {
        DataInputStream dIn = new DataInputStream(in);

        type = dIn.read();

        switch (type)
        {
        case SIMPLE:
            algorithm = dIn.read();
            break;

        case SALTED:
            algorithm = dIn.read();
            iv = new byte[8];
            dIn.readFully(iv, 0, iv.length);
            break;

        case SALTED_AND_ITERATED:
            algorithm = dIn.read();
            iv = new byte[8];
            dIn.readFully(iv, 0, iv.length);
            itCount = dIn.read();
            break;

        case ARGON_2:
            iv = new byte[16];
            dIn.readFully(iv);
            passes = dIn.read();
            parallelism = dIn.read();
            memorySizeExponent = dIn.read();
            break;

        case GNU_DUMMY_S2K:
            algorithm = dIn.read();
            dIn.read(); // G
            dIn.read(); // N
            dIn.read(); // U
            protectionMode = dIn.read(); // protection mode
            break;

        default:
            throw new IllegalStateException("Invalid S2K type: " + type);
        }
    }

    /**
     * Constructs a specifier for a {@link #SIMPLE simple} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to use.
     */
    public S2K(
        int algorithm)
    {
        this.type = 0;
        this.algorithm = algorithm;
    }

    /**
     * Constructs a specifier for a {@link #SALTED salted} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to use.
     * @param iv        the salt to apply to input to the key generation.
     */
    public S2K(
        int algorithm,
        byte[] iv)
    {
        this.type = 1;
        this.algorithm = algorithm;
        this.iv = iv;
    }

    /**
     * Constructs a specifier for a {@link #SALTED_AND_ITERATED salted and iterated} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to iterate.
     * @param iv        the salt to apply to input to the key generation.
     * @param itCount   the single byte iteration count specifier.
     */
    public S2K(
        int algorithm,
        byte[] iv,
        int itCount)
    {
        this.type = 3;
        this.algorithm = algorithm;
        this.iv = iv;

        if (itCount >= 256 && itCount <= 65536)
        {
            throw new IllegalArgumentException("invalid itCount");
        }
        this.itCount = itCount;
    }

    /**
     * Constructs a specifier for an {@link #ARGON_2 S2K method using Argon2}.
     *
     * @param argon2Params argon2 parameters
     */
    public S2K(Argon2Params argon2Params)
    {
        this.type = ARGON_2;
        this.iv = argon2Params.getSalt();
        this.passes = argon2Params.getPasses();
        this.parallelism = argon2Params.getParallelism();
        this.memorySizeExponent = argon2Params.getMemSizeExp();
    }

    /**
     * Construct a specifier for an S2K using the {@link #GNU_DUMMY_S2K} method.
     *
     * @param gnuDummyParams GNU_DUMMY_S2K parameters
     */
    public S2K(GNUDummyParams gnuDummyParams)
    {
        this.type = GNU_DUMMY_S2K;
        this.protectionMode = gnuDummyParams.getProtectionMode();
    }

    /**
     * Return a new S2K instance using the {@link #SIMPLE} method, using the given hash <pre>algorithm</pre>.
     *
     * @param algorithm hash algorithm tag
     * @return S2K
     */
    public static S2K simpleS2K(int algorithm)
    {
        return new S2K(algorithm);
    }

    /**
     * Return a new S2K instance using the {@link #SALTED} method, using the given hash <pre>algorithm</pre>
     * and <pre>salt</pre>.
     *
     * @param algorithm hash algorithm tag
     * @param salt      salt
     * @return S2K
     */
    public static S2K saltedS2K(int algorithm, byte[] salt)
    {
        return new S2K(algorithm, salt);
    }

    /**
     * Return a new S2K instance using the {@link #SALTED_AND_ITERATED} method, using the given hash <pre>algorithm</pre>,
     * <pre>salt</pre> and <pre>iterationCount</pre>.
     *
     * @param algorithm      hash algorithm tag
     * @param salt           salt
     * @param iterationCount number of iterations
     * @return S2K
     */
    public static S2K saltedAndIteratedS2K(int algorithm, byte[] salt, int iterationCount)
    {
        return new S2K(algorithm, salt, iterationCount);
    }

    /**
     * Return a new S2K instance using the {@link #ARGON_2} method, using the given argon2 <pre>parameters</pre>.
     *
     * @param parameters argon2 parameters
     * @return S2K
     */
    public static S2K argon2S2K(Argon2Params parameters)
    {
        return new S2K(parameters);
    }

    /**
     * Return a new S2K instance using the {@link #GNU_DUMMY_S2K} method, using the given GNU Dummy S2K <pre>parameters</pre>.
     *
     * @param parameters GNU Dummy S2K parameters
     * @return S2K
     */
    public static S2K gnuDummyS2K(GNUDummyParams parameters)
    {
        return new S2K(parameters);
    }

    /**
     * Gets the {@link HashAlgorithmTags digest algorithm} specified.
     */
    public int getType()
    {
        return type;
    }

    /**
     * Gets the {@link HashAlgorithmTags hash algorithm} for this S2K.
     */
    public int getHashAlgorithm()
    {
        return algorithm;
    }

    /**
     * Gets the iv/salt to use for the key generation.
     */
    public byte[] getIV()
    {
        return iv;
    }

    /**
     * Gets the actual (expanded) iteration count.
     */
    public long getIterationCount()
    {
        if (itCount >= 256)
        {
            return itCount;
        }
        return (16 + (itCount & 15)) << ((itCount >> 4) + EXPBIAS);
    }

    /**
     * Return the number of passes - only Argon2
     *
     * @return number of passes
     */
    public int getPasses()
    {
        return passes;
    }

    /**
     * Gets the protection mode - only if GNU_DUMMY_S2K
     */
    public int getProtectionMode()
    {
        return protectionMode;
    }

    /**
     * Gets the degree of parallelism - only if ARGON_2
     *
     * @return parallelism
     */
    public int getParallelism()
    {
        return parallelism;
    }

    /**
     * Gets the memory size exponent - only if ARGON_2
     *
     * @return memory size exponent
     */
    public int getMemorySizeExponent()
    {
        return memorySizeExponent;
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        switch (type)
        {
        case SIMPLE:
            out.write(type);
            out.write(algorithm);
            break;

        case SALTED:
            out.write(type);
            out.write(algorithm);
            out.write(iv);
            break;

        case SALTED_AND_ITERATED:
            out.write(type);
            out.write(algorithm);
            out.write(iv);
            writeOneOctetOrThrow(out, itCount, "Iteration count");
            break;

        case ARGON_2:
            out.write(type);
            out.write(iv);
            writeOneOctetOrThrow(out, passes, "Passes");
            writeOneOctetOrThrow(out, parallelism, "Parallelism");
            writeOneOctetOrThrow(out, memorySizeExponent, "Memory size exponent");
            break;

        case GNU_DUMMY_S2K:
            out.write(type);
            out.write(algorithm);
            out.write('G');
            out.write('N');
            out.write('U');
            out.write(protectionMode);
            break;

        default:
            throw new IllegalStateException("Unknown S2K type " + type);
        }
    }

    /**
     * Throw an {@link IllegalArgumentException} if the value cannot be encoded,
     * otherwise write the value to the output stream.
     *
     * @param out     output stream
     * @param val     value
     * @param valName name of the value for the error message
     * @throws IllegalArgumentException if the value cannot be encoded
     * @throws IOException              potentially thrown by {@link BCPGOutputStream#write(int)}
     */
    private void writeOneOctetOrThrow(BCPGOutputStream out, int val, String valName)
        throws IOException
    {
        if (val >= 256)
        {
            throw new IllegalStateException(valName + " not encodable");
        }
        out.write(val);
    }

    /**
     * Parameters for Argon2 S2K.
     */
    public static class Argon2Params
    {
        private final byte[] salt;
        private final int passes;
        private final int parallelism;
        private final int memSizeExp;

        /**
         * Uniformly safe and recommended parameters not tailored to any hardware.
         * Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1">RFC 9106: §4. Parameter Choice</a>
         */
        public Argon2Params()
        {
            this(CryptoServicesRegistrar.getSecureRandom());
        }

        /**
         * Uniformly safe and recommended parameters not tailored to any hardware.
         * Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1">RFC 9106: §4. Parameter Choice</a>
         */
        public Argon2Params(SecureRandom secureRandom)
        {
            this(1, 4, 21, secureRandom);
        }

        /**
         * Create customized Argon2 S2K parameters.
         *
         * @param passes       number of iterations, must be greater than 0
         * @param parallelism  number of lanes, must be greater 0
         * @param memSizeExp   exponent for memory consumption, must be between 3+ceil(log_2(p)) and 31
         * @param secureRandom secure random generator to initialize the salt vector
         */
        public Argon2Params(int passes, int parallelism, int memSizeExp, SecureRandom secureRandom)
        {
            this(mineSalt(secureRandom), passes, parallelism, memSizeExp);
        }

        /**
         * Create customized Argon2 S2K parameters.
         *
         * @param salt        16 bytes of random salt
         * @param passes      number of iterations, must be greater than 0
         * @param parallelism number of lanes, must be greater 0
         * @param memSizeExp  exponent for memory consumption, must be between 3+ceil(log_2(p)) and 31
         */
        public Argon2Params(byte[] salt, int passes, int parallelism, int memSizeExp)
        {
            if (salt.length != 16)
            {
                throw new IllegalArgumentException("Argon2 uses 16 bytes of salt");
            }
            this.salt = salt;

            if (passes < 1)
            {
                throw new IllegalArgumentException("Number of passes MUST be positive, non-zero");
            }
            this.passes = passes;

            if (parallelism < 1)
            {
                throw new IllegalArgumentException("Parallelism MUST be positive, non-zero.");
            }
            this.parallelism = parallelism;

            // log_2(p) = log_e(p) / log_e(2)
            //double log2_p = Math.log((double)parallelism) / Math.log(2.0);
            // see https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-05.html#section-3.7.1.4-5
            //if (memSizeExp < (3 + Math.ceil(log2_p)) || memSizeExp > 31)
            //{
                //throw new IllegalArgumentException("Memory size exponent MUST be between 3+ceil(log_2(parallelism)) and 31");
            //}
            this.memSizeExp = memSizeExp;
        }

        /**
         * Uniformly safe and recommended parameters not tailored to any hardware.
         * Uses Argon2id, 1 pass, 4 parallelism, 2 GiB RAM.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1">RFC 9106: §4. Parameter Choice</a>
         */
        public static Argon2Params universallyRecommendedParameters()
        {
            return new Argon2Params(1, 4, 21, new SecureRandom());
        }

        /**
         * Recommended parameters for memory constrained environments (64MiB RAM).
         * Uses Argon2id with 3 passes, 4 lanes and 64 MiB RAM.
         *
         * @return safe parameters for memory constrained environments
         * @see <a href="https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.2">RFC9106: §4. Parameter Choice</a>
         */
        public static Argon2Params memoryConstrainedParameters()
        {
            return new Argon2Params(3, 4, 16, new SecureRandom());
        }

        /**
         * Generate 16 bytes of random salt.
         *
         * @param secureRandom random number generator instance
         * @return salt
         */
        private static byte[] mineSalt(SecureRandom secureRandom)
        {
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            return salt;
        }

        /**
         * Return a 16-byte byte array containing the salt <pre>S</pre>.
         *
         * @return salt
         */
        public byte[] getSalt()
        {
            return salt;
        }

        /**
         * Return the number of passes <pre>t</pre>.
         *
         * @return number of passes
         */
        public int getPasses()
        {
            return passes;
        }

        /**
         * Return the factor of parallelism <pre>p</pre>.
         *
         * @return parallelism
         */
        public int getParallelism()
        {
            return parallelism;
        }

        /**
         * Return the exponent indicating the memory size <pre>m</pre>.
         *
         * @return memory size exponent
         */
        public int getMemSizeExp()
        {
            return memSizeExp;
        }
    }

    /**
     * Parameters for the {@link #GNU_DUMMY_S2K} method.
     */
    public static class GNUDummyParams
    {

        private final int protectionMode;

        private GNUDummyParams(int protectionMode)
        {
            this.protectionMode = protectionMode;
        }

        /**
         * Factory method for a GNU Dummy S2K indicating a missing private key.
         *
         * @return params
         */
        public static GNUDummyParams noPrivateKey()
        {
            return new GNUDummyParams(GNU_PROTECTION_MODE_NO_PRIVATE_KEY);
        }

        /**
         * Factory method for a GNU Dummy S2K indicating a private key located on a smart card.
         *
         * @return params
         */
        public static GNUDummyParams divertToCard()
        {
            return new GNUDummyParams(GNU_PROTECTION_MODE_DIVERT_TO_CARD);
        }

        /**
         * Return the GNU Dummy S2K protection method.
         *
         * @return protection method
         */
        public int getProtectionMode()
        {
            return protectionMode;
        }
    }
}
