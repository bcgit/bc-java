package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

/**
 * Key spec for use with the Argon2 SecretKeyFactory (RFC 9106).
 * <p>
 * Memory cost is expressed in KiB and the key length in bits, following the convention of
 * {@link ScryptKeySpec}. The variant ({@link #ARGON2_d}/{@link #ARGON2_i}/{@link #ARGON2_id}) and
 * version ({@link #ARGON2_VERSION_10}/{@link #ARGON2_VERSION_13}) constants mirror those on
 * {@link Argon2Parameters}; an optional secret (key) and additional/associated data may also be
 * supplied per RFC 9106.
 */
public class Argon2KeySpec
    implements KeySpec
{
    /** Argon2d - data-dependent memory access. */
    public static final int ARGON2_d = Argon2Parameters.ARGON2_d;
    /** Argon2i - data-independent memory access. */
    public static final int ARGON2_i = Argon2Parameters.ARGON2_i;
    /** Argon2id - hybrid of {@link #ARGON2_i} and {@link #ARGON2_d}. */
    public static final int ARGON2_id = Argon2Parameters.ARGON2_id;

    /** Argon2 v1.0 (legacy). */
    public static final int ARGON2_VERSION_10 = Argon2Parameters.ARGON2_VERSION_10;
    /** Argon2 v1.3 - the version standardised by RFC 9106. */
    public static final int ARGON2_VERSION_13 = Argon2Parameters.ARGON2_VERSION_13;

    private final char[] password;
    private final byte[] salt;
    private final byte[] secret;
    private final byte[] additional;
    private final int type;
    private final int version;
    private final int iterations;
    private final int memory;
    private final int parallelism;
    private final int keySize;

    /**
     * Argon2id, version 1.3, with no secret or additional data.
     *
     * @param password    the password to derive the key from.
     * @param salt        the salt.
     * @param iterations  the number of passes (time cost).
     * @param memory      the memory cost in KiB.
     * @param parallelism the degree of parallelism (lanes).
     * @param keySize     the length of the key to generate, in bits.
     */
    public Argon2KeySpec(char[] password, byte[] salt, int iterations, int memory, int parallelism, int keySize)
    {
        this(ARGON2_id, ARGON2_VERSION_13, password, salt, null, null, iterations, memory, parallelism, keySize);
    }

    /**
     * Argon2 with an explicit variant and version, no secret or additional data.
     *
     * @param type        the Argon2 variant ({@link #ARGON2_d}, {@link #ARGON2_i} or {@link #ARGON2_id}).
     * @param version     the Argon2 version ({@link #ARGON2_VERSION_10} or {@link #ARGON2_VERSION_13}).
     * @param password    the password to derive the key from.
     * @param salt        the salt.
     * @param iterations  the number of passes (time cost).
     * @param memory      the memory cost in KiB.
     * @param parallelism the degree of parallelism (lanes).
     * @param keySize     the length of the key to generate, in bits.
     */
    public Argon2KeySpec(int type, int version, char[] password, byte[] salt, int iterations, int memory, int parallelism, int keySize)
    {
        this(type, version, password, salt, null, null, iterations, memory, parallelism, keySize);
    }

    /**
     * Argon2 with full control over variant, version, optional secret and additional data.
     *
     * @param type        the Argon2 variant ({@link #ARGON2_d}, {@link #ARGON2_i} or {@link #ARGON2_id}).
     * @param version     the Argon2 version ({@link #ARGON2_VERSION_10} or {@link #ARGON2_VERSION_13}).
     * @param password    the password to derive the key from.
     * @param salt        the salt.
     * @param secret      the optional secret (key) value; may be null.
     * @param additional  the optional additional/associated data; may be null.
     * @param iterations  the number of passes (time cost).
     * @param memory      the memory cost in KiB.
     * @param parallelism the degree of parallelism (lanes).
     * @param keySize     the length of the key to generate, in bits.
     */
    public Argon2KeySpec(int type, int version, char[] password, byte[] salt, byte[] secret, byte[] additional, int iterations, int memory, int parallelism, int keySize)
    {
        this.type = type;
        this.version = version;
        this.password = password;
        this.salt = Arrays.clone(salt);
        this.secret = Arrays.clone(secret);
        this.additional = Arrays.clone(additional);
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.keySize = keySize;
    }

    public int getType()
    {
        return type;
    }

    public int getVersion()
    {
        return version;
    }

    public char[] getPassword()
    {
        return password;
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    public byte[] getAdditional()
    {
        return Arrays.clone(additional);
    }

    public int getIterations()
    {
        return iterations;
    }

    /**
     * @return the memory cost in KiB.
     */
    public int getMemory()
    {
        return memory;
    }

    public int getParallelism()
    {
        return parallelism;
    }

    /**
     * Key length (in bits).
     *
     * @return length of the key to generate in bits.
     */
    public int getKeyLength()
    {
        return keySize;
    }
}
