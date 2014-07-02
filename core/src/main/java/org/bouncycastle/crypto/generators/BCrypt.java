package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of the <b>bcrypt</b> password hash function from <a
 * href="http://www.openbsd.org/papers/bcrypt-paper.pdf">A Future Adaptable Password Scheme</a> by
 * Niels Provos and David Mazieres.
 * <p>
 * This implementation implements the raw bcrypt hash function. To produce/consume crypt style
 * formatted strings use {@link OpenBSDBcrypt}.
 */
public class BCrypt
{

    /**
     * EksBlowfish - Blowfish encryption with an Expensive Key Schedule.
     */
    private static class EksBlowfishEngine
        extends BlowfishEngine
    {
        private final byte[] salt;
        private final int cost;

        public EksBlowfishEngine(byte[] salt, int cost)
        {
            super(false);   // Don't restrict min/max key lengths
            this.salt = Arrays.copyOf(salt, salt.length);
            this.cost = cost;
        }

        public String getAlgorithmName()
        {
            return "EksBlowfish";
        }

        /**
         * Expensive key schedule for bcrypt.
         */
        protected void setKey(byte[] key)
        {
            // Blowfish is not defined for a zero byte key, so treat empty key as a sequence of zero
            // valued bytes, which produces the same key setup (as do all zero byte sequences).
            if (key.length == 0)
            {
                key = new byte[4];
            }

            // Extended key setup, substituting salt words for zeros in original Blowfish
            setKey(key, new ByteCycle(salt));

            // Repeat standard Blowfish key setup for 2^cost iterations
            // alternating salt and key as the 'key' input
            long setupRounds = 1L << cost;
            // NOTE: long to avoid integer overflow on 1 << 31
            for (int i = 0; i < setupRounds; i++)
            {
                // NOTE: original bcrypt paper has salt/key iteration.
                // Most implementations (including OpenBSD) do key/salt
                super.setKey(key);
                super.setKey(salt);
            }
        }
    }

    /** Base plaintext vector encrypted with Blowfish in the bcrypt algorithm */
    // OrpheanBeholderScryDoubt
    private static final byte[] HASH_BASE = {
        0x4f,0x72,0x70,0x68,0x65,0x61,0x6e,0x42,0x65,0x68,0x6f,0x6c,
        0x64,0x65,0x72,0x53,0x63,0x72,0x79,0x44,0x6f,0x75,0x62,0x74
        };

    /** Size of the salt parameter in bytes */
    static final int SALT_SIZE_BYTES = 16;

    /** Minimum value of cost parameter, equal to log2(bytes of salt) */
    static final int MIN_COST = 4;

    /** Maximum value of cost parameter (31 == 2,147,483,648) */
    static final int MAX_COST = 31;

    /** Maximum size of password == max (unrestricted) size of Blowfish key */
    // Blowfish spec limits keys to 448bit/56 bytes to ensure all bits of key affect all ciphertext
    // bits, but technically algorithm handles 72 byte keys and most implementations support this.
    static final int MAX_PASSWORD_BYTES = 72;

    /**
     * Calculates the <b>bcrypt</b> hash of a password.
     * <p>
     * This implements the raw <b>bcrypt</b> function as defined in the bcrypt specification, not
     * the crypt encoded version implemented in OpenBSD.
     *
     * @param password the password bytes (up to 72 bytes) to use for this invocation.
     * @param salt the 128 bit salt to use for this invocation.
     * @param cost the bcrypt cost parameter. The cost of the bcrypt function grows as
     *            <code>2^cost</code>. Legal values are 4..31 inclusive.
     * @return the output of the raw bcrypt operation: a 192 bit (24 byte) hash.
     */
    public static byte[] generate(byte[] password, byte[] salt, int cost)
    {
        if (password == null || salt == null)
        {
            throw new IllegalArgumentException("Password and salt are required");
        }
        if (salt.length != SALT_SIZE_BYTES)
        {
            throw new IllegalArgumentException("BCrypt salt must be 128 bits");
        }
        if (password.length > MAX_PASSWORD_BYTES)
        {
            throw new IllegalArgumentException("BCrypt password must be <= 72 bytes");
        }
        if (cost < MIN_COST || cost > MAX_COST)
        {
            throw new IllegalArgumentException("BCrypt cost must be from 4..31");
        }

        EksBlowfishEngine bf = new EksBlowfishEngine(salt, cost);
        bf.init(true, new KeyParameter(password));

        byte[] ctext = Arrays.copyOf(HASH_BASE, HASH_BASE.length);
        for (int i = 0; i < 64; i++)
        {
            bf.processBlock(ctext, 0, ctext, 0);
            bf.processBlock(ctext, 8, ctext, 8);
            bf.processBlock(ctext, 16, ctext, 16);
        }

        return ctext;
    }

}
