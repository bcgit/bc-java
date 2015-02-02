package org.bouncycastle.crypto.generators;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64Encoder;

/**
 * Implements the <b>bcrypt</b> password hash function from <a
 * href="http://www.openbsd.org/papers/bcrypt-paper.pdf">A Future Adaptable Password Scheme</a> as
 * implemented by OpenBSD (and implementations derived from that).
 * <p>
 * This implementation produces/consumes the crypt style formatted string salt/hash strings. To use
 * the raw BCrypt hash function directly, use the {@link BCrypt} class.
 * <p>
 * <b>NOTE:</b> This implementation follows the OpenBSD (and derived implementations by):
 * <ul>
 * <li>Supporting passwords up to 72 bytes in length (after conversion from strings where
 * applicable).</li>
 * <li>Truncating the last byte of the raw bcrypt hash (returning only 184 bits of hash).</li>
 * <li>Using the <code>2a</code> variant, where a null byte is added to the end of the passcode. The
 * <code>2</code>, <code>2a</code>, <code>2b</code> and <code>2y</code> variants are supported for
 * existing salt/hash values, but are all (except for the original <code>2</code>) treated as
 * equivalent by this implementation. The <code>2x</code> variant, and the <code>2a</code> 'with
 * safety' implemented in some crypt libraries are not supported.</li>
 * <li>Using a custom Base64 encoding alphabet, without padding.</li>
 * </ul>
 */
public class OpenBSDBcrypt
{
    /*
     * Ref: OpenBSD impl http://ftp.usa.openbsd.org/pub/OpenBSD/src/lib/libc/crypt/bcrypt.c (2a/2b
     * variants)
     *
     * Ref: Crypt_Blowfish http://www.openwall.com/crypt/ (2x/2y variants)
     */

    private static final SecureRandom DEFAULT_RANDOM = new SecureRandom();

    /**
     * BCrypt parameters, encodable in a hash string.
     */
    private static class BCryptParameters
    {
        // Original '2' variant is not supported by OpenBSD or crypt_blowfish
        public static final char VARIANT_NONE = 0;
        // 'a' signals null termination of key (not in original spec)
        // NOTE: Openwall crypt_blowfish implements magic collision checking for buggy 'a' impls
        // This implementation does not have those bugs (see 'y' variant).
        public static final char VARIANT_A = 'a';
        // 'b' signals a fix for cost param integer overflow in OpenBSD impl
        public static final char VARIANT_B = 'b';
        // 'y' signals a fix for improper sign extension during key bytes -> words in crypt_blowfish
        public static final char VARIANT_Y = 'y';
        // 'x' (not implemented) signals explicit harmful sign extension buggy behaviour in
        // crypt_blowfish - not easy to implement without borking BlowfishEngine

        private char variant;
        private byte[] salt;
        private int cost;

        public BCryptParameters(char variant, byte[] salt, int cost)
        {
            this.variant = variant;
            this.salt = salt;
            this.cost = cost;
        }
    }

    /**
     * Custom Base64 encoder as used in OpenBSD bcrypt implementation.
     */
    private static class BCryptBase64Encoder
        extends Base64Encoder
    {
        private static final byte[] ENCODER_TABLE;

        static
        {
            // Custom Base64 encoder alphabet
            final String encodeAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            ENCODER_TABLE = new byte[encodeAlphabet.length()];
            for (int i = 0; i < encodeAlphabet.length(); i++)
            {
                ENCODER_TABLE[i] = (byte)encodeAlphabet.charAt(i);
            }
        }

        protected void initialiseDecodingTable()
        {
            System.arraycopy(ENCODER_TABLE, 0, encodingTable, 0, ENCODER_TABLE.length);
            super.initialiseDecodingTable();
        }

        /**
         * Base64 encode data, stripping padding bytes.
         */
        public int encode(byte[] data, int off, int length, OutputStream out)
            throws IOException
        {
            return super.encode(data, off, length, new Base64PaddingStripper(out));
        }

        /**
         * Decode unpadded base64 data, restoring padding if required.
         */
        public int decode(byte[] data, int off, int length, OutputStream out)
            throws IOException
        {
            int padding = 4 - (data.length % 4);
            if (padding != 0)
            {
                data = Arrays.copyOf(data, data.length + padding);
                for (int i = data.length - 1; i >= data.length - padding; i--)
                {
                    data[i] = '=';
                }
            }
            return super.decode(data, off, length, out);
        }

        /**
         * Decode unpadded base64 data, restoring padding if required.
         */
        public int decode(String data, OutputStream out)
            throws IOException
        {
            int padding = 4 - (data.length() % 4);
            for (int i = 0; i < padding; i++)
            {
                data = data + "=";
            }
            return super.decode(data, out);
        }
    }

    /**
     * Output stream that drops Base64 padding bytes ('=')
     */
    private static class Base64PaddingStripper
        extends OutputStream
    {
        private OutputStream out;

        public Base64PaddingStripper(OutputStream out)
        {
            this.out = out;
        }

        public void write(int b)
            throws IOException
        {
            if (b == '=')
            {
                return;
            }
            out.write(b);
        }

    }

    /**
     * Output stream to Writer adapter that writes ASCII bytes as ASCII chars.
     */
    private static class ASCIIWriter
        extends OutputStream
    {
        private Writer writer;

        public ASCIIWriter(Writer writer)
        {
            this.writer = writer;
        }

        public void write(int b)
            throws IOException
        {
            writer.write(b);
        }
    }

    /**
     * String writer with BCrypt style Base64 encoding for data.
     */
    private static class BCryptWriter
        extends StringWriter
    {
        private Base64Encoder enc = new BCryptBase64Encoder();
        private OutputStream b64Out = new ASCIIWriter(this);

        public BCryptWriter()
        {
        }

        public void encode(byte[] data, int length)
            throws IOException
        {
            enc.encode(data, 0, length, b64Out);
        }

    }

    /**
     * Generate a salt for use with the {@link #hash(String, String)} method. <br/>
     * A random 128 bit salt will be generated with a platform default {@link SecureRandom}.
     *
     * @param cost the bcrypt cost parameter. The cost of the bcrypt function grows as
     *            <code>2^cost</code>. Legal values are 4..31 inclusive.
     * @return a string encoding the algorithm identifier, cost and salt.
     */
    public static String generateSalt(int cost)
    {
        return generateSalt(cost, DEFAULT_RANDOM);
    }

    /**
     * Generate a salt for use with the {@link #hash(String, String)} method.
     *
     * @param cost the bcrypt cost parameter. The cost of the bcrypt function grows as
     *            <code>2^cost</code>. Legal values are 4..31 inclusive.
     * @param rand a source of randomness to generate the 128 bit salt with.
     * @return a string encoding the algorithm identifier, cost and salt.
     */
    public static String generateSalt(int cost, SecureRandom rand)
    {
        byte[] salt = new byte[BCrypt.SALT_SIZE_BYTES];
        rand.nextBytes(salt);

        return encodeSalt(salt, cost);
    }

    /**
     * Encodes a pre-generated 128 bit salt and cost for use with the {@link #hash(String, String)}
     * method.
     *
     * @param salt a 128 bit (16 byte) salt.
     * @param cost the bcrypt cost parameter. The cost of the bcrypt function grows as
     *            <code>2^cost</code>. Legal values are 4..31 inclusive.
     * @return a string encoding the algorithm identifier, cost and salt.
     */
    public static String encodeSalt(byte[] salt, int cost)
    {
        if (salt == null)
        {
            throw new IllegalArgumentException("Salt is required");
        }
        if (salt.length != BCrypt.SALT_SIZE_BYTES)
        {
            throw new IllegalArgumentException("BCrypt salt must be 128 bits");
        }
        try
        {
            final BCryptWriter encoded = new BCryptWriter();
            encodeSalt(new BCryptParameters(BCryptParameters.VARIANT_A, salt, cost), encoded);
            return encoded.toString();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Unexpected error.");
        }
    }

    private static void encodeSalt(BCryptParameters params, BCryptWriter encoded)
        throws IOException
    {
        encoded.write("$2");
        if (params.variant != BCryptParameters.VARIANT_NONE)
        {
            encoded.write(params.variant);
        }
        encoded.write("$");
        if (params.cost < 10)
        {
            encoded.write('0');
        }
        encoded.write(Integer.toString(params.cost));
        encoded.write("$");

        encoded.encode(params.salt, params.salt.length);
    }

    private static BCryptParameters decodeSalt(String salt)
    {
        if (salt.charAt(0) != '$')
        {
            throw new IllegalArgumentException("Expected $ at start of salt.");
        }
        if (salt.charAt(1) != '2')
        {
            throw new IllegalArgumentException("Expected bcrypt identifier (2) in salt.");
        }
        char variant = salt.charAt(2);
        if (variant == '$')
        {
            variant = BCryptParameters.VARIANT_NONE;
            salt = salt.substring(3);
        }
        else if (variant == BCryptParameters.VARIANT_A || variant == BCryptParameters.VARIANT_B
            || variant == BCryptParameters.VARIANT_Y)
        {
            salt = salt.substring(4);
        }
        else
        {
            throw new IllegalArgumentException("Only $2$, $2a$, $2b$ and $2y$ version identifiers are supported.");
        }
        if (salt.charAt(2) != '$')
        {
            throw new IllegalArgumentException("Missing cost factor.");
        }

        try
        {
            int cost = Integer.parseInt(salt.substring(0, 2));
            if (cost < BCrypt.MIN_COST || cost > BCrypt.MAX_COST)
            {
                throw new IllegalArgumentException("Cost outside legal range.");
            }
            salt = salt.substring(3);

            if (salt.length() < 22)
            {
                throw new IllegalArgumentException("Encoded salt must be 22 characters");
            }
            salt = salt.substring(0, 22);

            BCryptBase64Encoder b64 = new BCryptBase64Encoder();
            ByteArrayOutputStream saltBytes = new ByteArrayOutputStream();
            b64.decode(salt, saltBytes);
            return new BCryptParameters(variant, saltBytes.toByteArray(), cost);
        }
        catch (NumberFormatException e)
        {
            throw new IllegalArgumentException("Cost is not a valid integer");
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Unexpected error: " + e);
        }
    }

    /**
     * Calculates the <b>bcrypt</b> hash of a password, converting the password to a UTF-8 encoded
     * byte sequence prior to {@link #hash(byte[], String) hashing}.
     *
     * @param password the password text, which may contain non ASCII characters.
     * @param salt a {@link #generateSalt(int) bcrypt formatted salt string}, including encoded
     *            cost.
     * @return the bcrypt encoded hash, including the algorithm identifier, cost, 128 bit salt and
     *         184 bit hash value.
     * @see OpenBSDBcrypt
     */
    public static String hash(String password, String salt)
    {
        if (password == null)
        {
            throw new IllegalArgumentException("Password is required");
        }
        try
        {
            return hash(password.getBytes("UTF-8"), salt);
        }
        catch (UnsupportedEncodingException e)
        {
            throw new IllegalStateException("UTF-8 not supported");
        }
    }

    /**
     * Calculates the <b>bcrypt</b> hash of a password and encodes it in a string compatible with
     * the original OpenBSD bcrypt implementation (e.g <code>$2a$cost$salt+hash</code>).
     *
     * @param password the password bytes to use for this invocation, <b>without</b> a trailing null
     *            byte if that is specified by the algorithm identifier in the salt.
     * @param salt the 128 bit salt to use for this invocation.
     * @param cost the bcrypt cost parameter. The cost of the bcrypt function grows as
     *            <code>2^cost</code>. Legal values are 4..31 inclusive.
     * @return the bcrypt encoded hash, including the algorithm identifier, cost, 128 bit salt and
     *         184 bit hash value.
     * @see OpenBSDBcrypt
     */
    public static String hash(byte[] password, String salt)
    {
        if (password == null)
        {
            throw new IllegalArgumentException("Password is required");
        }
        if (salt == null)
        {
            throw new IllegalArgumentException("Salt is required");
        }
        return hash(password, decodeSalt(salt));
    }

    private static String hash(byte[] password, BCryptParameters params)
    {
        // Follow OpenBSD implementation of $2a mode by including zero terminator of password in key
        if ((params.variant != BCryptParameters.VARIANT_NONE) && (password.length < BCrypt.MAX_PASSWORD_BYTES))
        {
            // Terminate with zero if room: for 72 byte password, zero terminator would be ignored
            // by Blowfish key schedule anyway
            password = Arrays.copyOf(password, password.length + 1);
        }

        byte[] bc = BCrypt.generate(password, params.salt, params.cost);

        final BCryptWriter encoded = new BCryptWriter();
        try
        {
            encodeSalt(params, encoded);
            // OpenBSD bcrypt and others that follow it faithfully throw away last byte of hash
            encoded.encode(bc, bc.length - 1);
            return encoded.toString();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Hash encoding failed: " + e);
        }
    }

    /**
     * Verifies a password against a previously generated hash value, converting the password to a
     * UTF-8 encoded byte sequence prior to hashing.
     * @param password the password text to hash and verify, which may contain non ASCII characters.
     * @param hash a {@link #hash(String, String) hashed} password, which also encodes the algorithm
     *            identifier, cost and salt.
     *
     * @return <code>true</code> iff the provided password hashes to the same value as that in the
     *         provided hash.
     */
    public static boolean verify(String password, String hash)
    {
        String check = hash(password, hash);
        return Arrays.constantTimeAreEqual(check.toCharArray(), hash.toCharArray());
    }

    /**
     * Verifies a password against a previously generated hash value.
     * @param password the bytes of the password to hash and verify.
     * @param hash a {@link #hash(byte[], String) hashed} password, which also encodes the algorithm
     *            identifier, cost and salt.
     *
     * @return <code>true</code> iff the provided password hashes to the same value as that in the
     *         provided hash.
     */
    public static boolean verify(byte[] password, String hash)
    {
        String check = hash(password, hash);
        return Arrays.constantTimeAreEqual(check.toCharArray(), hash.toCharArray());
    }

}
