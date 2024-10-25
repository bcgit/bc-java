package org.bouncycastle.bcpg.sig;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Signature Subpacket containing the AEAD cipher suites (AEAD algorithm, Symmetric Key Algorithm pairs)
 * preferred by the key holder's implementation.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites">
 *     OpenPGP - Preferred AEAD Ciphersuites</a>
 */
public class PreferredAEADCiphersuites
    extends PreferredAlgorithms
{

    private final Combination[] algorithms;

    /**
     * AES-128 + OCB is a MUST implement and is therefore implicitly supported.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites">
     * OpenPGP - Preferred AEAD Ciphersuites</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html">
     * OpenPGP - Preferred AEAD Ciphersuites</a>
     */
    private static final Combination AES_128_OCB = new Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB);

    /**
     * Create a new PreferredAEADAlgorithms signature subpacket from raw data.
     *
     * @param critical     whether the subpacket is critical
     * @param isLongLength whether the subpacket uses long length encoding
     * @param data         raw data
     */
    public PreferredAEADCiphersuites(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS, critical, isLongLength, requireEven(data));
        this.algorithms = parseCombinations(data);
    }

    /**
     * Create a new PreferredAEADAlgorithm signature subpacket.
     *
     * @param critical     whether the subpacket is critical
     * @param combinations list of combinations, with the most preferred option first
     */
    public PreferredAEADCiphersuites(boolean critical, Combination[] combinations)
    {
        this(critical, false, encodeCombinations(combinations));
    }

    /**
     * Unmarshall a byte array into a list of algorithm combinations.
     *
     * @param data marshalled bytes
     * @return unmarshalled list
     */
    private static Combination[] parseCombinations(byte[] data)
    {
        Combination[] algorithms = new Combination[data.length / 2];
        for (int i = 0; i < algorithms.length; i++)
        {
            algorithms[i] = new Combination(
                data[i * 2],
                data[i * 2 + 1]);
        }
        return algorithms;
    }

    /**
     * Marshall the list of combinations into a byte array.
     *
     * @param combinations list of algorithm combinations
     * @return marshalled byte array
     */
    private static byte[] encodeCombinations(Combination[] combinations)
    {
        byte[] encoding = new byte[combinations.length * 2];
        for (int i = 0; i < combinations.length; i++)
        {
            Combination combination = combinations[i];
            encoding[i * 2] = (byte)(combination.getSymmetricAlgorithm() & 0xff);
            encoding[i * 2 + 1] = (byte)(combination.getAeadAlgorithm() & 0xff);
        }
        return encoding;
    }

    /**
     * Return true, if the given algorithm combination is supported (explicitly or implicitly).
     *
     * @param combination combination
     * @return true, if the combination is supported, false otherwise
     */
    public boolean isSupported(Combination combination)
    {
        return contains(combination, getAlgorithms());
    }

    private static boolean contains(Combination combination, Combination[] combinations)
    {
        for (int i = 0; i != combinations.length; i++)
        {
            Combination supported = combinations[i];
            if (supported.equals(combination))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Return AEAD algorithm preferences. The most preferred option comes first.
     * This method returns the combinations as they are listed in the packet, possibly excluding implicitly supported
     * combinations.
     *
     * @return explicitly supported algorithm combinations
     */
    public Combination[] getRawAlgorithms()
    {
        Combination[] copy = new Combination[algorithms.length];
        System.arraycopy(algorithms, 0, copy, 0, algorithms.length);
        return copy;
    }

    /**
     * Returns AEAD algorithm preferences, including implicitly supported algorithm combinations.
     *
     * @return all supported algorithm combinations
     */
    public Combination[] getAlgorithms()
    {
        if (!contains(AES_128_OCB, algorithms))
        {
            // AES128 + OCB is MUST implement and implicitly supported
            Combination[] withImplicitOptionAppended = new Combination[algorithms.length + 1];
            System.arraycopy(algorithms, 0, withImplicitOptionAppended, 0, algorithms.length);
            withImplicitOptionAppended[algorithms.length] = AES_128_OCB;
            return withImplicitOptionAppended;
        }

        return getRawAlgorithms();
    }

    private static byte[] requireEven(byte[] encodedCombinations)
    {
        if (encodedCombinations.length % 2 != 0)
        {
            throw new IllegalArgumentException("Even number of bytes expected.");
        }
        return encodedCombinations;
    }

    /**
     * Return a {@link Builder} for constructing a {@link PreferredAEADCiphersuites} packet.
     * @param isCritical true if the packet is considered critical.
     * @return builder
     */
    public static Builder builder(boolean isCritical)
    {
        return new Builder(isCritical);
    }

    public static final class Builder
    {

        private final List<Combination> combinations = new ArrayList<Combination>();
        private final boolean isCritical;

        private Builder(boolean isCritical)
        {
            this.isCritical = isCritical;
        }

        /**
         * Add a combination of cipher- and AEAD algorithm to the list of supported ciphersuites.
         * @see SymmetricKeyAlgorithmTags for cipher algorithms
         * @see AEADAlgorithmTags for AEAD algorithms
         * @param symmetricAlgorithmId symmetric cipher algorithm ID
         * @param aeadAlgorithmId AEAD algorithm ID
         * @return builder
         */
        public Builder addCombination(int symmetricAlgorithmId, int aeadAlgorithmId)
        {
            combinations.add(new Combination(symmetricAlgorithmId, aeadAlgorithmId));
            return this;
        }

        /**
         * Build a {@link PreferredAEADCiphersuites} from this builder.
         * @return finished packet
         */
        public PreferredAEADCiphersuites build()
        {
            return new PreferredAEADCiphersuites(isCritical, (Combination[])combinations.toArray(new Combination[0]));
        }
    }

    /**
     * Algorithm combination of a {@link SymmetricKeyAlgorithmTags} and a {@link AEADAlgorithmTags}.
     */
    public static class Combination
    {
        private final int symmetricAlgorithm;
        private final int aeadAlgorithm;

        /**
         * Create a new algorithm combination from a {@link SymmetricKeyAlgorithmTags} and a {@link AEADAlgorithmTags}.
         *
         * @param symmetricAlgorithmTag symmetric algorithm tag
         * @param aeadAlgorithmTag      aead algorithm tag
         */
        public Combination(int symmetricAlgorithmTag, int aeadAlgorithmTag)
        {
            this.symmetricAlgorithm = symmetricAlgorithmTag;
            this.aeadAlgorithm = aeadAlgorithmTag;
        }

        /**
         * Return the symmetric algorithm tag.
         *
         * @return symmetric algorithm
         */
        public int getSymmetricAlgorithm()
        {
            return symmetricAlgorithm;
        }

        /**
         * Return the AEAD algorithm tag.
         *
         * @return aead algorithm
         */
        public int getAeadAlgorithm()
        {
            return aeadAlgorithm;
        }

        @Override
        public boolean equals(Object o)
        {
            if (o == null)
            {
                return false;
            }

            if (this == o)
            {
                return true;
            }

            if (!(o instanceof Combination))
            {
                return false;
            }

            Combination other = (Combination)o;
            return getSymmetricAlgorithm() == other.getSymmetricAlgorithm()
                && getAeadAlgorithm() == other.getAeadAlgorithm();
        }

        @Override
        public int hashCode()
        {
            return 13 * getSymmetricAlgorithm() + 17 * getAeadAlgorithm();
        }
    }
}
