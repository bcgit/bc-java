package org.bouncycastle.kmip.wire.object;

import java.math.BigInteger;

import org.bouncycastle.kmip.wire.enumeration.KMIPSplitKeyMethod;


/**
 * A Managed Cryptographic Object that is a Split Key. A split key is a secret, usually a symmetric key or a private key
 * that has been split into a number of parts, each of which MAY then be distributed to several key holders, for
 * additional security. The Split Key Parts field indicates the total number of parts, and the Split Key Threshold field
 * indicates the minimum number of parts needed to reconstruct the entire key. The Key Part Identifier indicates which
 * key part is contained in the cryptographic object, and SHALL be at least 1 and SHALL be less than or equal to Split
 * Key Parts.
 */
public class KMIPSplitKey
    extends KMIPObject
{

    private final int splitKeyParts;         // Total number of parts
    private final int keyPartIdentifier;      // Identifier for the key part
    private final int splitKeyThreshold;      // Minimum number of parts needed to reconstruct the key
    private final KMIPSplitKeyMethod splitKeyMethod; // Method used for splitting the key
    private final BigInteger primeFieldSize;  // Required only if Split Key Method is Polynomial Sharing

    // Key Block Object Data (can be defined separately as needed)
    private final KMIPKeyBlock KMIPKeyBlock;

    /**
     * Constructs a SplitKey object.
     *
     * @param splitKeyParts     Total number of parts.
     * @param keyPartIdentifier Identifier for the key part.
     * @param splitKeyThreshold Minimum number of parts needed to reconstruct the key.
     * @param splitKeyMethod    Method used for splitting the key.
     * @param primeFieldSize    Size of the prime field (if applicable).
     * @param KMIPKeyBlock      Key block object data.
     */
    public KMIPSplitKey(int splitKeyParts, int keyPartIdentifier, int splitKeyThreshold,
                        KMIPSplitKeyMethod splitKeyMethod, BigInteger primeFieldSize,
                        KMIPKeyBlock KMIPKeyBlock)
    {
        // Validate required fields
        if (splitKeyParts <= 0)
        {
            throw new IllegalArgumentException("Split Key Parts must be greater than 0.");
        }
        if (keyPartIdentifier <= 0)
        {
            throw new IllegalArgumentException("Key Part Identifier must be greater than 0.");
        }
        if (splitKeyThreshold <= 0 || splitKeyThreshold > splitKeyParts)
        {
            throw new IllegalArgumentException("Split Key Threshold must be greater than 0 and less than or equal to Split Key Parts.");
        }
        if (splitKeyMethod == null)
        {
            throw new IllegalArgumentException("Split Key Method must not be null.");
        }

        // If the method requires primeFieldSize, ensure it is provided
        if (splitKeyMethod == KMIPSplitKeyMethod.PolynomialSharingPrimeField && primeFieldSize == null)
        {
            throw new IllegalArgumentException("Prime Field Size is required when Split Key Method is Polynomial Sharing.");
        }

        this.splitKeyParts = splitKeyParts;
        this.keyPartIdentifier = keyPartIdentifier;
        this.splitKeyThreshold = splitKeyThreshold;
        this.splitKeyMethod = splitKeyMethod;
        this.primeFieldSize = primeFieldSize;
        this.KMIPKeyBlock = KMIPKeyBlock;
    }

    // Getters
    public int getSplitKeyParts()
    {
        return splitKeyParts;
    }

    public int getKeyPartIdentifier()
    {
        return keyPartIdentifier;
    }

    public int getSplitKeyThreshold()
    {
        return splitKeyThreshold;
    }

    public KMIPSplitKeyMethod getSplitKeyMethod()
    {
        return splitKeyMethod;
    }

    public BigInteger getPrimeFieldSize()
    {
        return primeFieldSize;
    }

    public KMIPKeyBlock getKeyBlock()
    {
        return KMIPKeyBlock;
    }
}
