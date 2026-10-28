package org.bouncycastle.crypto.params;

/**
 * Implemented by the parameter set classes of the post-quantum algorithms to report where a
 * parameter set sits in the NIST post-quantum security categories (NIST IR 8547, Table 1) and
 * the classical security strength NIST assigns to it (NIST IR 8547, Tables 3 and 5), so that
 * a policy such as "category 3 or better" can be applied without a per-algorithm table.
 * <p>
 * The classical security strength is the value the constraints framework reports as
 * {@link org.bouncycastle.crypto.CryptoServiceProperties#bitsOfSecurity()} for the algorithm.
 * </p>
 */
public interface PQCParameters
{
    /**
     * Return the NIST post-quantum security category (1 to 5) of this parameter set.
     *
     * @return the security category, as given in NIST IR 8547 Tables 3 and 5.
     */
    int getSecurityCategory();

    /**
     * Return the classical security strength, in bits, NIST assigns to this parameter set.
     *
     * @return the classical security strength in bits.
     */
    int getClassicalSecurityStrength();
}
