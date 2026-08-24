package org.bouncycastle.jcajce.spec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public class KEMKDFSpec
{
    private static final byte[] EMPTY_OTHER_INFO = new byte[0];

    private final String keyAlgorithmName;
    private final int keySizeInBits;
    private final AlgorithmIdentifier kdfAlgorithm;
    private final byte[] otherInfo;

    /**
     * Base constructor.
     * <p>
     * A null otherInfo is stored as empty, so {@link #getOtherInfo()} never returns null. The
     * Builder of every spec in this package already does that, but this constructor is reachable
     * directly by a subclass - the deprecated {@link KEMParameterSpec} is one - and
     * org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil's KMAC and SHAKE-256 branches read
     * the otherInfo length without a guard, so a null here would surface as a
     * NullPointerException out of a KEM operation.
     *
     * @param kdfAlgorithm the KDF to derive with, or null for the shared secret as it comes.
     * @param otherInfo the otherInfo/IV to feed the KDF, may be null for none.
     * @param keyAlgorithmName the algorithm name for the derived key.
     * @param keySizeInBits the size of the key to derive.
     */
    protected KEMKDFSpec(AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo, String keyAlgorithmName, int keySizeInBits)
    {
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySizeInBits = keySizeInBits;
        this.kdfAlgorithm = kdfAlgorithm;
        this.otherInfo = (otherInfo == null) ? EMPTY_OTHER_INFO : otherInfo;
    }

    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    public int getKeySize()
    {
        return keySizeInBits;
    }

    public AlgorithmIdentifier getKdfAlgorithm()
    {
        return kdfAlgorithm;
    }

    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }
}
