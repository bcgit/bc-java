package org.bouncycastle.crypto.params;

/**
 * Family identifier for BLS signature schemes — currently the BLS12-381
 * pairing-friendly curve from
 * {@code draft-irtf-cfrg-pairing-friendly-curves}.
 */
public class BLSParameters
{
    public static final BLSParameters bls12_381 = new BLSParameters("bls12-381");

    private final String name;

    private BLSParameters(String name)
    {
        this.name = name;
    }

    public String getName()
    {
        return name;
    }
}
