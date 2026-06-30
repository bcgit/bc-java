package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Parameter sets for SQIsign (Short Quaternion and Isogeny Signature), the
 * NIST PQC additional-signatures candidate based on isogenies of supersingular
 * elliptic curves. Three parameter sets are defined matching the official
 * NIST-API reference: {@code sqisign_lvl1}, {@code sqisign_lvl3},
 * {@code sqisign_lvl5} for NIST security categories I, III and V.
 * <p>
 * Byte sizes are taken from {@code src/nistapi/lvl<n>/api.h} of the
 * reference C implementation.
 * </p>
 */
public class SQIsignParameters
{
    public static final SQIsignParameters sqisign_lvl1 = new SQIsignParameters("sqisign_lvl1", 65,  353, 148);
    public static final SQIsignParameters sqisign_lvl3 = new SQIsignParameters("sqisign_lvl3", 97,  529, 224);
    public static final SQIsignParameters sqisign_lvl5 = new SQIsignParameters("sqisign_lvl5", 129, 701, 292);

    private final String name;
    private final int publicKeyBytes;
    private final int secretKeyBytes;
    private final int signatureBytes;

    private SQIsignParameters(String name, int publicKeyBytes, int secretKeyBytes, int signatureBytes)
    {
        this.name = name;
        this.publicKeyBytes = publicKeyBytes;
        this.secretKeyBytes = secretKeyBytes;
        this.signatureBytes = signatureBytes;
    }

    public String getName()
    {
        return name;
    }

    public int getPublicKeyLength()
    {
        return publicKeyBytes;
    }

    public int getPrivateKeyLength()
    {
        return secretKeyBytes;
    }

    public int getSignatureLength()
    {
        return signatureBytes;
    }
}
