package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Structured SQIsign secret key: the public curve (carried for signing),
 * the secret quaternion left ideal, the basis-change matrix from the canonical
 * 2^e-basis to the image of the standard basis under the secret isogeny, and
 * the canonical 2^e-basis on the public curve.
 *
 * <p>Mirrors C {@code secret_key_t}.</p>
 */
final class SQIsignSecretKeyData
{
    public final EcCurve curve;
    public final QuatLeftIdeal secretIdeal;
    public final Ibz[][] matBAcanToBA0Two;
    public final EcBasis canonicalBasis;

    public SQIsignSecretKeyData()
    {
        this.curve = new EcCurve();
        this.secretIdeal = new QuatLeftIdeal();
        this.matBAcanToBA0Two = IbzMat.init2x2();
        this.canonicalBasis = new EcBasis();
    }
}
