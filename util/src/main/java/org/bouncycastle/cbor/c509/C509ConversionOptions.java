package org.bouncycastle.cbor.c509;

/**
 * Options controlling the conversion of an X.509 certificate to C509.
 */
public class C509ConversionOptions
{
    /**
     * The default options: elliptic curve points are compressed and the ECDSA
     * signature component width is derived from the signature itself.
     */
    public static final C509ConversionOptions DEFAULT = new C509ConversionOptions(true, 0);

    private final boolean pointCompression;
    private final int ecdsaSignatureValueWidth;

    private C509ConversionOptions(boolean pointCompression, int ecdsaSignatureValueWidth)
    {
        this.pointCompression = pointCompression;
        this.ecdsaSignatureValueWidth = ecdsaSignatureValueWidth;
    }

    /**
     * Return a copy of these options with point compression turned on or off. When on
     * (the default), an uncompressed id-ecPublicKey subjectPublicKey is stored in
     * compressed form - for a re-encoded certificate using the 0xfe/0xfd markers of
     * Section 3.2.1 so the original DER can be recovered.
     */
    public C509ConversionOptions withPointCompression(boolean pointCompression)
    {
        return new C509ConversionOptions(pointCompression, ecdsaSignatureValueWidth);
    }

    /**
     * Return a copy of these options with a fixed octet width for the components of an
     * ECDSA style signature value (Section 3.2.2 - for example 32 for P-256). The
     * default of 0 derives the width from the signature's own component lengths,
     * rounded up to the width of the nearest common curve.
     */
    public C509ConversionOptions withEcdsaSignatureValueWidth(int width)
    {
        return new C509ConversionOptions(pointCompression, width);
    }

    boolean isPointCompression()
    {
        return pointCompression;
    }

    int getEcdsaSignatureValueWidth()
    {
        return ecdsaSignatureValueWidth;
    }
}
