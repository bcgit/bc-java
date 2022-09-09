package org.bouncycastle.crypto.kems;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
 */
public class ECIESKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private final ECPrivateKeyParameters decKey;
    private int keyLen;
    private DerivationFunction kdf;

    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;

    /**
     * Set up the ECIES-KEM.
     *
     * @param decKey the decryption key.
     * @param keyLen length in bytes of key to generate.
     * @param kdf the key derivation function to be used.
     */
    public ECIESKEMExtractor(
        ECPrivateKeyParameters decKey,
        int keyLen,
        DerivationFunction kdf)
    {
        this.decKey = decKey;
        this.keyLen = keyLen;
        this.kdf = kdf;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    /**
     * Set up the ECIES-KEM.
     *
     * @param decKey          the decryption key.
     * @param keyLen          length in bytes of key to generate.
     * @param kdf             the key derivation function to be used.
     * @param cofactorMode    if true use the new cofactor ECDH.
     * @param oldCofactorMode if true use the old cofactor ECDH.
     * @param singleHashMode  if true use single hash mode.
     */
    public ECIESKEMExtractor(
        ECPrivateKeyParameters decKey,
        int keyLen,
        DerivationFunction kdf,
        boolean cofactorMode,
        boolean oldCofactorMode,
        boolean singleHashMode)
    {
        this.decKey = decKey;
        this.keyLen = keyLen;
        this.kdf = kdf;

        // If both cofactorMode and oldCofactorMode are set to true
        // then the implementation will use the new cofactor ECDH 
        this.CofactorMode = cofactorMode;
        // https://www.shoup.net/iso/std4.pdf, Page 34.
        if (cofactorMode)
        {
            this.OldCofactorMode = false;
        }
        else
        {
            this.OldCofactorMode = oldCofactorMode;
        }
        this.SingleHashMode = singleHashMode;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ECIESKem",
            ConstraintUtils.bitsOfSecurityFor(this.decKey.getParameters().getCurve()), decKey, CryptoServicePurpose.DECRYPTION));
    }

    public byte[] extractSecret(byte[] encapsulation)
    {
        ECPrivateKeyParameters ecPrivKey = this.decKey;
        ECDomainParameters ecParams = ecPrivKey.getParameters();
        ECCurve curve = ecParams.getCurve();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();

        // Decode the ephemeral public key
        // Compute the static-ephemeral key agreement
        ECPoint gHat = curve.decodePoint(encapsulation);
        if ((CofactorMode) || (OldCofactorMode))
        {
            gHat = gHat.multiply(h);
        }

        BigInteger xHat = ecPrivKey.getD();
        if (CofactorMode)
        {
            xHat = xHat.multiply(ecParams.getHInv()).mod(n);
        }

        ECPoint hTilde = gHat.multiply(xHat).normalize();

        // Encode the shared secret value
        byte[] PEH = hTilde.getAffineXCoord().getEncoded();

        return ECIESKEMGenerator.deriveKey(SingleHashMode, kdf, keyLen, encapsulation, PEH);
    }

    public int getEncapsulationLength()
    {
        return (decKey.getParameters().getCurve().getFieldSize() / 8) * 2 + 1;
    }
}
