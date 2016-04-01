package org.bouncycastle.pqc.crypto.mceliece;


import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode.MaMaPe;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;


/**
 * This class implements key pair generation of the McEliece Public Key
 * Cryptosystem (McEliecePKC).
 */
public class McElieceCCA2KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{


    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

    private McElieceCCA2KeyGenerationParameters mcElieceCCA2Params;

    // the extension degree of the finite field GF(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;

    // the field polynomial
    private int fieldPoly;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;

    /**
     * Default initialization of the key pair generator.
     */
    private void initializeDefault()
    {
        McElieceCCA2KeyGenerationParameters mcCCA2Params = new McElieceCCA2KeyGenerationParameters(new SecureRandom(), new McElieceCCA2Parameters());
        init(mcCCA2Params);
    }

    // TODO
    public void init(
        KeyGenerationParameters param)
    {
        this.mcElieceCCA2Params = (McElieceCCA2KeyGenerationParameters)param;

        // set source of randomness
        this.random = new SecureRandom();

        this.m = this.mcElieceCCA2Params.getParameters().getM();
        this.n = this.mcElieceCCA2Params.getParameters().getN();
        this.t = this.mcElieceCCA2Params.getParameters().getT();
        this.fieldPoly = this.mcElieceCCA2Params.getParameters().getFieldPoly();
        this.initialized = true;
    }


    public AsymmetricCipherKeyPair generateKeyPair()
    {

        if (!initialized)
        {
            initializeDefault();
        }

        // finite field GF(2^m)
        GF2mField field = new GF2mField(m, fieldPoly);

        // irreducible Goppa polynomial
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
            PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);

        // generate canonical check matrix
        GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

        // compute short systematic form of check matrix
        MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
        GF2Matrix shortH = mmp.getSecondMatrix();
        Permutation p = mmp.getPermutation();

        // compute short systematic form of generator matrix
        GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

        // obtain number of rows of G (= dimension of the code)
        int k = shortG.getNumRows();

        // generate keys
        McElieceCCA2PublicKeyParameters pubKey = new McElieceCCA2PublicKeyParameters(n, t, shortG, getDigest(mcElieceCCA2Params.getParameters().getDigest().getAlgorithmName()));
        McElieceCCA2PrivateKeyParameters privKey = new McElieceCCA2PrivateKeyParameters(n, k, field, gp, p, getDigest(mcElieceCCA2Params.getParameters().getDigest().getAlgorithmName()));

        // return key pair
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    static Digest getDigest(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new SHA1Digest();
        }
        if (digestName.equals("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (digestName.equals("SHA-256"))
        {
            return new SHA256Digest();
        }
        if (digestName.equals("SHA-384"))
        {
            return new SHA384Digest();
        }
        if (digestName.equals("SHA-512"))
        {
            return new SHA512Digest();
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
