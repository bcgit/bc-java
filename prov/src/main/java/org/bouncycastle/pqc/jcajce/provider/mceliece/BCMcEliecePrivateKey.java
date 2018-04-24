package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McEliecePrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 * This class implements a McEliece private key and is usually instantiated by
 * the {@link McElieceKeyPairGenerator} or {@link McElieceKeyFactorySpi}.
 */
public class BCMcEliecePrivateKey
    implements CipherParameters, PrivateKey
{
    private static final long serialVersionUID = 1L;

    private McEliecePrivateKeyParameters params;

    public BCMcEliecePrivateKey(McEliecePrivateKeyParameters params)
    {
        this.params = params;
    }

    /**
     * Return the name of the algorithm.
     *
     * @return "McEliece"
     */
    public String getAlgorithm()
    {
        return "McEliece";
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return params.getN();
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return params.getK();
    }

    /**
     * @return the finite field
     */
    public GF2mField getField()
    {
        return params.getField();
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return params.getGoppaPoly();
    }

    /**
     * @return the k x k random binary non-singular matrix S
     */
    public GF2Matrix getSInv()
    {
        return params.getSInv();
    }

    /**
     * @return the permutation used to generate the systematic check matrix
     */
    public Permutation getP1()
    {
        return params.getP1();
    }

    /**
     * @return the permutation used to compute the public generator matrix
     */
    public Permutation getP2()
    {
        return params.getP2();
    }

    /**
     * @return the canonical check matrix
     */
    public GF2Matrix getH()
    {
        return params.getH();
    }

    /**
     * @return the matrix for computing square roots in <tt>(GF(2^m))^t</tt>
     */
    public PolynomialGF2mSmallM[] getQInv()
    {
        return params.getQInv();
    }

    /*
     * @return a human readable form of the key
     */
    // TODO:
//    public String toString()
//    {
//        String result = " length of the code          : " + getN() + Strings.lineSeparator();
//        result += " dimension of the code       : " + getK() + Strings.lineSeparator();
//        result += " irreducible Goppa polynomial: " + getGoppaPoly() + Strings.lineSeparator();
//        result += " permutation P1              : " + getP1() + Strings.lineSeparator();
//        result += " permutation P2              : " + getP2() + Strings.lineSeparator();
//        result += " (k x k)-matrix S^-1         : " + getSInv();
//        return result;
//    }

    /**
     * Compare this key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other)
    {
        if (!(other instanceof BCMcEliecePrivateKey))
        {
            return false;
        }
        BCMcEliecePrivateKey otherKey = (BCMcEliecePrivateKey)other;

        return (getN() == otherKey.getN()) && (getK() == otherKey.getK())
            && getField().equals(otherKey.getField())
            && getGoppaPoly().equals(otherKey.getGoppaPoly())
            && getSInv().equals(otherKey.getSInv()) && getP1().equals(otherKey.getP1())
            && getP2().equals(otherKey.getP2());
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode()
    {
        int code = params.getK();

        code = code * 37 + params.getN();
        code = code * 37 + params.getField().hashCode();
        code = code * 37 + params.getGoppaPoly().hashCode();
        code = code * 37 + params.getP1().hashCode();
        code = code * 37 + params.getP2().hashCode();

        return code * 37 + params.getSInv().hashCode();
    }

    /**
     * Return the key data to encode in the SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * </p>
     * <pre>
     *   McEliecePrivateKey ::= SEQUENCE {
     *     n          INTEGER                   -- length of the code
     *     k          INTEGER                   -- dimension of the code
     *     fieldPoly  OCTET STRING              -- field polynomial defining GF(2&circ;m)
     *     getGoppaPoly()  OCTET STRING              -- irreducible Goppa polynomial
     *     sInv       OCTET STRING              -- matrix S&circ;-1
     *     p1         OCTET STRING              -- permutation P1
     *     p2         OCTET STRING              -- permutation P2
     *     h          OCTET STRING              -- canonical check matrix
     *     qInv       SEQUENCE OF OCTET STRING  -- matrix used to compute square roots
     *   }
     * </pre>
     *
     * @return the key data to encode in the SubjectPublicKeyInfo structure
     */
    public byte[] getEncoded()
    {
        McEliecePrivateKey privateKey = new McEliecePrivateKey(params.getN(), params.getK(), params.getField(), params.getGoppaPoly(), params.getP1(), params.getP2(), params.getSInv());
        PrivateKeyInfo pki;
        try
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcEliece);
            pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);
        }
        catch (IOException e)
        {
            return null;
        }
        try
        {
            byte[] encoded = pki.getEncoded();
            return encoded;
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    AsymmetricKeyParameter getKeyParams()
    {
        return params;
    }
}
