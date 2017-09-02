package org.bouncycastle.pqc.jcajce.provider.mceliece;


import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 * This class implements a McEliece CCA2 public key and is usually instantiated
 * by the {@link McElieceCCA2KeyPairGenerator} or {@link McElieceCCA2KeyFactorySpi}.
 */
public class BCMcElieceCCA2PublicKey
    implements CipherParameters, PublicKey
{
    private static final long serialVersionUID = 1L;

    private McElieceCCA2PublicKeyParameters params;

    public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeyParameters params)
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
        return "McEliece-CCA2";
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
     * @return the error correction capability of the code
     */
    public int getT()
    {
        return params.getT();
    }

    /**
     * @return the generator matrix
     */
    public GF2Matrix getG()
    {
        return params.getG();
    }

    /**
     * @return a human readable form of the key
     */
    public String toString()
    {
        String result = "McEliecePublicKey:\n";
        result += " length of the code         : " + params.getN() + "\n";
        result += " error correction capability: " + params.getT() + "\n";
        result += " generator matrix           : " + params.getG().toString();
        return result;
    }

    /**
     * Compare this key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other)
    {
        if (other == null || !(other instanceof BCMcElieceCCA2PublicKey))
        {
            return false;
        }

        BCMcElieceCCA2PublicKey otherKey = (BCMcElieceCCA2PublicKey)other;

        return (params.getN() == otherKey.getN()) && (params.getT() == otherKey.getT()) && (params.getG().equals(otherKey.getG()));
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode()
    {
        return 37 * (params.getN() + 37 * params.getT()) + params.getG().hashCode();
    }

    /**
     * Return the keyData to encode in the SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * <pre>
     *       McEliecePublicKey ::= SEQUENCE {
     *         n           Integer      -- length of the code
     *         t           Integer      -- error correcting capability
     *         matrixG     OctetString  -- generator matrix as octet string
     *       }
     * </pre>
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    public byte[] getEncoded()
    {
        McElieceCCA2PublicKey key = new McElieceCCA2PublicKey(params.getN(), params.getT(), params.getG(), Utils.getDigAlgId(params.getDigest()));
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);

        try
        {
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, key);

            return subjectPublicKeyInfo.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }

    }

    public String getFormat()
    {
        return "X.509";
    }

    AsymmetricKeyParameter getKeyParams()
    {
        return params;
    }
}
