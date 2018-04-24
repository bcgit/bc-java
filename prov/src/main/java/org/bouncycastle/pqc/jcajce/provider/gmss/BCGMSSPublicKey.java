package org.bouncycastle.pqc.jcajce.provider.gmss;

import java.security.PublicKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.GMSSPublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.ParSet;
import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
import org.bouncycastle.pqc.crypto.gmss.GMSSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class implements the GMSS public key and is usually initiated by the <a
 * href="GMSSKeyPairGenerator">GMSSKeyPairGenerator</a>.
 *
 * @see org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator
 */
public class BCGMSSPublicKey
    implements CipherParameters, PublicKey
{

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    /**
     * The GMSS public key
     */
    private byte[] publicKeyBytes;

    /**
     * The GMSSParameterSet
     */
    private GMSSParameters gmssParameterSet;


    private GMSSParameters gmssParams;

    /**
     * The constructor
     *
     * @param pub              a raw GMSS public key
     * @param gmssParameterSet an instance of GMSS Parameterset
     * @see org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator
     */
    public BCGMSSPublicKey(byte[] pub, GMSSParameters gmssParameterSet)
    {
        this.gmssParameterSet = gmssParameterSet;
        this.publicKeyBytes = pub;
    }

    public BCGMSSPublicKey(
        GMSSPublicKeyParameters params)
    {
        this(params.getPublicKey(), params.getParameters());
    }

    /**
     * Returns the name of the algorithm
     *
     * @return "GMSS"
     */
    public String getAlgorithm()
    {
        return "GMSS";
    }

    /**
     * @return The GMSS public key byte array
     */
    public byte[] getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    /**
     * @return The GMSS Parameterset
     */
    public GMSSParameters getParameterSet()
    {
        return gmssParameterSet;
    }

    /**
     * Returns a human readable form of the GMSS public key
     *
     * @return A human readable form of the GMSS public key
     */
    public String toString()
    {
        String out = "GMSS public key : "
            + new String(Hex.encode(publicKeyBytes)) + "\n"
            + "Height of Trees: \n";

        for (int i = 0; i < gmssParameterSet.getHeightOfTrees().length; i++)
        {
            out = out + "Layer " + i + " : "
                + gmssParameterSet.getHeightOfTrees()[i]
                + " WinternitzParameter: "
                + gmssParameterSet.getWinternitzParameter()[i] + " K: "
                + gmssParameterSet.getK()[i] + "\n";
        }
        return out;
    }

    public byte[] getEncoded()
    {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.gmss, new ParSet(gmssParameterSet.getNumOfLayers(), gmssParameterSet.getHeightOfTrees(), gmssParameterSet.getWinternitzParameter(), gmssParameterSet.getK()).toASN1Primitive()), new GMSSPublicKey(publicKeyBytes));
    }

    public String getFormat()
    {
        return "X.509";
    }
}
