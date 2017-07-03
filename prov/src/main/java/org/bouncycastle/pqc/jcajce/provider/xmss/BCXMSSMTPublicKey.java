package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSMTPublicKey
    implements PublicKey, XMSSMTKey
{
    private final ASN1ObjectIdentifier treeDigest;
    private final XMSSMTPublicKeyParameters keyParams;

    public BCXMSSMTPublicKey(ASN1ObjectIdentifier treeDigest, XMSSMTPublicKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSMTPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        XMSSMTKeyParams keyParams = XMSSMTKeyParams.getInstance(keyInfo.getAlgorithm().getParameters());
        this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

        XMSSPublicKey xmssMtPublicKey = XMSSPublicKey.getInstance(keyInfo.parsePublicKey());

        this.keyParams = new XMSSMTPublicKeyParameters
            .Builder(new XMSSMTParameters(keyParams.getHeight(), keyParams.getLayers(), DigestUtil.getDigest(treeDigest)))
            .withPublicSeed(xmssMtPublicKey.getPublicSeed())
            .withRoot(xmssMtPublicKey.getRoot()).build();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSMTPublicKey)
        {
            BCXMSSMTPublicKey otherKey = (BCXMSSMTPublicKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(keyParams.toByteArray());
    }

    /**
     * @return name of the algorithm - "XMSSMT"
     */
    public final String getAlgorithm()
    {
        return "XMSSMT";
    }

    public byte[] getEncoded()
    {
        SubjectPublicKeyInfo pki;
        try
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(keyParams.getParameters().getHeight(), keyParams.getParameters().getLayers(), new AlgorithmIdentifier(treeDigest)));
            pki = new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(keyParams.getPublicSeed(), keyParams.getRoot()));

            return pki.getEncoded();
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

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public int getLayers()
    {
        return keyParams.getParameters().getLayers();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest);
    }
}
