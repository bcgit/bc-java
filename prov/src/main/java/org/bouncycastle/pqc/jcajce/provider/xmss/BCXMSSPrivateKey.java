package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSPrivateKey
    implements PrivateKey, XMSSKey
{
    private final XMSSPrivateKeyParameters keyParams;
    private final ASN1ObjectIdentifier treeDigest;

    public BCXMSSPrivateKey(
        ASN1ObjectIdentifier treeDigest,
        XMSSPrivateKeyParameters keyParams)
    {
        this.treeDigest = treeDigest;
        this.keyParams = keyParams;
    }

    public BCXMSSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        XMSSKeyParams keyParams = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
        this.treeDigest = keyParams.getTreeDigest().getAlgorithm();

        XMSSPrivateKey xmssPrivateKey = XMSSPrivateKey.getInstance(keyInfo.parsePrivateKey());

        try
        {
            XMSSPrivateKeyParameters.Builder keyBuilder = new XMSSPrivateKeyParameters
                .Builder(new XMSSParameters(keyParams.getHeight(), DigestUtil.getDigest(treeDigest)))
                .withIndex(xmssPrivateKey.getIndex())
                .withSecretKeySeed(xmssPrivateKey.getSecretKeySeed())
                .withSecretKeyPRF(xmssPrivateKey.getSecretKeyPRF())
                .withPublicSeed(xmssPrivateKey.getPublicSeed())
                .withRoot(xmssPrivateKey.getRoot());

            if (xmssPrivateKey.getBdsState() != null)
            {
                keyBuilder.withBDSState((BDS)XMSSUtil.deserialize(xmssPrivateKey.getBdsState()));
            }

            this.keyParams = keyBuilder.build();
        }
        catch (ClassNotFoundException e)
        {
            throw new IOException("ClassNotFoundException processing BDS state: " + e.getMessage());
        }
    }

    public String getAlgorithm()
    {
        return "XMSS";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        PrivateKeyInfo pki;
        try
        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss, new XMSSKeyParams(keyParams.getParameters().getHeight(), new AlgorithmIdentifier(treeDigest)));
            pki = new PrivateKeyInfo(algorithmIdentifier, createKeyStructure());

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCXMSSPrivateKey)
        {
            BCXMSSPrivateKey otherKey = (BCXMSSPrivateKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(keyParams.toByteArray(), otherKey.keyParams.toByteArray());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(keyParams.toByteArray());
    }

    CipherParameters getKeyParams()
    {
        return keyParams;
    }

    private XMSSPrivateKey createKeyStructure()
    {
        byte[] keyData = keyParams.toByteArray();

        int n = keyParams.getParameters().getDigestSize();
        int totalHeight = keyParams.getParameters().getHeight();
        int indexSize = 4;
        int secretKeySize = n;
        int secretKeyPRFSize = n;
        int publicSeedSize = n;
        int rootSize = n;

        int position = 0;
        int index = (int)XMSSUtil.bytesToXBigEndian(keyData, position, indexSize);
        if (!XMSSUtil.isIndexValid(totalHeight, index))
        {
            throw new IllegalArgumentException("index out of bounds");
        }
        position += indexSize;
        byte[] secretKeySeed = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeySize);
        position += secretKeySize;
        byte[] secretKeyPRF = XMSSUtil.extractBytesAtOffset(keyData, position, secretKeyPRFSize);
        position += secretKeyPRFSize;
        byte[] publicSeed = XMSSUtil.extractBytesAtOffset(keyData, position, publicSeedSize);
        position += publicSeedSize;
        byte[] root = XMSSUtil.extractBytesAtOffset(keyData, position, rootSize);
        position += rootSize;
               /* import BDS state */
        byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(keyData, position, keyData.length - position);

        return new XMSSPrivateKey(index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsStateBinary);
    }

    ASN1ObjectIdentifier getTreeDigestOID()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return keyParams.getParameters().getHeight();
    }

    public String getTreeDigest()
    {
        return DigestUtil.getXMSSDigestName(treeDigest);
    }
}
