package org.bouncycastle.pqc.jcajce.provider.sphincs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSKey;
import org.bouncycastle.util.Arrays;

public class BCSphincs256PrivateKey
    implements PrivateKey, SPHINCSKey
{
    private static final long serialVersionUID = 1L;

    private transient ASN1ObjectIdentifier treeDigest;
    private transient SPHINCSPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSphincs256PrivateKey(
        ASN1ObjectIdentifier treeDigest,
        SPHINCSPrivateKeyParameters params)
    {
        this.treeDigest = treeDigest;
        this.params = params;
    }

    public BCSphincs256PrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.params = (SPHINCSPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SPHINCS-256 private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCSphincs256PrivateKey)
        {
            BCSphincs256PrivateKey otherKey = (BCSphincs256PrivateKey)o;

            return treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(params.getKeyData(), otherKey.params.getKeyData());
        }

        return false;
    }

    public int hashCode()
    {
        return treeDigest.hashCode() + 37 * Arrays.hashCode(params.getKeyData());
    }

    /**
     * @return name of the algorithm - "SPHINCS-256"
     */
    public final String getAlgorithm()
    {
        return "SPHINCS-256";
    }

    public byte[] getEncoded()
    {

        try
        {
            PrivateKeyInfo pki;
            if (params.getTreeDigest() != null)
            {
                pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);
            }
            else
            {
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                    new SPHINCS256KeyParams(new AlgorithmIdentifier(treeDigest)));
                pki = new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getKeyData()), attributes);
            }

            return pki.getEncoded();
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

    ASN1ObjectIdentifier getTreeDigest()
    {
        return treeDigest;
    }
    
    public byte[] getKeyData()
    {
        return params.getKeyData();
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
