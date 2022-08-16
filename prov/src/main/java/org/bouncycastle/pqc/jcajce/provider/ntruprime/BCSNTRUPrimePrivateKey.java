package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SNTRUPrimeKey;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCSNTRUPrimePrivateKey
    implements PrivateKey, SNTRUPrimeKey
{
    private static final long serialVersionUID = 1L;

    private transient SNTRUPrimePrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSNTRUPrimePrivateKey(
        SNTRUPrimePrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSNTRUPrimePrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SNTRUPrimePrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
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

        if (o instanceof BCSNTRUPrimePrivateKey)
        {
            BCSNTRUPrimePrivateKey otherKey = (BCSNTRUPrimePrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "NTRULPRime"
     */
    public final String getAlgorithm()
    {
        return "NTRULPRime";
    }

    public byte[] getEncoded()
    {

        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public SNTRUPrimeParameterSpec getParameterSpec()
    {
        return SNTRUPrimeParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SNTRUPrimePrivateKeyParameters getKeyParams()
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
