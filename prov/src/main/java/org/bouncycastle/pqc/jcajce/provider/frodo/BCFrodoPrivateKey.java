package org.bouncycastle.pqc.jcajce.provider.frodo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.FrodoKey;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public class BCFrodoPrivateKey
    implements PrivateKey, FrodoKey
{
    private static final long serialVersionUID = 1L;

    private transient FrodoPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCFrodoPrivateKey(
            FrodoPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCFrodoPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (FrodoPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this private key with another object.
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

        if (o instanceof BCFrodoPrivateKey)
        {
            BCFrodoPrivateKey otherKey = (BCFrodoPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCFrodoPublicKey getPublicKey()
    {
        byte[] sk = params.getPrivateKey();
        int sBytes = params.getParameters().getSessionKeySize() / 8;
        int n = frodoN(params.getParameters());
        int pkSize = sk.length - (sBytes << 1) - (n << 4);
        byte[] pk = Arrays.copyOfRange(sk, sBytes, sBytes + pkSize);
        return new BCFrodoPublicKey(new FrodoPublicKeyParameters(params.getParameters(), pk));
    }

    private static int frodoN(org.bouncycastle.pqc.crypto.frodo.FrodoParameters params)
    {
        String name = params.getName();
        if (name.indexOf("640") >= 0)
        {
            return 640;
        }
        if (name.indexOf("976") >= 0)
        {
            return 976;
        }
        if (name.indexOf("1344") >= 0)
        {
            return 1344;
        }
        throw new IllegalStateException("unknown Frodo parameter set: " + name);
    }

    /**
     * @return name of the algorithm - "Frodo"
     */
    public final String getAlgorithm()
    {
        return "Frodo";
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

    public FrodoParameterSpec getParameterSpec()
    {
        return FrodoParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    FrodoPrivateKeyParameters getKeyParams()
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
