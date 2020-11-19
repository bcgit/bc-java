package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Strings;

public class BCDSAPublicKey
    implements DSAPublicKey
{
    private static final long serialVersionUID = 1752452449903495175L;
    private static BigInteger ZERO = BigInteger.valueOf(0);

    private BigInteger      y;

    private transient DSAPublicKeyParameters lwKeyParams;
    private transient DSAParams              dsaSpec;

    BCDSAPublicKey(
        DSAPublicKeySpec spec)
    {
        this.y = spec.getY();
        this.dsaSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
        this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
    }

    BCDSAPublicKey(
        DSAPublicKey key)
    {
        this.y = key.getY();
        this.dsaSpec = key.getParams();
        this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
    }

    BCDSAPublicKey(
        DSAPublicKeyParameters params)
    {
        this.y = params.getY();
        if (params.getParameters() != null)
        {
            this.dsaSpec = new DSAParameterSpec(params.getParameters().getP(), params.getParameters().getQ(), params.getParameters().getG());
        }
        else
        {
            this.dsaSpec = null;
        }
        this.lwKeyParams = params;
    }

    public BCDSAPublicKey(
        SubjectPublicKeyInfo info)
    {
        ASN1Integer              derY;

        try
        {
            derY = (ASN1Integer)info.parsePublicKey();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in DSA public key");
        }

        this.y = derY.getValue();

        if (isNotNull(info.getAlgorithm().getParameters()))
        {
            DSAParameter params = DSAParameter.getInstance(info.getAlgorithm().getParameters());
            
            this.dsaSpec = new DSAParameterSpec(params.getP(), params.getQ(), params.getG());
        }
        else
        {
            this.dsaSpec = null;
        }

        this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
    }

    private boolean isNotNull(ASN1Encodable parameters)
    {
        return parameters != null && !DERNull.INSTANCE.equals(parameters.toASN1Primitive());
    }

    public String getAlgorithm()
    {
        return "DSA";
    }

    public String getFormat()
    {
        return "X.509";
    }

    DSAPublicKeyParameters engineGetKeyParameters()
    {
        return lwKeyParams;
    }

    public byte[] getEncoded()
    {
        if (dsaSpec == null)
        {
            return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new ASN1Integer(y));
        }

        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()).toASN1Primitive()), new ASN1Integer(y));
    }

    public DSAParams getParams()
    {
        return dsaSpec;
    }

    public BigInteger getY()
    {
        return y;
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = Strings.lineSeparator();

        buf.append("DSA Public Key [").append(DSAUtil.generateKeyFingerprint(y, getParams())).append("]").append(nl);
        buf.append("            Y: ").append(this.getY().toString(16)).append(nl);

        return buf.toString();
    }

    public int hashCode()
    {
        if (dsaSpec != null)
        {
            return this.getY().hashCode() ^ this.getParams().getG().hashCode()
                ^ this.getParams().getP().hashCode() ^ this.getParams().getQ().hashCode();
        }
        else
        {
            return this.getY().hashCode();
        }
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DSAPublicKey))
        {
            return false;
        }
        
        DSAPublicKey other = (DSAPublicKey)o;

        if (this.dsaSpec != null)
        {
            return this.getY().equals(other.getY())
                && other.getParams() != null
                && this.getParams().getG().equals(other.getParams().getG())
                && this.getParams().getP().equals(other.getParams().getP())
                && this.getParams().getQ().equals(other.getParams().getQ());
        }
        else
        {
            return this.getY().equals(other.getY()) && other.getParams() == null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        BigInteger p = (BigInteger)in.readObject();
        if (p.equals(ZERO))
        {
            this.dsaSpec = null;
        }
        else
        {
            this.dsaSpec = new DSAParameterSpec(p, (BigInteger)in.readObject(), (BigInteger)in.readObject());
        }
        this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        if (dsaSpec == null)
        {
            out.writeObject(ZERO);
        }
        else
        {
            out.writeObject(dsaSpec.getP());
            out.writeObject(dsaSpec.getQ());
            out.writeObject(dsaSpec.getG());
        }
    }
}
