package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

public class BCDHPublicKey
    implements DHPublicKey
{
    static final long serialVersionUID = -216691575254424324L;
    
    private BigInteger              y;

    private transient DHPublicKeyParameters   dhPublicKey;
    private transient DHParameterSpec         dhSpec;
    private transient SubjectPublicKeyInfo    info;
    
    BCDHPublicKey(
        DHPublicKeySpec spec)
    {
        this.y = spec.getY();
        this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(spec.getP(), spec.getG()));
    }

    BCDHPublicKey(
        DHPublicKey key)
    {
        this.y = key.getY();
        this.dhSpec = key.getParams();
        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
    }

    BCDHPublicKey(
        DHPublicKeyParameters params)
    {
        this.y = params.getY();
        this.dhSpec = new DHParameterSpec(params.getParameters().getP(), params.getParameters().getG(), params.getParameters().getL());
        this.dhPublicKey = params;
    }

    BCDHPublicKey(
        BigInteger y,
        DHParameterSpec dhSpec)
    {
        this.y = y;
        this.dhSpec = dhSpec;
        this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
    }

    public BCDHPublicKey(
        SubjectPublicKeyInfo info)
    {
        this.info = info;

        ASN1Integer              derY;
        try
        {
            derY = (ASN1Integer)info.parsePublicKey();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in DH public key");
        }

        this.y = derY.getValue();

        ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithm().getParameters());
        ASN1ObjectIdentifier id = info.getAlgorithm().getAlgorithm();

        // we need the PKCS check to handle older keys marked with the X9 oid.
        if (id.equals(PKCSObjectIdentifiers.dhKeyAgreement) || isPKCSParam(seq))
        {
            DHParameter             params = DHParameter.getInstance(seq);

            if (params.getL() != null)
            {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG(), params.getL().intValue());
            }
            else
            {
                this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
            }
            this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
        }
        else if (id.equals(X9ObjectIdentifiers.dhpublicnumber))
        {
            DomainParameters params = DomainParameters.getInstance(seq);

            this.dhSpec = new DHParameterSpec(params.getP(), params.getG());
            ValidationParams validationParams = params.getValidationParams();
            if (validationParams != null)
            {
                this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(params.getP(), params.getG(), params.getQ(), params.getJ(),
                                            new DHValidationParameters(validationParams.getSeed(), validationParams.getPgenCounter().intValue())));
            }
            else
            {
                this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(params.getP(), params.getG(), params.getQ(), params.getJ(), null));
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown algorithm type: " + id);
        }
    }

    public String getAlgorithm()
    {
        return "DH";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        if (info != null)
        {
            return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
        }

        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.dhKeyAgreement, new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL()).toASN1Primitive()), new ASN1Integer(y));
    }

    public DHParameterSpec getParams()
    {
        return dhSpec;
    }

    public BigInteger getY()
    {
        return y;
    }

    public DHPublicKeyParameters engineGetKeyParameters()
    {
        return dhPublicKey;
    }

    private boolean isPKCSParam(ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            return true;
        }
        
        if (seq.size() > 3)
        {
            return false;
        }

        ASN1Integer l = ASN1Integer.getInstance(seq.getObjectAt(2));
        ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));

        if (l.getValue().compareTo(BigInteger.valueOf(p.getValue().bitLength())) > 0)
        {
            return false;
        }

        return true;
    }

    public int hashCode()
    {
        return this.getY().hashCode() ^ this.getParams().getG().hashCode()
                ^ this.getParams().getP().hashCode() ^ this.getParams().getL();
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHPublicKey))
        {
            return false;
        }

        DHPublicKey other = (DHPublicKey)o;

        return this.getY().equals(other.getY())
            && this.getParams().getG().equals(other.getParams().getG())
            && this.getParams().getP().equals(other.getParams().getP())
            && this.getParams().getL() == other.getParams().getL();
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        this.dhSpec = new DHParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject(), in.readInt());
        this.info = null;
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(dhSpec.getP());
        out.writeObject(dhSpec.getG());
        out.writeInt(dhSpec.getL());
    }
}
