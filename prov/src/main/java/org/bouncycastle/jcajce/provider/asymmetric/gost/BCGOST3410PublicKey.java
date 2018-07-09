package org.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.GOST3410Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jce.interfaces.GOST3410Params;
import org.bouncycastle.jce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeySpec;

public class BCGOST3410PublicKey
    implements GOST3410PublicKey
{
    static final long serialVersionUID = -6251023343619275990L;

    private BigInteger      y;
    private transient GOST3410Params  gost3410Spec;

    BCGOST3410PublicKey(
        GOST3410PublicKeySpec spec)
    {
        this.y = spec.getY();
        this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
    }

    BCGOST3410PublicKey(
        GOST3410PublicKey key)
    {
        this.y = key.getY();
        this.gost3410Spec = key.getParameters();
    }

    BCGOST3410PublicKey(
        GOST3410PublicKeyParameters params,
        GOST3410ParameterSpec spec)
    {
        this.y = params.getY();
        this.gost3410Spec = spec;
    }

    BCGOST3410PublicKey(
        BigInteger y,
        GOST3410ParameterSpec gost3410Spec)
    {
        this.y = y;
        this.gost3410Spec = gost3410Spec;
    }

    BCGOST3410PublicKey(
        SubjectPublicKeyInfo info)
    {
        GOST3410PublicKeyAlgParameters    params = GOST3410PublicKeyAlgParameters.getInstance(info.getAlgorithm().getParameters());
        DEROctetString                    derY;

        try
        {
            derY = (DEROctetString)info.parsePublicKey();
            
            byte[]                  keyEnc = derY.getOctets();
            byte[]                  keyBytes = new byte[keyEnc.length];
            
            for (int i = 0; i != keyEnc.length; i++)
            {
                keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // was little endian
            }

            this.y = new BigInteger(1, keyBytes);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in GOST3410 public key");
        }

        this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(params);
    }

    public String getAlgorithm()
    {
        return "GOST3410";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        SubjectPublicKeyInfo    info;
        byte[]                  keyEnc = this.getY().toByteArray();
        byte[]                  keyBytes;
        
        if (keyEnc[0] == 0)
        {
            keyBytes = new byte[keyEnc.length - 1];
        }
        else
        {
            keyBytes = new byte[keyEnc.length];
        }
        
        for (int i = 0; i != keyBytes.length; i++)
        {
            keyBytes[i] = keyEnc[keyEnc.length - 1 - i]; // must be little endian
        }

        try
        {
            if (gost3410Spec instanceof GOST3410ParameterSpec)
            {
                if (gost3410Spec.getEncryptionParamSetOID() != null)
                {
                    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getDigestParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getEncryptionParamSetOID()))), new DEROctetString(keyBytes));
                }
                else
                {
                    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getDigestParamSetOID()))), new DEROctetString(keyBytes));
                }
            }
            else
            {
                info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(keyBytes));
            }

            return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public GOST3410Params getParameters()
    {
        return gost3410Spec;
    }

    public BigInteger getY()
    {
        return y;
    }

    public String toString()
    {
        try
        {
            return GOSTUtil.publicKeyToString("GOST3410", y,
                ((GOST3410PublicKeyParameters)GOST3410Util.generatePublicKeyParameter(this)).getParameters());
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException(e.getMessage()); // should not be possible
        }
    }
    
    public boolean equals(Object o)
    {
        if (o instanceof BCGOST3410PublicKey)
        {
            BCGOST3410PublicKey other = (BCGOST3410PublicKey)o;
            
            return this.y.equals(other.y) && this.gost3410Spec.equals(other.gost3410Spec);
        }
        
        return false;
    }
    
    public int hashCode()
    {
        return y.hashCode() ^ gost3410Spec.hashCode();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        String publicKeyParamSetOID = (String)in.readObject();
        if (publicKeyParamSetOID != null)
        {
            this.gost3410Spec = new GOST3410ParameterSpec(publicKeyParamSetOID, (String)in.readObject(), (String)in.readObject());
        }
        else
        {
            this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec((BigInteger)in.readObject(), (BigInteger)in.readObject(), (BigInteger)in.readObject()));
            in.readObject();
            in.readObject();
        }
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        if (gost3410Spec.getPublicKeyParamSetOID() != null)
        {
            out.writeObject(gost3410Spec.getPublicKeyParamSetOID());
            out.writeObject(gost3410Spec.getDigestParamSetOID());
            out.writeObject(gost3410Spec.getEncryptionParamSetOID());
        }
        else
        {
            out.writeObject(null);
            out.writeObject(gost3410Spec.getPublicKeyParameters().getP());
            out.writeObject(gost3410Spec.getPublicKeyParameters().getQ());
            out.writeObject(gost3410Spec.getPublicKeyParameters().getA());
            out.writeObject(gost3410Spec.getDigestParamSetOID());
            out.writeObject(gost3410Spec.getEncryptionParamSetOID());
        }
    }
}
