package org.bouncycastle.jcajce.provider.symmetric.util;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class BCPBEKey
    implements PBEKey, Destroyable
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    String              algorithm;
    ASN1ObjectIdentifier oid;
    int                 type;
    int                 digest;
    int                 keySize;
    int                 ivSize;

    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;

    private final CipherParameters    param;

    boolean             tryWrong = false;

    /**
     * @param param
     */
    public BCPBEKey(
        String algorithm,
        ASN1ObjectIdentifier oid,
        int type,
        int digest,
        int keySize,
        int ivSize,
        PBEKeySpec pbeKeySpec,
        CipherParameters param)
    {
        this.algorithm = algorithm;
        this.oid = oid;
        this.type = type;
        this.digest = digest;
        this.keySize = keySize;
        this.ivSize = ivSize;
        this.password = pbeKeySpec.getPassword();
        this.iterationCount = pbeKeySpec.getIterationCount();
        this.salt = pbeKeySpec.getSalt();
        this.param = param;
    }

    public BCPBEKey(String algName, CipherParameters param)
    {
        this.algorithm = algName;
        this.param = param;
        this.password = null;
        this.iterationCount = -1;
        this.salt = null;
    }

    public String getAlgorithm()
    {
        String rv = this.algorithm;

        checkDestroyed(this);

        return rv;
    }

    public String getFormat()
    {
        checkDestroyed(this);

        return "RAW";
    }

    public byte[] getEncoded()
    {
        byte[] enc;

        if (param != null)
        {
            KeyParameter    kParam;
            
            if (param instanceof ParametersWithIV)
            {
                kParam = (KeyParameter)((ParametersWithIV)param).getParameters();
            }
            else
            {
                kParam = (KeyParameter)param;
            }
            
            enc = kParam.getKey();
        }
        else
        {
            if (type == PBE.PKCS12)
            {
                enc = PBEParametersGenerator.PKCS12PasswordToBytes(password);
            }
            else if (type == PBE.PKCS5S2_UTF8)
            {
                enc = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
            }
            else
            {   
                enc = PBEParametersGenerator.PKCS5PasswordToBytes(password);
            }
        }

        checkDestroyed(this);

        return enc;
    }
    
    int getType()
    {
        int rv = type;

        checkDestroyed(this);

        return rv;
    }
    
    int getDigest()
    {
        int rv = digest;

        checkDestroyed(this);

        return rv;
    }
    
    int getKeySize()
    {
        int rv = keySize;

        checkDestroyed(this);

        return rv;
    }
    
    public int getIvSize()
    {
        int rv = ivSize;

        checkDestroyed(this);

        return rv;
    }
    
    public CipherParameters getParam()
    {
        CipherParameters rv = param;

        checkDestroyed(this);

        return rv;
    }

    /* (non-Javadoc)
     * @see javax.crypto.interfaces.PBEKey#getPassword()
     */
    public char[] getPassword()
    {
        char[] clone = Arrays.clone(password);

        checkDestroyed(this);

        if (clone == null)
        {
            throw new IllegalStateException("no password available");
        }

        return clone;
    }

    /* (non-Javadoc)
     * @see javax.crypto.interfaces.PBEKey#getSalt()
     */
    public byte[] getSalt()
    {
        byte[] clone = Arrays.clone(salt);

        checkDestroyed(this);

        return clone;
    }

    /* (non-Javadoc)
     * @see javax.crypto.interfaces.PBEKey#getIterationCount()
     */
    public int getIterationCount()
    {
        int rv = iterationCount;

        checkDestroyed(this);

        return rv;
    }
    
    public ASN1ObjectIdentifier getOID()
    {
        ASN1ObjectIdentifier rv = oid;

        checkDestroyed(this);

        return rv;
    }
    
    public void setTryWrongPKCS12Zero(boolean tryWrong)
    {
        this.tryWrong = tryWrong; 
    }
    
    boolean shouldTryWrongPKCS12()
    {
        return tryWrong;
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            if (password != null)
            {
                Arrays.fill(password, (char)0);
            }
            if (salt != null)
            {
                Arrays.fill(salt, (byte)0);
            }
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    static void checkDestroyed(Destroyable destroyable)
    {
        if (destroyable.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }
}