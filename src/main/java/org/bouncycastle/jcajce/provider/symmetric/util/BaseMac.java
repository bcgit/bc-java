package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.macs.OldHMac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BaseMac
    extends MacSpi implements PBE
{
    private Mac macEngine;

    private int                     pbeType = PKCS12;
    private int                     pbeHash = SHA1;
    private int                     keySize = 160;

    protected BaseMac(
        Mac macEngine)
    {
        this.macEngine = macEngine;
    }

    protected BaseMac(
        Mac macEngine,
        int pbeType,
        int pbeHash,
        int keySize)
    {
        this.macEngine = macEngine;
        this.pbeType = pbeType;
        this.pbeHash = pbeHash;
        this.keySize = keySize;
    }

    protected void engineInit(
        Key                     key,
        AlgorithmParameterSpec  params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        CipherParameters        param;

        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }

        if (key instanceof BCPBEKey)
        {
            BCPBEKey k = (BCPBEKey)key;

            if (k.getParam() != null)
            {
                param = k.getParam();
            }
            else if (params instanceof PBEParameterSpec)
            {
                param = PBE.Util.makePBEMacParameters(k, params);
            }
            else
            {
                throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
            }
        }
        else if (params instanceof IvParameterSpec)
        {
            param = new ParametersWithIV(new KeyParameter(key.getEncoded()), ((IvParameterSpec)params).getIV());
        }
        else if (params == null)
        {
            param = new KeyParameter(key.getEncoded());
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown parameter type.");
        }

        macEngine.init(param);
    }

    protected int engineGetMacLength() 
    {
        return macEngine.getMacSize();
    }

    protected void engineReset() 
    {
        macEngine.reset();
    }

    protected void engineUpdate(
        byte    input) 
    {
        macEngine.update(input);
    }

    protected void engineUpdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        macEngine.update(input, offset, len);
    }

    protected byte[] engineDoFinal() 
    {
        byte[]  out = new byte[engineGetMacLength()];

        macEngine.doFinal(out, 0);

        return out;
    }
}
