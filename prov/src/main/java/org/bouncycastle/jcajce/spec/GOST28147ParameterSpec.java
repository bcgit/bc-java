package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.util.Arrays;

/**
 * A parameter spec for the GOST-28147 cipher.
 */
public class GOST28147ParameterSpec
    implements AlgorithmParameterSpec
{
    private byte[] iv = null;
    private byte[] sBox = null;

    public GOST28147ParameterSpec(
        byte[] sBox)
    {
        this.sBox = new byte[sBox.length];
        
        System.arraycopy(sBox, 0, this.sBox, 0, sBox.length);
    }

    public GOST28147ParameterSpec(
        byte[] sBox,
        byte[] iv)
    {
        this(sBox);
        this.iv = new byte[iv.length];
        
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }
    
    public GOST28147ParameterSpec(
        String sBoxName)
    {
        this.sBox = GOST28147Engine.getSBox(sBoxName);
    }

    public GOST28147ParameterSpec(
        String sBoxName,
        byte[] iv)
    {
        this(sBoxName);
        this.iv = new byte[iv.length];
        
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    public GOST28147ParameterSpec(
        ASN1ObjectIdentifier sBoxName,
        byte[] iv)
    {
        this(getName(sBoxName));
        this.iv = Arrays.clone(iv);
    }

    /**
     * @deprecated use getSBox()
     */
    public byte[] getSbox()
    {
        return Arrays.clone(sBox);
    }

    public byte[] getSBox()
    {
        return Arrays.clone(sBox);
    }

    /**
     * Returns the IV or null if this parameter set does not contain an IV.
     *
     * @return the IV or null if this parameter set does not contain an IV.
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }

    private static Map oidMappings = new HashMap();

    static
    {
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
        oidMappings.put(RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, "Param-Z");
    }

    private static String getName(ASN1ObjectIdentifier sBoxOid)
    {
        String sBoxName = (String)oidMappings.get(sBoxOid);

        if (sBoxName == null)
        {
            throw new IllegalArgumentException("unknown OID: " + sBoxOid);
        }

        return sBoxName;
    }
}