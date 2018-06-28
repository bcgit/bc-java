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
public class GOST28147WrapParameterSpec
    implements AlgorithmParameterSpec
{
    private byte[] ukm = null;
    private byte[] sBox = null;

    public GOST28147WrapParameterSpec(
        byte[] sBox)
    {
        this.sBox = new byte[sBox.length];

        System.arraycopy(sBox, 0, this.sBox, 0, sBox.length);
    }

    public GOST28147WrapParameterSpec(
        byte[] sBox,
        byte[] ukm)
    {
        this(sBox);
        this.ukm = new byte[ukm.length];

        System.arraycopy(ukm, 0, this.ukm, 0, ukm.length);
    }

    public GOST28147WrapParameterSpec(
        String sBoxName)
    {
        this.sBox = GOST28147Engine.getSBox(sBoxName);
    }

    public GOST28147WrapParameterSpec(
        String sBoxName,
        byte[] ukm)
    {
        this(sBoxName);
        this.ukm = new byte[ukm.length];

        System.arraycopy(ukm, 0, this.ukm, 0, ukm.length);
    }

    public GOST28147WrapParameterSpec(
        ASN1ObjectIdentifier sBoxName,
        byte[] ukm)
    {
        this(getName(sBoxName));
        this.ukm = Arrays.clone(ukm);
    }

    public byte[] getSBox()
    {
        return Arrays.clone(sBox);
    }

    /**
     * Returns the UKM.
     *
     * @return the UKM.
     */
    public byte[] getUKM()
    {
        return Arrays.clone(ukm);
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