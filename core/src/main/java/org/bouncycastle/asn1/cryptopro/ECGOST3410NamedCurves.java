package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.encoders.Hex;

/**
 * table of the available named parameters for GOST 3410-2001 / 2012.
 */
public class ECGOST3410NamedCurves
{
    private static X9ECPoint configureBasepoint(ECCurve curve, BigInteger x, BigInteger y)
    {
        ECPoint G = curve.createPoint(x, y);
        WNafUtil.configureBasepoint(G);
        return new X9ECPoint(G, false);
    }

    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    private static BigInteger fromHex(String hex)
    {
        return new BigInteger(1, Hex.decodeStrict(hex));
    }

    /*
     * GostR3410-2001-CryptoPro-A (and GostR3410-2001-CryptoPro-XchA)
     */
    static X9ECParametersHolder gostR3410_2001_CryptoPro_A = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
            BigInteger mod_q = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
                fromHex("A6"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.ONE,
                fromHex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * GostR3410-2001-CryptoPro-B
     */
    static X9ECParametersHolder gostR3410_2001_CryptoPro_B = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("8000000000000000000000000000000000000000000000000000000000000C99");
            BigInteger mod_q = fromHex("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("8000000000000000000000000000000000000000000000000000000000000C96"),
                fromHex("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.ONE,
                fromHex("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * GostR3410-2001-CryptoPro-C
     */
    static X9ECParametersHolder gostR3410_2001_CryptoPro_C = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B");
            BigInteger mod_q = fromHex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
                fromHex("805A"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.ZERO,
                fromHex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * GostR3410-2001-CryptoPro-XchB
     */
    static X9ECParametersHolder gostR3410_2001_CryptoPro_XchB = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B");
            BigInteger mod_q = fromHex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
                fromHex("805A"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.ZERO,
                fromHex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * Tc26-Gost-3410-12-256-paramSetA
     */
    static X9ECParametersHolder id_tc26_gost_3410_12_256_paramSetA = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97");
            BigInteger mod_q = fromHex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
                fromHex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
                mod_q, ECConstants.FOUR, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                fromHex("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
                fromHex("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * Tc26-Gost-3410-12-512-paramSetA
     */
    static X9ECParametersHolder id_tc26_gost_3410_12_512_paramSetA = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7");
            BigInteger mod_q = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
                fromHex("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.THREE,
                fromHex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * Tc26-Gost-3410-12-512-paramSetB
     */
    static X9ECParametersHolder id_tc26_gost_3410_12_512_paramSetB = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F");
            BigInteger mod_q = fromHex("800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C"),
                fromHex("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"),
                mod_q, ECConstants.ONE, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                ECConstants.TWO,
                fromHex("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * Tc26-Gost-3410-12-512-paramSetC
     */
    static X9ECParametersHolder id_tc26_gost_3410_12_512_paramSetC = new X9ECParametersHolder()
    {
        protected ECCurve createCurve()
        {
            BigInteger mod_p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7");
            BigInteger mod_q = fromHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED");

            return configureCurve(new ECCurve.Fp(
                mod_p,
                fromHex("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"),
                fromHex("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"),
                mod_q, ECConstants.FOUR, true));
        }

        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = getCurve();

            X9ECPoint G = configureBasepoint(curve,
                fromHex("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"),
                fromHex("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"));

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };


    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurve(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        objIds.put(name, oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        defineCurve("GostR3410-2001-CryptoPro-A", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, gostR3410_2001_CryptoPro_A);
        defineCurve("GostR3410-2001-CryptoPro-B", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, gostR3410_2001_CryptoPro_B);
        defineCurve("GostR3410-2001-CryptoPro-C", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, gostR3410_2001_CryptoPro_C);
        defineCurve("GostR3410-2001-CryptoPro-XchA", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, gostR3410_2001_CryptoPro_A);
        defineCurve("GostR3410-2001-CryptoPro-XchB", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, gostR3410_2001_CryptoPro_XchB);
        defineCurve("Tc26-Gost-3410-12-256-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA, id_tc26_gost_3410_12_256_paramSetA);
        defineCurve("Tc26-Gost-3410-12-512-paramSetA", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, id_tc26_gost_3410_12_512_paramSetA);
        defineCurve("Tc26-Gost-3410-12-512-paramSetB", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB, id_tc26_gost_3410_12_512_paramSetB);
        defineCurve("Tc26-Gost-3410-12-512-paramSetC", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC, id_tc26_gost_3410_12_512_paramSetC);
    }

    public static X9ECParameters getByNameX9(String name)
    {
        ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOIDX9(oid);
    }

    public static X9ECParametersHolder getByNameLazy(String name)
    {
        ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOIDLazy(oid);
    }

    public static X9ECParameters getByOIDX9(ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = getByOIDLazy(oid);
        return holder == null ? null : holder.getParameters();
    }

    public static X9ECParametersHolder getByOIDLazy(ASN1ObjectIdentifier oid)
    {
        return (X9ECParametersHolder)curves.get(oid);
    }

    public static ASN1ObjectIdentifier getOID(String name)
    {
        return (ASN1ObjectIdentifier)objIds.get(name);
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        ASN1ObjectIdentifier  oid)
    {
        return (String)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for parameters
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return names.elements();
    }
}
