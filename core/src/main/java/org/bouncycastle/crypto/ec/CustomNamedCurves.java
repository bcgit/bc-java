package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP128R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP160K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP160R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP160R2Curve;
import org.bouncycastle.math.ec.custom.sec.SecP192K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT113R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT113R2Curve;
import org.bouncycastle.math.ec.custom.sec.SecT131R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT131R2Curve;
import org.bouncycastle.math.ec.custom.sec.SecT163K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT163R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT163R2Curve;
import org.bouncycastle.math.ec.custom.sec.SecT193R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT193R2Curve;
import org.bouncycastle.math.ec.custom.sec.SecT233K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT233R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT239K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT283K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT283R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT409K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT409R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT571K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecT571R1Curve;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.math.ec.endo.ScalarSplitParameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class CustomNamedCurves
{
    private static X9ECPoint configureBasepoint(ECCurve curve, String encoding)
    {
        X9ECPoint G = new X9ECPoint(curve, Hex.decodeStrict(encoding));
        WNafUtil.configureBasepoint(G.getPoint());
        return G;
    }

    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    private static ECCurve configureCurveGLV(ECCurve c, GLVTypeBParameters p)
    {
        return c.configure().setEndomorphism(new GLVTypeBEndomorphism(c, p)).create();
    }

    /*
     * curve25519
     */
    static X9ECParametersHolder curve25519 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new Curve25519());

            /*
             * NOTE: Curve25519 was specified in Montgomery form. Rewriting in Weierstrass form
             * involves substitution of variables, so the base-point x coordinate is 9 + (486662 / 3).
             * 
             * The Curve25519 paper doesn't say which of the two possible y values the base
             * point has. The choice here is guided by language in the Ed25519 paper.
             * 
             * (The other possible y value is 5F51E65E475F794B1FE122D388B72EB36DC2B28192839E4DD6163A5D81312C14) 
             */
            X9ECPoint G = configureBasepoint(curve,
                "042AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9");

            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp128r1
     */
    static X9ECParametersHolder secp128r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("000E0D4D696E6768756151750CC03A4473D03679");
            ECCurve curve = configureCurve(new SecP128R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "04161FF7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp160k1
     */
    static X9ECParametersHolder secp160k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("9ba48cba5ebcb9b6bd33b92830b2a2e0e192f10a", 16),
                new BigInteger("c39c6c3b3a36d7701b9c71a1f5804ae5d0003f4", 16),
                new ScalarSplitParameters(
                    new BigInteger[]{
                        new BigInteger("9162fbe73984472a0a9e", 16),
                        new BigInteger("-96341f1138933bc2f505", 16) },
                    new BigInteger[]{
                        new BigInteger("127971af8721782ecffa3", 16),
                        new BigInteger("9162fbe73984472a0a9e", 16) },
                    new BigInteger("9162fbe73984472a0a9d0590", 16),
                    new BigInteger("96341f1138933bc2f503fd44", 16),
                    176));
            ECCurve curve = configureCurveGLV(new SecP160K1Curve(), glv);
            X9ECPoint G = configureBasepoint(curve,
                "043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp160r1
     */
    static X9ECParametersHolder secp160r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("1053CDE42C14D696E67687561517533BF3F83345");
            ECCurve curve = configureCurve(new SecP160R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "044A96B5688EF573284664698968C38BB913CBFC8223A628553168947D59DCC912042351377AC5FB32");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp160r2
     */
    static X9ECParametersHolder secp160r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("B99B99B099B323E02709A4D696E6768756151751");
            ECCurve curve = configureCurve(new SecP160R2Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0452DCB034293A117E1F4FF11B30F7199D3144CE6DFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp192k1
     */
    static X9ECParametersHolder secp192k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("bb85691939b869c1d087f601554b96b80cb4f55b35f433c2", 16),
                new BigInteger("3d84f26c12238d7b4f3d516613c1759033b1a5800175d0b1", 16),
                new ScalarSplitParameters(
                    new BigInteger[]{
                        new BigInteger("71169be7330b3038edb025f1", 16),
                        new BigInteger("-b3fb3400dec5c4adceb8655c", 16) },
                    new BigInteger[]{
                        new BigInteger("12511cfe811d0f4e6bc688b4d", 16),
                        new BigInteger("71169be7330b3038edb025f1", 16) },
                    new BigInteger("71169be7330b3038edb025f1d0f9", 16),
                    new BigInteger("b3fb3400dec5c4adceb8655d4c94", 16),
                    208));
            ECCurve curve = configureCurveGLV(new SecP192K1Curve(), glv);
            X9ECPoint G = configureBasepoint(curve,
                "04DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp192r1
     */
    static X9ECParametersHolder secp192r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("3045AE6FC8422F64ED579528D38120EAE12196D5");
            ECCurve curve = configureCurve(new SecP192R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "04188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224k1
     */
    static X9ECParametersHolder secp224k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("fe0e87005b4e83761908c5131d552a850b3f58b749c37cf5b84d6768", 16),
                new BigInteger("60dcd2104c4cbc0be6eeefc2bdd610739ec34e317f9b33046c9e4788", 16),
                new ScalarSplitParameters(
                    new BigInteger[]{
                        new BigInteger("6b8cf07d4ca75c88957d9d670591", 16),
                        new BigInteger("-b8adf1378a6eb73409fa6c9c637d", 16) },
                    new BigInteger[]{
                        new BigInteger("1243ae1b4d71613bc9f780a03690e", 16),
                        new BigInteger("6b8cf07d4ca75c88957d9d670591", 16) },
                    new BigInteger("6b8cf07d4ca75c88957d9d67059037a4", 16),
                    new BigInteger("b8adf1378a6eb73409fa6c9c637ba7f5", 16),
                    240));
            ECCurve curve = configureCurveGLV(new SecP224K1Curve(), glv);
            X9ECPoint G = configureBasepoint(curve,
                "04A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224r1
     */
    static X9ECParametersHolder secp224r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
            ECCurve curve = configureCurve(new SecP224R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp256k1
     */
    static X9ECParametersHolder secp256k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            GLVTypeBParameters glv = new GLVTypeBParameters(
                new BigInteger("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16),
                new BigInteger("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16),
                new ScalarSplitParameters(
                    new BigInteger[]{
                        new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16),
                        new BigInteger("-e4437ed6010e88286f547fa90abfe4c3", 16) },
                    new BigInteger[]{
                        new BigInteger("114ca50f7a8e2f3f657c1108d9d44cfd8", 16),
                        new BigInteger("3086d221a7d46bcde86c90e49284eb15", 16) },
                    new BigInteger("3086d221a7d46bcde86c90e49284eb153dab", 16),
                    new BigInteger("e4437ed6010e88286f547fa90abfe4c42212", 16),
                    272));
            ECCurve curve = configureCurveGLV(new SecP256K1Curve(), glv);
            X9ECPoint G = configureBasepoint(curve,
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp256r1
     */
    static X9ECParametersHolder secp256r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("C49D360886E704936A6678E1139D26B7819F7E90");
            ECCurve curve = configureCurve(new SecP256R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp384r1
     */
    static X9ECParametersHolder secp384r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("A335926AA319A27A1D00896A6773A4827ACDAC73");
            ECCurve curve = configureCurve(new SecP384R1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp521r1
     */
    static X9ECParametersHolder secp521r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("D09E8800291CB85396CC6717393284AAA0DA64BA");
            ECCurve curve = configureCurve(new SecP521R1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect113r1
     */
    static X9ECParametersHolder sect113r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("10E723AB14D696E6768756151756FEBF8FCB49A9");
            ECCurve curve = configureCurve(new SecT113R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "04009D73616F35F4AB1407D73562C10F00A52830277958EE84D1315ED31886");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect113r2
     */
    static X9ECParametersHolder sect113r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("10C0FB15760860DEF1EEF4D696E676875615175D");
            ECCurve curve = configureCurve(new SecT113R2Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0401A57A6A7B26CA5EF52FCDB816479700B3ADC94ED1FE674C06E695BABA1D");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect131r1
     */
    static X9ECParametersHolder sect131r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("4D696E676875615175985BD3ADBADA21B43A97E2");
            ECCurve curve = configureCurve(new SecT131R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "040081BAF91FDF9833C40F9C181343638399078C6E7EA38C001F73C8134B1B4EF9E150");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect131r2
     */
    static X9ECParametersHolder sect131r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("985BD3ADBAD4D696E676875615175A21B43A97E3");
            ECCurve curve = configureCurve(new SecT131R2Curve());
            X9ECPoint G = configureBasepoint(curve,
                "040356DCD8F2F95031AD652D23951BB366A80648F06D867940A5366D9E265DE9EB240F");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect163k1
     */
    static X9ECParametersHolder sect163k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT163K1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect163r1
     */
    static X9ECParametersHolder sect163r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("24B7B137C8A14D696E6768756151756FD0DA2E5C");
            ECCurve curve = configureCurve(new SecT163R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "040369979697AB43897789566789567F787A7876A65400435EDB42EFAFB2989D51FEFCE3C80988F41FF883");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect163r2
     */
    static X9ECParametersHolder sect163r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("85E25BFE5C86226CDB12016F7553F9D0E693A268");
            ECCurve curve = configureCurve(new SecT163R2Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0403F0EBA16286A2D57EA0991168D4994637E8343E3600D51FBC6C71A0094FA2CDD545B11C5C0C797324F1");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect193r1
     */
    static X9ECParametersHolder sect193r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("103FAEC74D696E676875615175777FC5B191EF30");
            ECCurve curve = configureCurve(new SecT193R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0401F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E10025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect193r2
     */
    static X9ECParametersHolder sect193r2 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("10B7B4D696E676875615175137C8A16FD0DA2211");
            ECCurve curve = configureCurve(new SecT193R2Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0400D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect233k1
     */
    static X9ECParametersHolder sect233k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT233K1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "04017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD612601DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect233r1
     */
    static X9ECParametersHolder sect233r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("74D59FF07F6B413D0EA14B344B20A2DB049B50C3");
            ECCurve curve = configureCurve(new SecT233R1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0400FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect239k1
     */
    static X9ECParametersHolder sect239k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT239K1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0429A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect283k1
     */
    static X9ECParametersHolder sect283k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT283K1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836"
                + "01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect283r1
     */
    static X9ECParametersHolder sect283r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("77E2B07370EB0F832A6DD5B62DFC88CD06BB84BE");
            ECCurve curve = configureCurve(new SecT283R1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053"
                + "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect409k1
     */
    static X9ECParametersHolder sect409k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT409K1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746"
                + "01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect409r1
     */
    static X9ECParametersHolder sect409r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("4099B5A457F9D69F79213D094C4BCD4D4262210B");
            ECCurve curve = configureCurve(new SecT409R1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7"
                + "0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect571k1
     */
    static X9ECParametersHolder sect571k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecT571K1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972"
                + "0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sect571r1
     */
    static X9ECParametersHolder sect571r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decodeStrict("2AA058F73A0E33AB486B0F610410C53A7F132310");
            ECCurve curve = configureCurve(new SecT571R1Curve());
            X9ECPoint G = configureBasepoint(curve, "04"
                + "0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19"
                + "037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * sm2p256v1
     */
    static X9ECParametersHolder sm2p256v1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SM2P256V1Curve());
            X9ECPoint G = configureBasepoint(curve,
                "0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };


    static final Hashtable nameToCurve = new Hashtable();
    static final Hashtable nameToOID = new Hashtable();
    static final Hashtable oidToCurve = new Hashtable();
    static final Hashtable oidToName = new Hashtable();
    static final Vector names = new Vector();

    static void defineCurve(String name, X9ECParametersHolder holder)
    {
        names.addElement(name);
        name = Strings.toLowerCase(name);
        nameToCurve.put(name, holder);
    }

    static void defineCurveWithOID(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        names.addElement(name);
        oidToName.put(oid, name);
        oidToCurve.put(oid, holder);
        name = Strings.toLowerCase(name);
        nameToOID.put(name, oid);
        nameToCurve.put(name, holder);
    }

    static void defineCurveAlias(String name, ASN1ObjectIdentifier oid)
    {
        Object curve = oidToCurve.get(oid);
        if (curve == null)
        {
            throw new IllegalStateException();
        }

        name = Strings.toLowerCase(name);
        nameToOID.put(name, oid);
        nameToCurve.put(name, curve);
    }

    static
    {
        defineCurveWithOID("curve25519", CryptlibObjectIdentifiers.curvey25519, curve25519);

//        defineCurveWithOID("secp112r1", SECObjectIdentifiers.secp112r1, secp112r1);
//        defineCurveWithOID("secp112r2", SECObjectIdentifiers.secp112r2, secp112r2);
        defineCurveWithOID("secp128r1", SECObjectIdentifiers.secp128r1, secp128r1);
//        defineCurveWithOID("secp128r2", SECObjectIdentifiers.secp128r2, secp128r2);
        defineCurveWithOID("secp160k1", SECObjectIdentifiers.secp160k1, secp160k1);
        defineCurveWithOID("secp160r1", SECObjectIdentifiers.secp160r1, secp160r1);
        defineCurveWithOID("secp160r2", SECObjectIdentifiers.secp160r2, secp160r2);
        defineCurveWithOID("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
        defineCurveWithOID("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
        defineCurveWithOID("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1);
        defineCurveWithOID("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1);
        defineCurveWithOID("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
        defineCurveWithOID("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);
        defineCurveWithOID("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1);
        defineCurveWithOID("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1);

        defineCurveWithOID("sect113r1", SECObjectIdentifiers.sect113r1, sect113r1);
        defineCurveWithOID("sect113r2", SECObjectIdentifiers.sect113r2, sect113r2);
        defineCurveWithOID("sect131r1", SECObjectIdentifiers.sect131r1, sect131r1);
        defineCurveWithOID("sect131r2", SECObjectIdentifiers.sect131r2, sect131r2);
        defineCurveWithOID("sect163k1", SECObjectIdentifiers.sect163k1, sect163k1);
        defineCurveWithOID("sect163r1", SECObjectIdentifiers.sect163r1, sect163r1);
        defineCurveWithOID("sect163r2", SECObjectIdentifiers.sect163r2, sect163r2);
        defineCurveWithOID("sect193r1", SECObjectIdentifiers.sect193r1, sect193r1);
        defineCurveWithOID("sect193r2", SECObjectIdentifiers.sect193r2, sect193r2);
        defineCurveWithOID("sect233k1", SECObjectIdentifiers.sect233k1, sect233k1);
        defineCurveWithOID("sect233r1", SECObjectIdentifiers.sect233r1, sect233r1);
        defineCurveWithOID("sect239k1", SECObjectIdentifiers.sect239k1, sect239k1);
        defineCurveWithOID("sect283k1", SECObjectIdentifiers.sect283k1, sect283k1);
        defineCurveWithOID("sect283r1", SECObjectIdentifiers.sect283r1, sect283r1);
        defineCurveWithOID("sect409k1", SECObjectIdentifiers.sect409k1, sect409k1);
        defineCurveWithOID("sect409r1", SECObjectIdentifiers.sect409r1, sect409r1);
        defineCurveWithOID("sect571k1", SECObjectIdentifiers.sect571k1, sect571k1);
        defineCurveWithOID("sect571r1", SECObjectIdentifiers.sect571r1, sect571r1);

        defineCurveWithOID("sm2p256v1", GMObjectIdentifiers.sm2p256v1, sm2p256v1);

        defineCurveAlias("B-163", SECObjectIdentifiers.sect163r2);
        defineCurveAlias("B-233", SECObjectIdentifiers.sect233r1);
        defineCurveAlias("B-283", SECObjectIdentifiers.sect283r1);
        defineCurveAlias("B-409", SECObjectIdentifiers.sect409r1);
        defineCurveAlias("B-571", SECObjectIdentifiers.sect571r1);

        defineCurveAlias("K-163", SECObjectIdentifiers.sect163k1);
        defineCurveAlias("K-233", SECObjectIdentifiers.sect233k1);
        defineCurveAlias("K-283", SECObjectIdentifiers.sect283k1);
        defineCurveAlias("K-409", SECObjectIdentifiers.sect409k1);
        defineCurveAlias("K-571", SECObjectIdentifiers.sect571k1);

        defineCurveAlias("P-192", SECObjectIdentifiers.secp192r1);
        defineCurveAlias("P-224", SECObjectIdentifiers.secp224r1);
        defineCurveAlias("P-256", SECObjectIdentifiers.secp256r1);
        defineCurveAlias("P-384", SECObjectIdentifiers.secp384r1);
        defineCurveAlias("P-521", SECObjectIdentifiers.secp521r1);
    }

    public static X9ECParameters getByName(String name)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)nameToCurve.get(Strings.toLowerCase(name));
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the X9ECParameters object for the named curve represented by the passed in object
     * identifier. Null if the curve isn't present.
     * 
     * @param oid
     *            an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)oidToCurve.get(oid);
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the object identifier signified by the passed in name. Null if there is no object
     * identifier associated with name.
     * 
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(String name)
    {
        return (ASN1ObjectIdentifier)nameToOID.get(Strings.toLowerCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(ASN1ObjectIdentifier oid)
    {
        return (String)oidToName.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves contained in this structure.
     */
    public static Enumeration getNames()
    {
        return names.elements();
    }
}
