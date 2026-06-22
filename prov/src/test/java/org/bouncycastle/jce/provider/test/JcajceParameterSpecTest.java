package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPrivateKeySpec;
import org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.spec.SkeinParameterSpec;
import org.bouncycastle.jcajce.spec.TLSRSAPremasterSecretParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import org.bouncycastle.jce.spec.GOST3410PrivateKeySpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeySpec;
import org.bouncycastle.jce.spec.RepeatedSecretKeySpec;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.NTRUPlusParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Coverage for the value-type {@code AlgorithmParameterSpec} / {@code KeySpec}
 * classes across the provider's spec packages that the algorithm tests only
 * touch obliquely. From {@code org.bouncycastle.jcajce.spec}:
 * {@link ScryptKeySpec}, {@link HKDFParameterSpec},
 * {@link GOST28147WrapParameterSpec}, {@link GOST28147ParameterSpec},
 * {@link DHUParameterSpec}, {@link DHExtendedPrivateKeySpec} /
 * {@link DHExtendedPublicKeySpec}, {@link TLSRSAPremasterSecretParameterSpec},
 * {@link SkeinParameterSpec} (via its {@code Builder}) and
 * {@link CompositeAlgorithmSpec} (via its {@code Builder}, including the
 * duplicate-name and empty-build error branches). From the legacy
 * {@code org.bouncycastle.jce.spec}: the ElGamal spec family, the deprecated
 * GOST-28147 spec, and the GOST-3410 key specs. From
 * {@code org.bouncycastle.pqc.jcajce.spec}: {@link LMSParameterSpec},
 * {@link LMSHSSParameterSpec} and {@link NTRUPlusParameterSpec}. Also exercises
 * the {@code fromName(String)} lookup error branches on a representative PQC
 * spec.
 */
public class JcajceParameterSpecTest
    extends SimpleTest
{
    public String getName()
    {
        return "JcajceParameterSpecTest";
    }

    public void performTest()
        throws Exception
    {
        scryptKeySpec();
        hkdfParameterSpec();
        gost28147WrapParameterSpec();
        gost28147ParameterSpec();
        dhuParameterSpec();
        dhExtendedAndTlsSpecs();
        legacyJceSpecs();
        pqcKeySpecs();
        skeinParameterSpec();
        compositeAlgorithmSpec();
        pqcFromName();
    }

    private void scryptKeySpec()
    {
        char[] password = "secret".toCharArray();
        byte[] salt = Strings.toByteArray("salt-value");

        ScryptKeySpec spec = new ScryptKeySpec(password, salt, 1024, 8, 2, 256);

        isTrue("scrypt password", Arrays.areEqual(password, spec.getPassword()));
        isTrue("scrypt salt", Arrays.areEqual(salt, spec.getSalt()));
        isEquals("scrypt cost", 1024, spec.getCostParameter());
        isEquals("scrypt block", 8, spec.getBlockSize());
        isEquals("scrypt parallel", 2, spec.getParallelizationParameter());
        isEquals("scrypt keyLength", 256, spec.getKeyLength());
    }

    private void hkdfParameterSpec()
    {
        byte[] ikm = Strings.toByteArray("input-keying-material");
        byte[] salt = Strings.toByteArray("salt");
        byte[] info = Strings.toByteArray("info");

        HKDFParameterSpec spec = new HKDFParameterSpec(ikm, salt, info, 42);

        isTrue("hkdf ikm", Arrays.areEqual(ikm, spec.getIKM()));
        isTrue("hkdf salt", Arrays.areEqual(salt, spec.getSalt()));
        isTrue("hkdf info", Arrays.areEqual(info, spec.getInfo()));
        isEquals("hkdf outputLength", 42, spec.getOutputLength());
        isTrue("hkdf skipExtract", !spec.skipExtract());

        // empty / null salt collapses to null; null info becomes empty (not null)
        HKDFParameterSpec sparse = new HKDFParameterSpec(ikm, new byte[0], null, 16);
        isTrue("hkdf null salt", sparse.getSalt() == null);
        isTrue("hkdf empty info", sparse.getInfo() != null && sparse.getInfo().length == 0);

        try
        {
            new HKDFParameterSpec(null, salt, info, 16);
            fail("expected IllegalArgumentException for null IKM");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void gost28147WrapParameterSpec()
    {
        byte[] sBox = new byte[128];
        for (int i = 0; i != sBox.length; i++)
        {
            sBox[i] = (byte)i;
        }
        byte[] ukm = Strings.toByteArray("12345678");

        GOST28147WrapParameterSpec fromBytes = new GOST28147WrapParameterSpec(sBox, ukm);
        isTrue("gost sBox", Arrays.areEqual(sBox, fromBytes.getSBox()));
        isTrue("gost ukm", Arrays.areEqual(ukm, fromBytes.getUKM()));

        // single-arg ctor leaves the UKM unset
        GOST28147WrapParameterSpec noUkm = new GOST28147WrapParameterSpec(sBox);
        isTrue("gost no ukm", noUkm.getUKM() == null);

        // named-sBox ctor resolves the table from the engine
        GOST28147WrapParameterSpec named = new GOST28147WrapParameterSpec("E-A", ukm);
        isTrue("gost named sBox", named.getSBox() != null && named.getSBox().length == 128);
        isTrue("gost named ukm", Arrays.areEqual(ukm, named.getUKM()));
    }

    private void gost28147ParameterSpec()
    {
        byte[] sBox = new byte[128];
        for (int i = 0; i != sBox.length; i++)
        {
            sBox[i] = (byte)(127 - i);
        }
        byte[] iv = Strings.toByteArray("iv-bytes");

        GOST28147ParameterSpec fromBytes = new GOST28147ParameterSpec(sBox, iv);
        isTrue("gostspec sBox", Arrays.areEqual(sBox, fromBytes.getSBox()));
        isTrue("gostspec sBox (deprecated)", Arrays.areEqual(sBox, fromBytes.getSbox()));
        isTrue("gostspec iv", Arrays.areEqual(iv, fromBytes.getIV()));

        // single-arg ctor leaves the IV unset
        GOST28147ParameterSpec noIv = new GOST28147ParameterSpec(sBox);
        isTrue("gostspec no iv", noIv.getIV() == null);

        // named-sBox ctor resolves the table from the engine
        GOST28147ParameterSpec named = new GOST28147ParameterSpec("E-A", iv);
        isTrue("gostspec named sBox", named.getSBox() != null && named.getSBox().length == 128);
        isTrue("gostspec named iv", Arrays.areEqual(iv, named.getIV()));

        // OID-keyed ctor maps a CryptoPro param-set OID to its named sBox
        GOST28147ParameterSpec byOid = new GOST28147ParameterSpec(
            CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, iv);
        isTrue("gostspec oid sBox", byOid.getSBox() != null && byOid.getSBox().length == 128);

        try
        {
            new GOST28147ParameterSpec(new ASN1ObjectIdentifier("1.2.3.4.5"), iv);
            fail("expected IllegalArgumentException for unknown sBox OID");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void dhuParameterSpec()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = kpg.generateKeyPair();
        PublicKey otherPub = kpg.generateKeyPair().getPublic();
        byte[] ukm = Strings.toByteArray("user-keying-material");

        DHUParameterSpec full = new DHUParameterSpec(kp.getPublic(), kp.getPrivate(), otherPub, ukm);
        isTrue("dhu ephem pub", full.getEphemeralPublicKey() == kp.getPublic());
        isTrue("dhu ephem priv", full.getEphemeralPrivateKey() == kp.getPrivate());
        isTrue("dhu other", full.getOtherPartyEphemeralKey() == otherPub);
        isTrue("dhu ukm", Arrays.areEqual(ukm, full.getUserKeyingMaterial()));

        // no-ukm explicit-keys variant
        DHUParameterSpec noUkm = new DHUParameterSpec(kp.getPublic(), kp.getPrivate(), otherPub);
        isTrue("dhu no ukm", noUkm.getUserKeyingMaterial() == null);

        // KeyPair variants
        DHUParameterSpec fromPair = new DHUParameterSpec(kp, otherPub, ukm);
        isTrue("dhu pair pub", fromPair.getEphemeralPublicKey() == kp.getPublic());
        DHUParameterSpec fromPairNoUkm = new DHUParameterSpec(kp, otherPub);
        isTrue("dhu pair no ukm", fromPairNoUkm.getUserKeyingMaterial() == null);

        // private-only variants (our ephemeral public key is computed later, so null here)
        DHUParameterSpec privOnly = new DHUParameterSpec(kp.getPrivate(), otherPub, ukm);
        isTrue("dhu priv-only pub null", privOnly.getEphemeralPublicKey() == null);
        DHUParameterSpec privOnlyNoUkm = new DHUParameterSpec(kp.getPrivate(), otherPub);
        isTrue("dhu priv-only no ukm", privOnlyNoUkm.getUserKeyingMaterial() == null);

        try
        {
            new DHUParameterSpec(kp.getPublic(), null, otherPub, ukm);
            fail("expected IllegalArgumentException for null ephemeral private key");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        try
        {
            new DHUParameterSpec(kp.getPublic(), kp.getPrivate(), null, ukm);
            fail("expected IllegalArgumentException for null other party key");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void skeinParameterSpec()
    {
        byte[] key = Strings.toByteArray("skein-key");
        byte[] personalisation = Strings.toByteArray("person");
        byte[] publicKey = Strings.toByteArray("public-key");
        byte[] keyId = Strings.toByteArray("key-id");
        byte[] nonce = Strings.toByteArray("nonce");
        byte[] custom = Strings.toByteArray("custom-value");

        SkeinParameterSpec spec = new SkeinParameterSpec.Builder()
            .setKey(key)
            .setPersonalisation(personalisation)
            .setPublicKey(publicKey)
            .setKeyIdentifier(keyId)
            .setNonce(nonce)
            .set(10, custom)
            .build();

        isTrue("skein key", Arrays.areEqual(key, spec.getKey()));
        isTrue("skein personalisation", Arrays.areEqual(personalisation, spec.getPersonalisation()));
        isTrue("skein publicKey", Arrays.areEqual(publicKey, spec.getPublicKey()));
        isTrue("skein keyIdentifier", Arrays.areEqual(keyId, spec.getKeyIdentifier()));
        isTrue("skein nonce", Arrays.areEqual(nonce, spec.getNonce()));
        isTrue("skein custom param", Arrays.areEqual(custom, (byte[])spec.getParameters().get(Integers.valueOf(10))));

        // a Builder seeded from an existing spec carries the parameters forward
        SkeinParameterSpec copy = new SkeinParameterSpec.Builder(spec).build();
        isTrue("skein copy key", Arrays.areEqual(key, copy.getKey()));
        isTrue("skein params size", spec.getParameters().size() == copy.getParameters().size());

        // the recommended YYYYMMDD/email/distinguisher personalisation overloads
        Date date = new Date(0L);
        SkeinParameterSpec dated = new SkeinParameterSpec.Builder()
            .setPersonalisation(date, "test@example.com", "distinguisher")
            .build();
        isTrue("skein dated personalisation", dated.getPersonalisation() != null);

        SkeinParameterSpec datedLocale = new SkeinParameterSpec.Builder()
            .setPersonalisation(date, Locale.ENGLISH, "test@example.com", "distinguisher")
            .build();
        isTrue("skein dated-locale personalisation", datedLocale.getPersonalisation() != null);
    }

    private void compositeAlgorithmSpec()
    {
        try
        {
            new CompositeAlgorithmSpec.Builder().build();
            fail("expected IllegalStateException building with no algorithm names");
        }
        catch (IllegalStateException e)
        {
            // expected
        }

        AlgorithmParameterSpec inner = MLKEMParameterSpec.ml_kem_768;
        CompositeAlgorithmSpec spec = new CompositeAlgorithmSpec.Builder()
            .add("Ed25519")
            .add("ML-KEM-768", inner)
            .build();

        List<String> names = spec.getAlgorithmNames();
        isEquals("composite size", 2, names.size());
        isTrue("composite name 0", "Ed25519".equals(names.get(0)));
        isTrue("composite name 1", "ML-KEM-768".equals(names.get(1)));

        List<AlgorithmParameterSpec> specs = spec.getParameterSpecs();
        isEquals("composite specs size", 2, specs.size());
        isTrue("composite spec 0 null", specs.get(0) == null);
        isTrue("composite spec 1", specs.get(1) == inner);

        try
        {
            new CompositeAlgorithmSpec.Builder().add("Ed25519").add("Ed25519");
            fail("expected IllegalStateException for duplicate algorithm name");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private void dhExtendedAndTlsSpecs()
    {
        BigInteger p = BigInteger.valueOf(0x7fffffff);
        BigInteger g = BigInteger.valueOf(2);
        BigInteger value = BigInteger.valueOf(12345);
        DHParameterSpec dhParams = new DHParameterSpec(p, g);

        DHExtendedPrivateKeySpec priv = new DHExtendedPrivateKeySpec(value, dhParams);
        isTrue("dh-ext priv params", priv.getParams() == dhParams);
        isTrue("dh-ext priv x", value.equals(priv.getX()));

        DHExtendedPublicKeySpec pub = new DHExtendedPublicKeySpec(value, dhParams);
        isTrue("dh-ext pub params", pub.getParams() == dhParams);
        isTrue("dh-ext pub y", value.equals(pub.getY()));

        TLSRSAPremasterSecretParameterSpec tls = new TLSRSAPremasterSecretParameterSpec(0x0303);
        isEquals("tls premaster version", 0x0303, tls.getProtocolVersion());
    }

    private void legacyJceSpecs()
    {
        BigInteger p = BigInteger.valueOf(0x7fffffff);
        BigInteger g = BigInteger.valueOf(2);
        BigInteger x = BigInteger.valueOf(7);
        BigInteger y = BigInteger.valueOf(11);

        // ElGamal spec family (jce.spec)
        ElGamalParameterSpec egParams = new ElGamalParameterSpec(p, g);
        isTrue("elgamal p", p.equals(egParams.getP()));
        isTrue("elgamal g", g.equals(egParams.getG()));

        ElGamalPrivateKeySpec egPriv = new ElGamalPrivateKeySpec(x, egParams);
        isTrue("elgamal priv x", x.equals(egPriv.getX()));
        isTrue("elgamal priv params", egPriv.getParams() == egParams);

        ElGamalPublicKeySpec egPub = new ElGamalPublicKeySpec(y, egParams);
        isTrue("elgamal pub y", y.equals(egPub.getY()));

        ElGamalGenParameterSpec egGen = new ElGamalGenParameterSpec(1024);
        isEquals("elgamal gen prime size", 1024, egGen.getPrimeSize());

        // deprecated jce.spec GOST-28147 spec (subclass of the jcajce one)
        byte[] sBox = new byte[128];
        byte[] iv = Strings.toByteArray("gost-iv0");
        org.bouncycastle.jce.spec.GOST28147ParameterSpec gostBytes =
            new org.bouncycastle.jce.spec.GOST28147ParameterSpec(sBox, iv);
        isTrue("jce gost sBox", Arrays.areEqual(sBox, gostBytes.getSBox()));
        isTrue("jce gost iv", Arrays.areEqual(iv, gostBytes.getIV()));
        isTrue("jce gost sBox-only", new org.bouncycastle.jce.spec.GOST28147ParameterSpec(sBox).getIV() == null);
        org.bouncycastle.jce.spec.GOST28147ParameterSpec gostNamed =
            new org.bouncycastle.jce.spec.GOST28147ParameterSpec("E-A", iv);
        isTrue("jce gost named", gostNamed.getSBox().length == 128);
        isTrue("jce gost named-only", new org.bouncycastle.jce.spec.GOST28147ParameterSpec("E-A").getIV() == null);

        // GOST-3410 key specs (jce.spec)
        BigInteger q = BigInteger.valueOf(0x10001);
        BigInteger a = BigInteger.valueOf(3);
        GOST3410PrivateKeySpec gostPriv = new GOST3410PrivateKeySpec(x, p, q, a);
        isTrue("gost3410 priv x", x.equals(gostPriv.getX()));
        isTrue("gost3410 priv p", p.equals(gostPriv.getP()));
        isTrue("gost3410 priv q", q.equals(gostPriv.getQ()));
        isTrue("gost3410 priv a", a.equals(gostPriv.getA()));

        GOST3410PublicKeySpec gostPub = new GOST3410PublicKeySpec(y, p, q, a);
        isTrue("gost3410 pub y", y.equals(gostPub.getY()));
        isTrue("gost3410 pub p", p.equals(gostPub.getP()));
        isTrue("gost3410 pub q", q.equals(gostPub.getQ()));
        isTrue("gost3410 pub a", a.equals(gostPub.getA()));

        // deprecated jce.spec RepeatedSecretKeySpec (subclass of the jcajce one)
        RepeatedSecretKeySpec repeated = new RepeatedSecretKeySpec("AES");
        isTrue("repeated key algorithm", "AES".equals(repeated.getAlgorithm()));
    }

    private void pqcKeySpecs()
    {
        // LMS / HSS hash-based signature parameter specs
        LMSParameterSpec lms = new LMSParameterSpec(
            LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1);
        isTrue("lms sig params", lms.getSigParams() == LMSigParameters.lms_sha256_n32_h5);
        isTrue("lms ots params", lms.getOtsParams() == LMOtsParameters.sha256_n32_w1);

        LMSHSSParameterSpec hss = new LMSHSSParameterSpec(new LMSParameterSpec[]{ lms });
        isEquals("hss specs length", 1, hss.getLMSSpecs().length);
        isTrue("hss spec element", hss.getLMSSpecs()[0] == lms);

        // NTRU+ KEM parameter spec — getName accessor and the fromName map
        // round-trip. fromName(spec.getName()) must return the same constant for
        // every parameter set (including ntruplus_1152), the lookup is
        // case-insensitive on the canonical name, and an unknown name maps to
        // null. (Regression: the fromName map was previously keyed by strings
        // getName() never produces, and the 1152 set was absent from it.)
        NTRUPlusParameterSpec[] ntruPlusSpecs =
            {
                NTRUPlusParameterSpec.ntruplus_768,
                NTRUPlusParameterSpec.ntruplus_864,
                NTRUPlusParameterSpec.ntruplus_1152
            };
        for (int i = 0; i != ntruPlusSpecs.length; i++)
        {
            NTRUPlusParameterSpec spec = ntruPlusSpecs[i];
            isTrue("ntruplus name " + i, spec.getName().length() > 0);
            isTrue("ntruplus fromName round-trip " + spec.getName(),
                NTRUPlusParameterSpec.fromName(spec.getName()) == spec);
            isTrue("ntruplus fromName lower " + spec.getName(),
                NTRUPlusParameterSpec.fromName(Strings.toLowerCase(spec.getName())) == spec);
        }
        isTrue("ntruplus fromName miss", NTRUPlusParameterSpec.fromName("no-such-name") == null);
    }

    private void pqcFromName()
    {
        isEquals("ML-KEM-1024", MLKEMParameterSpec.ml_kem_1024.getName());
        isEquals("ML-KEM-768", MLKEMParameterSpec.fromName("ML-KEM-768").getName());

        try
        {
            MLKEMParameterSpec.fromName("not-a-real-name");
            fail("expected IllegalArgumentException for unknown name");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            MLKEMParameterSpec.fromName(null);
            fail("expected NullPointerException for null name");
        }
        catch (NullPointerException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new JcajceParameterSpecTest());
    }
}
