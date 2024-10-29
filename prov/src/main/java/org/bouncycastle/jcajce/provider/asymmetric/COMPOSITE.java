package org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class COMPOSITE
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE";

    private static final Map<String, String> compositeAttributes = new HashMap<String, String>();

    static
    {
        compositeAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
        compositeAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    private static AsymmetricKeyInfoConverter baseConverter;

    public static class KeyFactory
        extends BaseKeyFactorySpi
    {
        protected Key engineTranslateKey(Key key)
            throws InvalidKeyException
        {
            try
            {
                if (key instanceof PrivateKey)
                {
                    return generatePrivate(PrivateKeyInfo.getInstance(key.getEncoded()));
                }
                else if (key instanceof PublicKey)
                {
                    return generatePublic(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
                }
            }
            catch (IOException e)
            {
                throw new InvalidKeyException("key could not be parsed: " + e.getMessage());
            }

            throw new InvalidKeyException("key not recognized");
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return baseConverter.generatePrivate(keyInfo);
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return baseConverter.generatePublic(keyInfo);
        }
    }

    private static class CompositeKeyInfoConverter
        implements AsymmetricKeyInfoConverter
    {
        private final ConfigurableProvider provider;

        public CompositeKeyInfoConverter(ConfigurableProvider provider)
        {
            this.provider = provider;
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());
            PrivateKey[] privKeys = new PrivateKey[keySeq.size()];

            ASN1Encodable firstKey = keySeq.getObjectAt(0);

            if (firstKey instanceof ASN1OctetString)
            {
                CompositeSignaturesConstants.CompositeName name = CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(keyInfo.getPrivateKeyAlgorithm().getAlgorithm());
                switch (name)
                {
                case MLDSA44_Ed25519_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA65_Ed25519_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA87_Ed448_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA44_RSA2048_PSS_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA65_RSA3072_PSS_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA44_RSA2048_PKCS15_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA65_RSA3072_PKCS15_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA44_ECDSA_P256_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA65_ECDSA_P256_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_65), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, TeleTrusTObjectIdentifiers.brainpoolP256r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA87_ECDSA_P384_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp384r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_87), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, TeleTrusTObjectIdentifiers.brainpoolP384r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case Falcon512_ECDSA_P256_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case Falcon512_ECDSA_brainpoolP256r1_SHA256:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, TeleTrusTObjectIdentifiers.brainpoolP256r1), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                case Falcon512_Ed25519_SHA512:
                    privKeys[0] = createPrivateKey(new AlgorithmIdentifier(BCObjectIdentifiers.falcon_512), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    privKeys[1] = createPrivateKey(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), ASN1OctetString.getInstance(keySeq.getObjectAt(0)));
                    break;
                default:
                    throw new IllegalArgumentException("unknown composite algorithm");
                }
            }
            else
            {
                for (int i = 0; i != keySeq.size(); i++)
                {
                    ASN1Sequence kSeq = ASN1Sequence.getInstance(keySeq.getObjectAt(i));

                    PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kSeq);

                    privKeys[i] = provider.getKeyInfoConverter(
                        privInfo.getPrivateKeyAlgorithm().getAlgorithm()).generatePrivate(privInfo);
                }
            }

            return new CompositePrivateKey(privKeys);
        }

        private PrivateKey createPrivateKey(AlgorithmIdentifier algId, ASN1OctetString enc)
            throws IOException
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new ASN1Integer(0));
            v.add(algId);
            v.add(enc);

            PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(new DERSequence(v));

            return provider.getKeyInfoConverter(
                privInfo.getPrivateKeyAlgorithm().getAlgorithm()).generatePrivate(privInfo);
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(keyInfo.getPublicKeyData().getBytes());
            PublicKey[] pubKeys = new PublicKey[keySeq.size()];

            for (int i = 0; i != keySeq.size(); i++)
            {
                SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(keySeq.getObjectAt(i));

                pubKeys[i] = provider.getKeyInfoConverter((pubInfo.getAlgorithm().getAlgorithm())).generatePublic(pubInfo);
            }

            return new CompositePublicKey(pubKeys);
        }
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.COMPOSITE", PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_alg_composite, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_alg_composite, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_composite_key, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_composite_key, PREFIX + "$KeyFactory");

            baseConverter = new CompositeKeyInfoConverter(provider);

            provider.addKeyInfoConverter(MiscObjectIdentifiers.id_alg_composite, baseConverter);
            provider.addKeyInfoConverter(MiscObjectIdentifiers.id_composite_key, baseConverter);
        }
    }
}
