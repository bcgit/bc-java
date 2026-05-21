package org.bouncycastle.pkcs.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS12SecretBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.Arrays;

/**
 * Verifies that secret-key entries — both BC-JCE-keystore-written and
 * pkix-builder-written — round-trip through {@link PKCS12PfxPdu} and surface
 * as {@link PKCS12SecretBag} via {@link PKCS12SafeBag#getBagValue()}
 * (github #1807).
 */
public class PKCS12PfxPduSecretKeyTest
    extends TestCase
{
    private static final char[] PASSWD = "secret".toCharArray();

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Round-trip via the JCE PKCS#12 KeyStore: store an AES-256 SecretKey,
     * then parse the resulting bytes through {@code PKCS12PfxPdu} and walk
     * encrypted SafeContents looking for a {@code secretBag} bag.
     */
    public void testJceKeyStoreSecretKeyRoundTripsThroughPfxPdu()
        throws Exception
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0xC0 ^ i);
        }
        SecretKey aes = new SecretKeySpec(keyBytes, "AES");

        KeyStore writer = KeyStore.getInstance("PKCS12", "BC");
        writer.load(null, null);
        writer.setKeyEntry("aes-256", aes, PASSWD, null);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writer.store(buf, PASSWD);

        Map secretsByAlias = collectSecretBags(new PKCS12PfxPdu(buf.toByteArray()), PASSWD);

        assertTrue("aes-256 alias missing; bags found: " + secretsByAlias.keySet(),
            secretsByAlias.containsKey("aes-256"));
        PKCS12SecretBag bag = (PKCS12SecretBag)secretsByAlias.get("aes-256");
        assertEquals(NISTObjectIdentifiers.id_aes256_CBC, bag.getSecretTypeId());

        byte[] octets = ASN1OctetString.getInstance(bag.getSecretValue()).getOctets();
        assertTrue("AES-256 key bytes did not survive PfxPdu round-trip",
            Arrays.areEqual(keyBytes, octets));
    }

    /**
     * Round-trip via the pkix high-level builder: construct a PFX whose
     * encrypted SafeContents holds a SafeBag of type secretBag carrying an
     * HMAC key, then load through PKCS12PfxPdu without any JCE KeyStore
     * involvement.
     */
    public void testHighLevelBuilderSecretBagRoundTripsThroughPfxPdu()
        throws Exception
    {
        byte[] keyBytes = new byte[32];
        for (int i = 0; i < keyBytes.length; i++)
        {
            keyBytes[i] = (byte)(0x10 + i);
        }

        PKCS12SecretBag secret = new PKCS12SecretBagBuilder(
            PKCSObjectIdentifiers.id_hmacWithSHA256,
            new DEROctetString(keyBytes))
            .build();
        PKCS12SafeBagBuilder safeBagBuilder = new PKCS12SafeBagBuilder(secret);
        safeBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
            new DERBMPString("hmac-sha256"));
        PKCS12SafeBag safeBag = safeBagBuilder.build();

        OutputEncryptor encOut = new JcePKCSPBEOutputEncryptorBuilder(
            PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
            .setProvider("BC").build(PASSWD);

        PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
        pfxBuilder.addEncryptedData(encOut, new PKCS12SafeBag[]{safeBag});
        PKCS12MacCalculatorBuilder macBuilder = new BcPKCS12MacCalculatorBuilder();
        PKCS12PfxPdu pfx = pfxBuilder.build(macBuilder, PASSWD);

        Map secretsByAlias = collectSecretBags(new PKCS12PfxPdu(pfx.getEncoded()), PASSWD);

        assertTrue("hmac-sha256 alias missing; bags found: " + secretsByAlias.keySet(),
            secretsByAlias.containsKey("hmac-sha256"));
        PKCS12SecretBag readBag = (PKCS12SecretBag)secretsByAlias.get("hmac-sha256");
        assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, readBag.getSecretTypeId());
        byte[] octets = ASN1OctetString.getInstance(readBag.getSecretValue()).getOctets();
        assertTrue("HMAC key bytes did not survive PfxPdu round-trip",
            Arrays.areEqual(keyBytes, octets));
    }

    /**
     * Walk every ContentInfo in the PFX, decrypt the encrypted ones with the
     * keystore password, and collect every bag of type secretBag keyed on
     * its friendlyName attribute (or "unknown" if absent).
     */
    private static Map collectSecretBags(PKCS12PfxPdu pfx, char[] password)
        throws Exception
    {
        InputDecryptorProvider decProv =
            new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC").build(password);

        Map out = new HashMap();
        ContentInfo[] infos = pfx.getContentInfos();
        for (int i = 0; i < infos.length; i++)
        {
            PKCS12SafeBagFactory fact;
            if (infos[i].getContentType().equals(PKCSObjectIdentifiers.encryptedData))
            {
                fact = new PKCS12SafeBagFactory(infos[i], decProv);
            }
            else
            {
                fact = new PKCS12SafeBagFactory(infos[i]);
            }

            PKCS12SafeBag[] bags = fact.getSafeBags();
            for (int j = 0; j < bags.length; j++)
            {
                if (!bags[j].getType().equals(PKCSObjectIdentifiers.secretBag))
                {
                    continue;
                }
                String alias = friendlyName(bags[j]);
                Object value = bags[j].getBagValue();
                assertTrue("secretBag bagValue should be PKCS12SecretBag, was "
                    + value.getClass(), value instanceof PKCS12SecretBag);
                out.put(alias == null ? "unknown" : alias, value);
            }
        }
        return out;
    }

    private static String friendlyName(PKCS12SafeBag bag)
    {
        Attribute[] attrs = bag.getAttributes();
        if (attrs == null)
        {
            return null;
        }
        for (int i = 0; i < attrs.length; i++)
        {
            if (PKCS12SafeBag.friendlyNameAttribute.equals(attrs[i].getAttrType()))
            {
                ASN1Encodable[] values = attrs[i].getAttributeValues();
                if (values.length > 0)
                {
                    return ((DERBMPString)values[0]).getString();
                }
            }
        }
        return null;
    }
}
