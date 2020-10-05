package org.bouncycastle.cms.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class AuthEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean _initialised = false;

    public boolean DEBUG = true;

    private static final byte[] Sample1 = Base64.decode("MIAGCyqGSIb3DQEJEAEXoIAwgAIBADGBmzCBmAIBAoABATANBgkqhkiG9w0BAQEFAASBgG9yJPC3zFmIbPTtSrrTD+71lluua3F1" +
        "/V/XzzDOczjdymy4tI4sle5HSxJN8yrw+m2JdWKb4s/u4frvmNqE6fcqfFtLpLEMXJneoEWWXZFKbndoqQNRMgfKGCncpeWhktRc" +
        "SRtbEEk/H4hWggJGmVClS7f/nmCDjwyANBnI3shYMIAGCSqGSIb3DQEHATAfBglghkgBZQMEAQYwEgQQLO0PwnuhYXRk8pLLhgik" +
        "0aCABB8KvxIkbmBKT73Oz4xtf0DNNGmdn+tzPcOldJUQWCEnAAAAAAQMn+tzPcOldJUQWCEnAAAAAAAA");

    private static final byte[] Sample1Key = Base64.decode("MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBAMtFuFyzl4jgeuPL\n" +
        "uGp8Niqf11QGWVDTpZvE7VabLoPanzuVgjTYC8oJOq4PvVYW5V56KeGzXhsnhsDt\n" +
        "IBaRESTFuXM50uiH4mRPGsqCFJvbmokvxfhb24TPg3gQ5E2SEvmXFN425J/jvcqq\n" +
        "XpX7wQGtr9DWLIXsqPeLKhoy/qdhAgMBAAECf3xBB80spVPEggTXW2aoebwXt1pw\n" +
        "8BqzUnSWqlZaHJGdtgbxL0qNsjECX42Djj+1vzddJud0dRHvu4m8y8zlVl/Ro+fv\n" +
        "xETE9nCKzt1MlaNUG9mywZeWLjyOKZFY5fxc+yzoH+d8fcXTM7SwKG9bl6hisU0j\n" +
        "LWdramL5eV/kILECQQDxD5WuYZY2gF2DhtqAxCaf2MLgDlXzj1PcX3X1nPlrNKy3\n" +
        "G0jyMWofmZFORzUz1G0Dlyfxk3Wlc+1IIWbxH5dNAkEA196fcWJN9ZpavkuLKG3W\n" +
        "5sSWAs05Jdk2FGw/pbycoIaMOtf/3KeWJTSNxK1jKsoTQN3RUF9h2jtFhf+yqOjO\n" +
        "ZQJAGpf7jVdauPyEVIRGCrqZAD1rkkhClzISsFcfrk74/Si8fR7Xd1CYQpAwhZA5\n" +
        "gFRJCoJcd7wq2Gvnm3OD5cn0aQJAP98H8CV1CaltFgcGGqU9Q7SA6j1Mnm1BehN5\n" +
        "VZGUCk8lKLgGZYRUgZemJr5irCN0ROoc55oBOu/0pyw78YxInQJBAKjibmupsLLt\n" +
        "kUQF7vyalONmkebwEDwTHODWOGXC7xmcvXhFAnlpYkv3QCohF53X0RS+VprfojbI\n" +
        "X0T/eAP0zJA=");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public AuthEnvelopedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AuthEnvelopedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(AuthEnvelopedDataTest.class));
    }

    public void testSample1()
        throws Exception
    {
        CMSAuthEnvelopedData authEnv = new CMSAuthEnvelopedData(Sample1);

        RecipientInformationStore recipients = authEnv.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(Sample1Key));

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals("auth-enveloped data", Strings.fromByteArray(recData));

        assertTrue(Arrays.areEqual(Sample1, authEnv.getEncoded()));
    }

    public void testAttributes()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));
        
        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }
}