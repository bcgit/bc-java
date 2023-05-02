package org.bouncycastle.jce.provider.test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFException;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class X509LDAPCertStoreTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testLdapFilter()
            throws Exception
    {
        BcFilterCheck filterCheck = new BcFilterCheck();

        //start mock ldap server for logging
        InMemoryDirectoryServer ds = mockLdapServer(filterCheck);
        ds.startListening();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(256);

        //generate malicious certificate
        String subject = "CN=chars[*()\\\0]";
        X509Certificate cert = TestUtils.createSelfSignedCert(new X500Name(subject), "SHA256withECDSA", kpg.generateKeyPair());

//        Attribute[] attr1 =
//        {
//          new Attribute("objectClass", "top", "person", "organizationalPerson",
//               "inetOrgPerson"),
//          new Attribute("uid", "john.doe"),
//          new Attribute("givenName", "John"),
//          new Attribute("sn", "Doe"),
//          new Attribute("cn", "chars[*()\\\0]")
//        };
//        LDAPResult result = ds.add("dc=test", attr1);
//
//        Attribute[] attributes =
//        {
//          new Attribute("objectClass", "top", "person", "organizationalPerson",
//               "inetOrgPerson"),
//          new Attribute("uid", "john.doe"),
//          new Attribute("givenName", "John"),
//          new Attribute("sn", "Doe"),
//          new Attribute("cn", "chars[*()\\\0]")
//        };
//        result = ds.add("uid=john.doe,dc=test", attributes);
        readEntriesFromFile(ds);
//        testMemberOf(ds);

        //trigger the exploit
        verifyCert(cert);

        //shut down ldap server
        ds.shutDown(true);

        assertTrue(filterCheck.isUsed());
    }

    private static InMemoryDirectoryServer mockLdapServer(BcFilterCheck filterCheck)
            throws Exception
    {
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=test");
        serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("0.0.0.0"),
                1389,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));

        serverConfig.addInMemoryOperationInterceptor(filterCheck);

        return new InMemoryDirectoryServer(serverConfig);
    }

    public static void readEntriesFromFile(InMemoryDirectoryServer ds) throws IOException, LDAPException, LDIFException
    {
        InputStream src = TestResourceFinder.findTestResource("ldap/", "X509LDAPCertTest.ldif");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line = null;
        List<String> entry = new ArrayList<String>();
        while ((line = bin.readLine()) != null)
        {
            if (line.isEmpty())
            {
                // End of entry, add to list and reset
                if (entry.size() > 0)
                {
                    addEntry(ds, entry.toArray(new String[0]));
                    entry.clear();
                }
            }
            else
            {
                // Add entry line and attributes
                line = line.replaceAll("\\\\0", "\0");
                entry.add(line);
            }
        }
        bin.close();
        if (entry.size() > 0)
        {
            addEntry(ds, entry.toArray(new String[0]));
            entry.clear();
        }

    }

//    public static void testMemberOf(InMemoryDirectoryServer ds)
//        throws Exception
//    {
//
//        addEntry(ds, "dn: dc=test", "objectClass: top", "objectClass: domain", "dc: test");
//
//        ObjectClassDefinition oc = new ObjectClassDefinition("10.19.19.78", new String[]{"user"}, "", false, new String[]{"TOP"},
//            ObjectClassType.STRUCTURAL, new String[]{"memberOf"},
//            new String[]{}, new HashMap());
//        addEntry(ds, "dn: cn=schema2,dc=test", "objectClass: top", "objectClass: ldapSubEntry", "objectClass: subschema", "cn: schema2",
//            "objectClasses:  " + oc.toString());
//
//        addEntry(ds, "dn: dc=people,dc=test", "objectClass: top", "objectClass: domain", "dc: people");
//        addEntry(ds, "dn: dc=groups,dc=test", "objectClass: top", "objectClass: domain", "dc: groups");
//        addEntry(ds, "dn: cn=test-group,dc=groups,dc=test", "objectClass: groupOfUniqueNames", "cn: test group");
//        addEntry(ds, "dn: cn=Testy Tester,dc=people,dc=test", "objectClass: Person", "objectClass: organizationalPerson", "sn: Tester", "cn: Testy Tester");
//        addEntry(ds, "dn: cn=chars[*()\\\0],dc=people,dc=test", "objectClass: Person", "objectClass: organizationalPerson", "sn: chars", "cn: chars[*()\\\0]");
//    }

    public static void addEntry(InMemoryDirectoryServer ds, String... args)
        throws LDIFException, LDAPException
    {
        LDAPResult result = ds.add(args);
        assertEquals(0, result.getResultCode().intValue());
    }

    static void verifyCert(X509Certificate cert)
        throws Exception
    {
        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Load the JDK's trusted certs
        String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream(filename), "changeit".toCharArray());

        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(keystore, selector);

        //setup additional LDAP store
        X509LDAPCertStoreParameters CertStoreParameters = new X509LDAPCertStoreParameters.Builder("ldap://127.0.0.1:1389", "CN=certificates").build();
        CertStore certStore = CertStore.getInstance("LDAP", CertStoreParameters, "BC");
        pkixParams.addCertStore(certStore);

        // Build and verify the certification chain
        try
        {
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(pkixParams);

        }
        catch (ExtCertPathBuilderException exception)
        {
            //expected to fail with ExtCertPathBuilderException: Error finding target certificate.
        }
    }

    /*
        check we get a suitably escaped subject.
     */
    static class BcFilterCheck
        extends InMemoryOperationInterceptor
    {
        private volatile boolean used = false;

        public void processSearchResult(InMemoryInterceptedSearchResult result)
        {
            String filter = result.getRequest().getFilter().toString();

            assertEquals("(&(cn=*chars[\\2a\\28\\29\\00]*)(userCertificate=*))", filter);

            used = true;

            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

        boolean isUsed()
        {
            return used;
        }
    }
}
