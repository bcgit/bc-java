package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 */
public class NetscapeCertRequestTest
    implements Test
{
    /* from NS 4.75 */
    static final String test1 =
    "MIIBRzCBsTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmwdh+LJXQ8AtXczo"+
    "4EIGfXjpmDwsoIRpPaXEx1CBHhpon/Dpo/o5Vw2WoWNICXj5lmqhftIpCPO9qKxx"+
    "85x6k/fuyTPH8P02hkmscAYsgqOgb/1yRCNXFryuFOATqxw1tsuye5Q3lTU9JCLU"+
    "UilQ6BV8n3fm2egtPPUaJEuCvcsCAwEAARYNZml4ZWQtZm9yLW5vdzANBgkqhkiG"+
    "9w0BAQQFAAOBgQAImbJD6xHbJtXl6kOTbCFoMnDk7U0o6pHy9l56DYVsiluXegiY"+
    "6twB4o7OWsrqTb+gVvzK65FfP+NBVVzxY8UzcjbqC51yvO/9wnpUsIBqD/Gvi1gE"+
    "qvw7RHwVEhdzsvLwlL22G8CfDxHnWLww39j8uRJsmoNiKJly3BcsZkLd9g==";
    
    public String getName()
    {
        return "NetscapeCertRequest";
    }

    public TestResult perform()
    {
        try
        {
            String    challenge = "fixed-for-now";
        
            byte data [] = Base64.decode (test1);

            ASN1InputStream    in = new ASN1InputStream (new ByteArrayInputStream(data));
            ASN1Sequence    spkac = (ASN1Sequence)in.readObject ();
            // System.out.println("SPKAC: \n"+DERDump.dumpAsString (spkac));


            NetscapeCertRequest nscr = new NetscapeCertRequest (spkac);

            if (!nscr.verify (challenge)) 
            {
                return new SimpleTestResult(false, getName() + ": 1 - not verified");
            }

            //now try to generate one
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance (nscr.getKeyAlgorithm().getAlgorithm().getId(), "BC");

            kpg.initialize (1024);

            KeyPair kp = kpg.genKeyPair();

            nscr.setPublicKey (kp.getPublic());
            nscr.sign (kp.getPrivate());

            byte[] derEncoding = nscr.getEncoded(ASN1Encoding.DER);

            ASN1InputStream     in2 =
                new ASN1InputStream (new ByteArrayInputStream(derEncoding));
            ASN1Sequence        spkac2 = (ASN1Sequence)in2.readObject ();

            // System.out.println("SPKAC2: \n"+DERDump.dumpAsString (spkac2));

            NetscapeCertRequest nscr2 = new NetscapeCertRequest (spkac2);

            if (!nscr2.verify (challenge)) 
            {
                return new SimpleTestResult(false, getName() + ": 2 - not verified");
            }

            //lets build it from scratch


            challenge = "try it";

            NetscapeCertRequest nscr3 =
                new NetscapeCertRequest (challenge,
                                         new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, null),
                                         kp.getPublic());
            
            nscr3.sign (kp.getPrivate());
            
            // System.out.println("SPKAC3: \n"+DERDump.dumpAsString (nscr3));
            
            if (nscr3.verify (challenge)) 
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": 3 - not verified");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString());
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new NetscapeCertRequestTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
