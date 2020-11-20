
package org.bouncycastle.jce.provider.test;
 
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PKIXTest
    implements Test
{
    /*
     * The following certs and crls are described in:
     * https://www.ietf.org/internet-drafts/draft-ietf-pkix-new-part1-08.txt
     *
     *   This section contains four examples: three certificates and a CRL.
     *   The first two certificates and the CRL comprise a minimal
     *   certification path.
     *
     *   Section C.1 contains an annotated hex dump of a "self-signed"
     *   certificate issued by a CA whose distinguished name is
     *   cn=us,o=gov,ou=nist.  The certificate contains a DSA public key with
     *   parameters, and is signed by the corresponding DSA private key.
     *
     *   Section C.2 contains an annotated hex dump of an end entity
     *   certificate.  The end entity certificate contains a DSA public key,
     *   and is signed by the private key corresponding to the "self-signed"
     *   certificate in section C.1.
     *
     *   Section C.3 contains a dump of an end entity certificate which
     *   contains an RSA public key and is signed with RSA and MD5.  This
     *   certificate is not part of the minimal certification path.
     *
     *   Section C.4 contains an annotated hex dump of a CRL.  The CRL is
     *   issued by the CA whose distinguished name is cn=us,o=gov,ou=nist and
     *   the list of revoked certificates includes the end entity certificate
     *   presented in C.2.
     */

    /**
     * C.1  Certificate
     * 
        * This section contains an annotated hex dump of a 699 byte version 3
        * certificate.  The certificate contains the following information:
        * (a)  the serial number is 23 (17 hex);
        * (b)  the certificate is signed with DSA and the SHA-1 hash algorithm;
        * (c)  the issuer's distinguished name is OU=NIST; O=gov; C=US
        * (d)  and the subject's distinguished name is OU=NIST; O=gov; C=US
        * (e)  the certificate was issued on June 30, 1997 and will expire on
        * December 31, 1997;
        * (f)  the certificate contains a 1024 bit DSA public key with
        * parameters;
        * (g)  the certificate contains a subject key identifier extension
        * generated using method (1) of section 4.2.1.2; and
        * (h)  the certificate is a CA certificate (as indicated through the
        * basic constraints extension.)
     */
    static byte[] rootCertBin = Hex.decode(
        "308202bb3082027ba003020102020111300906072a8648ce380403302a310b30"
        + "09060355040613025553310c300a060355040a1303676f76310d300b06035504"
        + "0b13044e495354301e170d3937303633303030303030305a170d393731323331"
        + "3030303030305a302a310b3009060355040613025553310c300a060355040a13"
        + "03676f76310d300b060355040b13044e495354308201b83082012c06072a8648"
        + "ce3804013082011f02818100b68b0f942b9acea525c6f2edfcfb9532ac011233"
        + "b9e01cad909bbc48549ef394773c2c713555e6fe4f22cbd5d83e8993334dfcbd"
        + "4f41643ea29870ec31b450deebf198280ac93e44b3fd22979683d018a3e3bd35"
        + "5bffeea321726a7b96dab93f1e5a90af24d620f00d21a7d402b91afcac21fb9e"
        + "949e4b42459e6ab24863fe43021500b20db0b101df0c6624fc1392ba55f77d57"
        + "7481e5028181009abf46b1f53f443dc9a565fb91c08e47f10ac30147c2444236"
        + "a99281de57c5e0688658007b1ff99b77a1c510a580917851513cf6fcfccc46c6"
        + "817892843df4933d0c387e1a5b994eab1464f60c21224e28089c92b9669f40e8"
        + "95f6d5312aef39a262c7b26d9e58c43aa81181846daff8b419b4c211aed0223b"
        + "aa207fee1e57180381850002818100b59e1f490447d1dbf53addca0475e8dd75"
        + "f69b8ab197d6596982d3034dfd3b365f4af2d14ec107f5d12ad378776356ea96"
        + "614d420b7a1dfbab91a4cedeef77c8e5ef20aea62848afbe69c36aa530f2c2b9"
        + "d9822b7dd9c4841fde0de854d71b992eb3d088f6d6639ba7e20e82d43b8a681b"
        + "065631590b49eb99a5d581417bc955a3323030301d0603551d0e0416041486ca"
        + "a5228162efad0a89bcad72412c2949f48656300f0603551d130101ff04053003"
        + "0101ff300906072a8648ce380403032f00302c0214431bcf292545c04e52e77d"
        + "d6fcb1664c83cf2d7702140b5b9a241198e8f3869004f608a9e18da5cc3ad4");


    /**
     * C.2  Certificate
     * 
        * This section contains an annotated hex dump of a 730 byte version 3
        * certificate.  The certificate contains the following information:
        * (a the serial number is 18 (12 hex);
        * (b)  the certificate is signed with DSA and the SHA-1 hash algorithm;
        * (c)  the issuer's distinguished name is OU=nist; O=gov; C=US
        * (d)  and the subject's distinguished name is CN=Tim Polk; OU=nist;
        * O=gov; C=US
        * (e)  the certificate was valid from July 30, 1997 through December 1,
        * 1997;
        * (f)  the certificate contains a 1024 bit DSA public key;
        * (g)  the certificate is an end entity certificate, as the basic
        * constraints extension is not present;
        * (h)  the certificate contains an authority key identifier extension
        * matching the subject key identifier of the certificate in Appendix
        * C.1; and
        * (i)  the certificate includes one alternative name - an RFC 822
        * address of "wpolk@nist.gov".
     */
    static byte[] userCert1Bin = Hex.decode(
        "308202da30820299a003020102020112300906072a8648ce380403302a310b30"
        + "09060355040613025553310c300a060355040a1303676f76310d300b06035504"
        + "0b13044e495354301e170d3937303733303030303030305a170d393731323031"
        + "3030303030305a303d310b3009060355040613025553310c300a060355040a13"
        + "03676f76310d300b060355040b13044e4953543111300f060355040313085469"
        + "6d20506f6c6b308201b73082012c06072a8648ce3804013082011f02818100b6"
        + "8b0f942b9acea525c6f2edfcfb9532ac011233b9e01cad909bbc48549ef39477"
        + "3c2c713555e6fe4f22cbd5d83e8993334dfcbd4f41643ea29870ec31b450deeb"
        + "f198280ac93e44b3fd22979683d018a3e3bd355bffeea321726a7b96dab93f1e"
        + "5a90af24d620f00d21a7d402b91afcac21fb9e949e4b42459e6ab24863fe4302"
        + "1500b20db0b101df0c6624fc1392ba55f77d577481e5028181009abf46b1f53f"
        + "443dc9a565fb91c08e47f10ac30147c2444236a99281de57c5e0688658007b1f"
        + "f99b77a1c510a580917851513cf6fcfccc46c6817892843df4933d0c387e1a5b"
        + "994eab1464f60c21224e28089c92b9669f40e895f6d5312aef39a262c7b26d9e"
        + "58c43aa81181846daff8b419b4c211aed0223baa207fee1e5718038184000281"
        + "8030b675f77c2031ae38bb7e0d2baba09c4bdf20d524133ccd98e55f6cb7c1ba"
        + "4abaa9958053f00d72dc3337f4010bf5041f9d2e1f62d8843a9b25095a2dc846"
        + "8e2bd4f50d3bc72dc66cb998c1253a444e8eca9561357cce15315c23131ea205"
        + "d17a241ccbd3720990ff9b9d28c0a10aec469f0db8d0dcd018a62b5ef98fb595"
        + "bea33e303c30190603551d1104123010810e77706f6c6b406e6973742e676f76"
        + "301f0603551d2304183016801486caa5228162efad0a89bcad72412c2949f486"
        + "56300906072a8648ce380403033000302d02143697cbe3b42ce1bb61a9d3cc24"
        + "cc22929ff4f587021500abc979afd2161ca9e368a91410b4a02eff225a73");


    /**
     * C.3  End Entity Certificate Using RSA
     * 
        * This section contains an annotated hex dump of a 654 byte version 3
        * certificate.  The certificate contains the following information:
        * (a)  the serial number is 256;
        * (b)  the certificate is signed with RSA and the SHA-1 hash algorithm;
        * (c)  the issuer's distinguished name is OU=NIST; O=gov; C=US
        * (d)  and the subject's distinguished name is CN=Tim Polk; OU=NIST;
        * O=gov; C=US
        * (e)  the certificate was issued on May 21, 1996 at 09:58:26 and
        * expired on May 21, 1997 at 09:58:26;
        * (f)  the certificate contains a 1024 bit RSA public key;
        * (g)  the certificate is an end entity certificate (not a CA
        * certificate);
        * (h)  the certificate includes an alternative subject name of
     *    "<https://www.itl.nist.gov/div893/staff/polk/index.html>" and an
        * alternative issuer name of "<https://www.nist.gov/>" - both are URLs;
        * (i)  the certificate include an authority key identifier extension
        * and a certificate policies extension psecifying the policy OID
        * 2.16.840.1.101.3.2.1.48.9; and
        * (j)  the certificate includes a critical key usage extension
        * specifying that the public key is intended for verification of
        * digital signatures.
     */
    static byte[] userCert2Bin = Hex.decode(
        "3082028e308201f7a00302010202020100300d06092a864886f70d0101050500"
        + "302a310b3009060355040613025553310c300a060355040b1303676f76310d30"
        + "0b060355040a13044e495354301e170d3936303532313039353832365a170d39"
        + "37303532313039353832365a303d310b3009060355040613025553310c300a06"
        + "0355040b1303676f76310d300b060355040a13044e4953543111300f06035504"
        + "03130854696d20506f6c6b30819f300d06092a864886f70d010101050003818d"
        + "0030818902818100e16ae4033097023cf410f3b51e4d7f147bf6f5d078e9a48a"
        + "f0a375ecedb656967f8899859af23e687787eb9ed19fc0b417dcab8923a41d7e"
        + "16234c4fa84df531b87caae31a4909f44b26db2767308212014ae91ab6c10c53"
        + "8b6cfc2f7a43ec33367e32b27bd5aacf0114c612ec13f22d147a8b215814134c"
        + "46a39af21695ff230203010001a381af3081ac303f0603551d11043830368634"
        + "687474703a2f2f7777772e69746c2e6e6973742e676f762f6469763839332f73"
        + "746166662f706f6c6b2f696e6465782e68746d6c301f0603551d120418301686"
        + "14687474703a2f2f7777772e6e6973742e676f762f301f0603551d2304183016"
        + "80140868af8533c8394a7af882938e706a4a20842c3230170603551d20041030"
        + "0e300c060a60864801650302013009300e0603551d0f0101ff04040302078030"
        + "0d06092a864886f70d0101050500038181008e8e3656788bbfa13975172ee310"
        + "dc832b6834521cf66c1d525e5420105e4ca940f94b729e82b961dceb32a5bdb1"
        + "b148f99b01bbebaf9b83f6528cb06d7cd09a39543e6d206fcdd0debe275f204f"
        + "b6ab0df5b7e1bab4dfdf3dd4f6ed01fb6ecb9859ac41fb489c1ff65b46e029e2"
        + "76ecc43a0afc92c5c0d2a9c9d32952876533");

    /**
     * This section contains an annotated hex dump of a version 2 CRL with
     * one extension (cRLNumber). The CRL was issued by OU=NIST; O=gov; C=US
     * on August 7, 1997; the next scheduled issuance was September 7, 1997.
     * The CRL includes one revoked certificates: serial number 18 (12 hex),
     * which was revoked on July 31, 1997 due to keyCompromise.  The CRL
     * itself is number 18, and it was signed with DSA and SHA-1.
     */
    static byte[] crlBin = Hex.decode(
        "3081cb30818c020101300906072a8648ce380403302a310b3009060355040613025553310c300a060355040a1303676f76310d300b060355040b13044e495354170d3937303830373030303030305a170d3937303930373030303030305a30223020020112170d3937303733313030303030305a300c300a0603551d1504030a0101a00e300c300a0603551d14040302010c300906072a8648ce380403032f00302c0214224e9f43ba950634f2bb5e65dba68005c03a29470214591a57c982d7022114c3d40b321b9616b11f465a");


    public TestResult perform()
    {
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin));
            X509Certificate userCert1 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(userCert1Bin));
            X509Certificate userCert2 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(userCert2Bin));
            X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlBin));
            rootCert.verify(rootCert.getPublicKey(), "BC");
            userCert1.verify(rootCert.getPublicKey(), "BC");

            crl.verify(rootCert.getPublicKey(), "BC");

            if (!crl.isRevoked(userCert1))
            {
                return new SimpleTestResult(false, this.getName() + ": usercert1 not revoked.");
            }

            if (crl.isRevoked(userCert2))
            {
                return new SimpleTestResult(false, this.getName() + ": usercert2 revoked.");
            }

        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName() + ": exception - " + e.toString());
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public String getName()
    {
        return "PKIX";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new PKIXTest();
        TestResult        result = test.perform();

        System.out.println(result.toString());
    }

}

