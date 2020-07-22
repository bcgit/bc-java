package org.bouncycastle.asn1.test;


import java.io.IOException;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CertifiedKeyPairTest
    extends SimpleTest
{
    byte[]  cert1 = Base64.decode(
           "MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
         + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
         + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
         + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
         + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
         + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
         + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
         + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
         + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
         + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
         + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
         + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
         + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
         + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
         + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
         + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
         + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
         + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF"
         + "5/8=");

    byte[] encEncryptedValue = Hex.decode(
        "30820145a11d060960864801650304010204109ed75dc2111f006e0ea707583" +
            "daa49898241001fad2520dec6122c51f9f292fc96de9adb881a2101a49155de" +
            "3e4b04a4699ee517d7a7623679812f62e0fc996854d89df2daa6850862f11e4" +
            "f1751768e8a1a8da30d06092a864886f70d01010105000381d100bb1084782a" +
            "3b326390ce1096b44eda81e89b24e117c22b197a0df3ff3d181a5e3d96f30f6" +
            "a7f8b545733a867f27f299ff3c2c0ec64bcdca18f566a5e3be893e4842a7442" +
            "184a4d147066515d8bcb9aa7d8e6655937e393b2c45186119bf0869702fc58a" +
            "ae8a983ce5b54cf5273bcd2e5273e219e2947e41446612c8cf8f4d9e1ede52d" +
            "25e00d505485083ea8359f7767c0ae66ff47894f9d621459f50f60e0376059a" +
            "6a3b6fe7caca1c13274cf549f6721cf9f3654462687c7392a1c0efea2f393d9" +
            "4a5d33b829de8bd521c7205069db");

    public void performTest()
        throws Exception
    {
        CertOrEncCert certOrEncCert = new CertOrEncCert(new CMPCertificate(Certificate.getInstance(cert1)));

        CertifiedKeyPair ckp = new CertifiedKeyPair(certOrEncCert);

        isEquals(certOrEncCert, ckp.getCertOrEncCert());
        isTrue(null == ckp.getPrivateKey());
        isTrue(null == ckp.getPublicationInfo());

        encEqualTest(ckp);

        PKIPublicationInfo pubInfo = new PKIPublicationInfo(PKIPublicationInfo.dontPublish);
        ckp = new CertifiedKeyPair(certOrEncCert, (EncryptedKey)null, pubInfo);

        isEquals(certOrEncCert, ckp.getCertOrEncCert());
        isTrue(null == ckp.getPrivateKey());
        isEquals(pubInfo, ckp.getPublicationInfo());

        encEqualTest(ckp);

        EncryptedValue encValue = EncryptedValue.getInstance(encEncryptedValue);

        ckp = new CertifiedKeyPair(certOrEncCert, encValue, null);

        isEquals(certOrEncCert, ckp.getCertOrEncCert());
        isEquals(encValue, ckp.getPrivateKey());
        isTrue(null == ckp.getPublicationInfo());

        encEqualTest(ckp);

        ckp = new CertifiedKeyPair(certOrEncCert, encValue, pubInfo);

        isEquals(certOrEncCert, ckp.getCertOrEncCert());
        isEquals(encValue, ckp.getPrivateKey());
        isEquals(pubInfo, ckp.getPublicationInfo());

        encEqualTest(ckp);
    }

    private void encEqualTest(CertifiedKeyPair ckp)
        throws IOException
    {
        byte[] b = ckp.getEncoded();

        CertifiedKeyPair ckpResult = CertifiedKeyPair.getInstance(b);

        isEquals(ckp, ckpResult);
    }

    public String getName()
    {
        return "CertifiedKeyPairTest";
    }

    public static void main(String[] args) {
        runTest(new CertifiedKeyPairTest());
    }

}
