package org.bouncycastle.jce.provider.test;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for the JCA OpenSSHPublicKeySpec / OpenSSHPrivateKeySpec key specifications.
 * <p>
 * NOT-A-SECRET: openssh test vector. Every private key in this file is a deliberately published
 * test fixture. Each was generated for this test suite with no passphrase and has never protected
 * anything; they exist so the parser can be exercised against real ssh-keygen output. Automated
 * secret scanners flag them, and that is a false positive - there is nothing here to rotate or
 * report.
 * <p>
 * All of them carry the comment "bc-test-vector". A new vector should be generated the same way,
 * with ssh-keygen -C bc-test-vector, so that no user name or host name of whoever produced it is
 * carried in the key's comment field, where it is invisible in the source but recoverable by
 * anyone who decodes the blob (github #2376).
 */
public class OpenSSHSpecTests
    extends SimpleTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public void testEncodingRSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAB3NzaC1yc2EAAAADAQABAAAAgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNhOnlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClw==");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDvh2BophdIp8ojwGZQR0FQ/awowXnV24nAPm+/na8MOUrdySNh\n" +
            "Onlek4LAZl82/+Eu2t21XD6hQUiHKAj6XaNFBthTuss7Cz/tA348DLEMHD9wUtT0\n" +
            "FXVmsxqN4BfusunbcULxxVWG2z8FvqeaGgc/Unkp9y7/kyf54pPUCBcClwIDAQAB\n" +
            "AoGBAOMXYEoXHgAeREE9CkOWKtDUkEJbnF0rNSB0kZIDt5BJSTeYmNh3jdYi2FX9\n" +
            "OMx2MFIx4v0tJZvQvyiUxl5IJJ9ZJsYUWF+6VbcTVwYYfdVzZzP2TNyGmF9/ADZW\n" +
            "wBehqP04uRlYjt94kqb4HoOKF3gJ3LC4uW9xcEltTBeHWCfhAkEA/2biF5St9/Ya\n" +
            "540E4zu/FKPsxLSaT8LWCo9+X7IqIzlBQCB4GjM+nZeTm7eZOkfAFZoxwfiNde/9\n" +
            "qleXXf6B2QJBAPAW+jDBC3QF4/g8n9cDxm/A3ICmcOFSychLSrydk9ZyRPbTRyQC\n" +
            "YlC2mf/pCrO/yO7h189BXyQ3PXOEhnujce8CQQD7gDy0K90EiH0F94AQpA0OLj5B\n" +
            "lfc/BAXycEtpwPBtrzvqAg9C/aNzXIgmly10jqNAoo7NDA2BTcrlq0uLa8xBAkBl\n" +
            "7Hs+I1XnZXDIO4Rn1VRysN9rRj15ipnbDAuoUwUl7tDUMBFteg2e0kZCW/6NHIgC\n" +
            "0aG6fLgVOdY+qi4lYtfFAkEAqqiBgEgSrDmnJLTm6j/Pv1mBA6b9bJbjOqomrDtr\n" +
            "AWTXe+/kSCv/jYYdpNA/tDgAwEmtkWWEie6+SwJB5cXXqg==\n" +
            "-----END RSA PRIVATE KEY-----\n")).readPemObject().getContent();


        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-rsa");
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");


        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);

        originalMessage[0] |= 1;

        KeyFactory kpf = KeyFactory.getInstance("RSA", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec rcPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec rcPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", rcPublicKeySpec.getType(), "ssh-rsa");
        isEquals("Spec Type", rcPrivateSpec.getFormat(), "ASN.1");

        isTrue("RSAPublic key not same", Arrays.areEqual(rawPub, rcPublicKeySpec.getEncoded()));
        isTrue("RSAPrivate key not same", Arrays.areEqual(rawPriv, rcPrivateSpec.getEncoded()));

        String rsa2048Key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
          + "NhAAAAAwEAAQAAAQEAn/cyGwU5fpQyeNtMOvdawJu4TOKSjo8werfS9ZID43mLzCspbV3t\n"
          + "fhQfOgPLByUzBMqjKJO2kuX2NBe9MfARdYLcxyMuF7CTraozZmjkyVVRYkMn+P9SqHSMYx\n"
          + "YXjzqGxkqNWIcJI6FkIsXI0yIYXbpweFZd7PdolOilt6KbFQuW2jdbMthPJW6xG63+c1v/\n"
          + "r9go0hCw5U5IV7B2nUzcjIoKa8EiO3CKCzyLTf2kf32N+IUxzkJqv8YJc8jUC5tRvY5Utw\n"
          + "RGpO+7++oTuqctngmymJWuk3RKga//BoY3dsldyHC0uqXi4oEkdW/Pujzx5D4g1JBvVIuU\n"
          + "YnQaNh6HVwAAA8hYJQiMWCUIjAAAAAdzc2gtcnNhAAABAQCf9zIbBTl+lDJ420w691rAm7\n"
          + "hM4pKOjzB6t9L1kgPjeYvMKyltXe1+FB86A8sHJTMEyqMok7aS5fY0F70x8BF1gtzHIy4X\n"
          + "sJOtqjNmaOTJVVFiQyf4/1KodIxjFhePOobGSo1YhwkjoWQixcjTIhhdunB4Vl3s92iU6K\n"
          + "W3opsVC5baN1sy2E8lbrEbrf5zW/+v2CjSELDlTkhXsHadTNyMigprwSI7cIoLPItN/aR/\n"
          + "fY34hTHOQmq/xglzyNQLm1G9jlS3BEak77v76hO6py2eCbKYla6TdEqBr/8Ghjd2yV3IcL\n"
          + "S6peLigSR1b8+6PPHkPiDUkG9Ui5RidBo2HodXAAAAAwEAAQAAAQATt2ElSXCRCcJqzlod\n"
          + "Tng7aItqa+a1IYWlKoZwSXinOfJMI5Rt7CIl5GRblIoarbAVysVvbpLAlQ19KuE2iCjEEM\n"
          + "bA2LTeq0ntzB5HuhgGOg4s4VV08ECyOKNGYeZc0Kbkm93DZ+ltddVPdTdP0VJVgxxHs3Ai\n"
          + "O/Ws8jvdYB0N68zFvW7L+0raTTw/82yoZ0nLwZ292r2TQJRImyl5J08T4gY7d8RfpctjCq\n"
          + "abhBIqkEQ+C6wt87xXdX2bJdW+tGclVIKQCi6lh4apDsYNU5+a6IU4Ao8cz6LkuLhVjxtl\n"
          + "+wZ+KrUANZFKqx+CYpjkkFKFzBGVkzkRhPu9WLXQBLOpAAAAgQCdohE82wtc8ZzgTPW1sB\n"
          + "9QyO2/mt/JcFoyqjg1jWKWehO4yg30WsnUqmSdzyYbL7bMudxhgErhPXTa8nVSWqcmn2EW\n"
          + "iM7IAvgj2CarnSEak2iWWQDu+2VJw9IbXV8CnnuegGKOX8WhWRDz1YB4MRHsaIXmZVh1S4\n"
          + "FsrMYFaZB9qQAAAIEA17zGUZmxDSkdFLgSPGJgOWMUcy1r5XY0mi7BYsPpcgHRPoXsXgxQ\n"
          + "6zJtNfo9bK6CAa4ugLDK0345QY9pMQlXERRuWPrmlWgU+AWBhPXrGjMOWbiMf+tuHkkGAh\n"
          + "Aph/a3lta3DU6vWsdjK7sz8HWwEinuolUfu+TgDoR7zX0vfx0AAACBAL3R0+aIjedj4D2U\n"
          + "tczpGw8mBf59Jn9qNv1CD/YJrwxAS2QUSsW+t1Hp6Xgu9Khjc2dpaQ5CmkjdPQ0sIdReTp\n"
          + "bJpvQqAFg5HrUyUHUdnDd3hytuw5UAEBHymA8fr3edBdXSrnjLXt43kEpsu3IwMm6Pr845\n"
          + "0X1wzy3bjAtUIBIDAAAADmJjLXRlc3QtdmVjdG9yAQIDBA==\n"
          + "-----END OPENSSH PRIVATE KEY-----\n";

        rcPrivateSpec = new OpenSSHPrivateKeySpec(new PemReader(new StringReader(rsa2048Key)).readPemObject().getContent());

        isEquals("Spec Type", rcPrivateSpec.getFormat(), "OpenSSH");

        prk = kpf.generatePrivate(rcPrivateSpec);
        isEquals("pub exponent", ((RSAPrivateCrtKey)prk).getPublicExponent(), new BigInteger("10001", 16));
    }

    public void testEncodingDSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAB3NzaC1kc3MAAACBAJBB5+S4kZZYZLswaQ/zm3GM7YWmHsumwo/Xxu+z6Cg2l5PUoiBBZ4ET9EhhQuL2ja/zrCMCi0ZwiSRuSp36ayPrHLbNJb3VdOuJg8xExRa6F3YfVZfcTPUEKh6FU72fI31HrQmi4rpyHnWxL/iDX496ZG2Hdq6UkPISQpQwj4TtAAAAFQCP9TXcVahR/2rpfEhvdXR0PfhbRwAAAIBdXzAVqoOtb9zog6lNF1cGS1S06W9W/clvuwq2xF1s3bkoI/xUbFSc0IAPsGl2kcB61PAZqcop50lgpvYzt8cq/tbqz3ypq1dCQ0xdmJHj975QsRFax+w6xQ0kgpBhwcS2EOizKb+C+tRzndGpcDSoSMuVXp9i4wn5pJSTZxAYFQAAAIEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mBeP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSKHGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtc=");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIBuwIBAAKBgQCQQefkuJGWWGS7MGkP85txjO2Fph7LpsKP18bvs+goNpeT1KIg\n" +
            "QWeBE/RIYULi9o2v86wjAotGcIkkbkqd+msj6xy2zSW91XTriYPMRMUWuhd2H1WX\n" +
            "3Ez1BCoehVO9nyN9R60JouK6ch51sS/4g1+PemRth3aulJDyEkKUMI+E7QIVAI/1\n" +
            "NdxVqFH/aul8SG91dHQ9+FtHAoGAXV8wFaqDrW/c6IOpTRdXBktUtOlvVv3Jb7sK\n" +
            "tsRdbN25KCP8VGxUnNCAD7BpdpHAetTwGanKKedJYKb2M7fHKv7W6s98qatXQkNM\n" +
            "XZiR4/e+ULERWsfsOsUNJIKQYcHEthDosym/gvrUc53RqXA0qEjLlV6fYuMJ+aSU\n" +
            "k2cQGBUCgYEAhQZc687zYxrEDR/1q6m4hw5GFxuVvLsC+bSHtMF0c11Qy4IPg7mB\n" +
            "eP7K5Kq4WyJPtmZhuc5Bb12bJQR6qgd1uLn692fe1UK2kM6eWXBzhlzZ54BslfSK\n" +
            "HGNN4qH+ln3Zaf/4rpKE7fvoinkrgkOZmj0PMx9D6wlpHKkXMUxeXtcCFELnLOJ8\n" +
            "D0akSCUFY/iDLo/KnOIH\n" +
            "-----END DSA PRIVATE KEY-----\n")).readPemObject().getContent();


        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-dss");
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");


        byte[] originalMessage = new byte[10];
        secureRandom.nextBytes(originalMessage);


        originalMessage[0] |= 1;

        KeyFactory kpf = KeyFactory.getInstance("DSA", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec dsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec dsaPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", dsaPublicKeySpec.getType(), "ssh-dss");
        isEquals("Spec Type", dsaPrivateSpec.getFormat(), "ASN.1");

        isTrue("DSA Public key not same", Arrays.areEqual(rawPub, dsaPublicKeySpec.getEncoded()));
        isTrue("DSA Private key not same", Arrays.areEqual(rawPriv, dsaPrivateSpec.getEncoded()));

    }

    private void testEncodingECDSA()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHq5qxGqnh93Gpbj2w1Avx1UwBl6z5bZC3Viog1yNHDZYcV6Da4YQ3i0/hN7xY7sUy9dNF6g16tJSYXQQ4tvO3g=");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIHeg/+m02j6nr4bO8ubfbzhs0fqOjiuIoWbvGnVg+FmpoAoGCCqGSM49\n" +
            "AwEHoUQDQgAEermrEaqeH3caluPbDUC/HVTAGXrPltkLdWKiDXI0cNlhxXoNrhhD\n" +
            "eLT+E3vFjuxTL100XqDXq0lJhdBDi287eA==\n" +
            "-----END EC PRIVATE KEY-----\n")).readPemObject().getContent();

        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("ecdsa-sha2-nistp256", pubSpec.getType());
        isEquals("Spec Type", privSpec.getFormat(), "ASN.1");

        KeyFactory kpf = KeyFactory.getInstance("EC", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec ecdsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec ecdsaPrivateSpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Spec Type", ecdsaPrivateSpec.getFormat(), "ASN.1");

        isTrue("ECPublic key not same", Arrays.areEqual(rawPub, ecdsaPublicKeySpec.getEncoded()));
        isTrue("ECPrivate key not same", Arrays.areEqual(rawPriv, ecdsaPrivateSpec.getEncoded()));

        isEquals("ecdsa-sha2-nistp256", ecdsaPublicKeySpec.getType());
    }

    public void testED25519()
        throws Exception
    {
        byte[] rawPub = Base64.decode("AAAAC3NzaC1lZDI1NTE5AAAAIM8WklYS64PF4pjk1kvRPno981YfTRHc/KabXnvvPznQ");
        byte[] rawPriv = new PemReader(new StringReader("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACAW/E58SrX5iFoBlW0IlOiBr4bMdh38iLW4PvTcP/nSmQAAAJiV4ge7leIH\n" +
            "uwAAAAtzc2gtZWQyNTUxOQAAACAW/E58SrX5iFoBlW0IlOiBr4bMdh38iLW4PvTcP/nSmQ\n" +
            "AAAEC9KTOf3gXejV2hit9BMuunVsPUZwadjoe9Jzw5ZV6Gvxb8TnxKtfmIWgGVbQiU6IGv\n" +
            "hsx2HfyItbg+9Nw/+dKZAAAADmJjLXRlc3QtdmVjdG9yAQIDBAUGBw==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n")).readPemObject().getContent();

        OpenSSHPublicKeySpec pubSpec = new OpenSSHPublicKeySpec(rawPub);
        OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);

        isEquals("Pk type", pubSpec.getType(), "ssh-ed25519");
        isEquals("Spec Type", privSpec.getFormat(), "OpenSSH");

        KeyFactory kpf = KeyFactory.getInstance("ED25519", "BC");

        PublicKey pk = kpf.generatePublic(pubSpec);
        PrivateKey prk = kpf.generatePrivate(privSpec);

        OpenSSHPublicKeySpec edDsaPublicKeySpec = (OpenSSHPublicKeySpec)kpf.getKeySpec(pk, OpenSSHPublicKeySpec.class);
        OpenSSHPrivateKeySpec edDsaPrivateKeySpec = (OpenSSHPrivateKeySpec)kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);

        isEquals("Pk type", edDsaPublicKeySpec.getType(), "ssh-ed25519");
        isEquals("Spec Type", edDsaPrivateKeySpec.getFormat(), "OpenSSH");


        isTrue("EDPublic key not same", Arrays.areEqual(rawPub, edDsaPublicKeySpec.getEncoded()));

        // EdEc private keys include a random check int, so we check around it.
        byte[] enc = edDsaPrivateKeySpec.getEncoded();
        byte[] base = Hex.decode("6f70656e7373682d6b65792d763100000000046e6f6e65000000046e6f6e650000000000000001000000330000000b7373682d656432353531390000002016fc4e7c4ab5f9885a01956d0894e881af86cc761dfc88b5b83ef4dc3ff9d29900000088");
        byte[] tail = Hex.decode("0000000b7373682d656432353531390000002016fc4e7c4ab5f9885a01956d0894e881af86cc761dfc88b5b83ef4dc3ff9d29900000040bd29339fde05de8d5da18adf4132eba756c3d467069d8e87bd273c39655e86bf16fc4e7c4ab5f9885a01956d0894e881af86cc761dfc88b5b83ef4dc3ff9d299000000000102030405");
        isTrue("EDPrivate key base not same", Arrays.areEqual(base, Arrays.copyOfRange(enc, 0, base.length)));
        isTrue("EDPrivate key tail not same", Arrays.areEqual(tail, Arrays.copyOfRange(enc, base.length + 8, enc.length)));

        isEquals("ssh-ed25519", edDsaPublicKeySpec.getType());
    }

    private static final String PASSPHRASE = "JcaTest!9";

    public void testEncryptedKeys()
        throws Exception
    {
        checkEncrypted("RSA",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD161lE42\n" +
            "Pi10684+iRIdqFAAAACAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDXzhJv/fnj\n" +
            "qoSIfI0/vlqRbkseO79oy8z7MBjesqfSq3/B5qK2trgrUnw0dwTdZ/ZtoLKfbc6xu75JCx\n" +
            "ZQJtXLxS8CW3+n30EQFCfaU4YU0sdDYzOhzCOGOxWH6EOrTR+YNK46Ef3BiBng66ZR8HQR\n" +
            "zcStfETkTl7osQ+l8vVnH8YdeIC3E9kFryOvI4y6JYo+C+dT10iyNglKB/RdIt1DLfO9yi\n" +
            "KXvt4+6ecFkrQAknYbRG6ZoWqB8wwzUuRCOhILIdJrYZnQ7sMm2rQgYPk3YgrmcL4xEHGj\n" +
            "fPvBuOeEeQ42pJsSw1oAKhDBuZqSC//lLMIw2maJyh/WUzk0IpKxAAADwNU5x6Kk3dX2Lw\n" +
            "eKc7dUovv80XrVk15z2UpbpfC/9rUmJD9vWOpo/5a2+0nvJtRooC6NAvl/4Ygc1SmPhD0Q\n" +
            "5jc/uOzGHEL4vKavDruYMeEpbqziIyJX9/Zs/NMI6u473kDD+513Wsk8r0rPrsYNjgMToI\n" +
            "ZQbFVaNDQVrVgsmB/sAfl6DzXmNsVGEc8kTk4bmCU1AtH4u+vfYLNWfUxFf330P6kM6w2O\n" +
            "Yywvvs5J4gss2/YsPVM3S9SSfgDlh49ZpjDhA7WKqxJKI7pFlnTyI1TDMH/gcSp10/HCw3\n" +
            "+3GRgiDvGhJQlIC3m88fse3nkffNFwAwP/VzdfNq6WnZEjFb2z4sHwNDWzqtYxYNMHr13d\n" +
            "R8n8ZTdlodccDmP6vED/SFA/fsnBtpVqgtV/vepwzaDxp6xv+ItOhNN/hNBPsiwGt+9Bfh\n" +
            "LNNEwnT9bt59CE8FM7rlyRi0XcY6wz5LN6G4tJUQHJmjfZy/htkcqwvVCgaVQ9XaZ7HXTL\n" +
            "7ApuOd/G9NZ7qzwzWJ7MAHzIgOJUFWXKdd0H6M6YE6ly+JTBRGvH5QM7WHzMbqk9Y7fnHu\n" +
            "Lm8g5g2eyeSquLg69lTh5Vp6TUOp/gfw0f3YwiqqgzLFep7dUs1JklXR40AqsCSt/dI6CW\n" +
            "9knDLJ63i0P8Mp5rPYY/uLxJ3GYdNacXvMX+v6eZSkkkacCHtQJEqey0y9MmSuaEExvLia\n" +
            "Hmdd0fBuS2zpkLpDmqNlKy8aMQWiIRMZ9cFAhGWbrzqXQ3vdR17swRBKYyHaQo+KNRLdQN\n" +
            "FIDLi29uWv+QFGiN61DqKwbTd8xVeGJpl7QHYeQ7NWnCkvE9jQ0COXS6VSsTVfPSGQrrYM\n" +
            "Dg83whRCsE1aAlH6DhCBtYosvAyESGW3z+JB3MMur8K4EFkdx4TQTIa2PxjrSNqHrDyifO\n" +
            "O18qUmNjGSSaJ7NacTADl/xy5/YJm1cLc8QovEDCzj1I+huz79apBTuo6He7WRv9Nat26X\n" +
            "SB3lwokZg9Ul1NNs8nJe8LJ9v72SyUaQKLXhRHblWHdP6FRd9X8BeB8Gze2ClQIoCE5bRa\n" +
            "S5airRSn624CLdRhoWV7xoYNq4KhplPXSQEAUN/mSERv8faM3Gqp+on7Iy5eKk8B8HLy8s\n" +
            "7Ci5C7z1lLNRsWW5IAUSrlh9ZMwJjqiCnfvbs+UhioonFN0/95RK3racB8wEgn+rsrSWid\n" +
            "u21N5w2Lz03OU8TaoaLyLXNoot4vALf9nwFBuJXRVPbFGIezeVTlwfjSy+7VUOEHbTk9vr\n" +
            "Ec5+BKvA==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100d7ce126ffdf9e3aa84887c8d3fbe5a916e4b1e3bbf68cbccfb3018deb2a7d2ab7fc1e6a2b6b6b82b527c347704dd67f66da0b29f6dceb1bbbe490b165026d5cbc52f025b7fa7df41101427da538614d2c7436333a1cc23863b1587e843ab4d1f9834ae3a11fdc18819e0eba651f07411cdc4ad7c44e44e5ee8b10fa5f2f5671fc61d7880b713d905af23af238cba258a3e0be753d748b236094a07f45d22dd432df3bdca2297bede3ee9e70592b40092761b446e99a16a81f30c3352e4423a120b21d26b6199d0eec326dab42060f937620ae670be311071a37cfbc1b8e784790e36a49b12c35a002a10c1b99a920bffe52cc230da6689ca1fd65339342292b1020301000102820100076acd466d1fc41bedbf352cb3a6aabd39e1ba11caa3e2f15226d68bfceef8b62d477052625e485930d615058c34c1e87ddf1a9491351bf5bc760d3c00983d1bea5491cbac490c4ad3af25a982da6667d232763be5913b1d5775877ccbaa9d157b69401dbdd58f6bca9be8ed87fe7036d6702e984953e17fb096b9577650c9f104f5458a90c8ed1cf6f931d5b8581323a116bb000f55370bfd6fc76b7e7282e6fd1d5fac9706e7d7df0ac3e89ecd5332f6861ecf969c003fde52c291d33d5ef8dfd7afa40728112059a35a3907ed66de22090024710e79a8bde1c2c0ba4d7634a231a7810514630a2a4b70879d73f1c0643f77992d8e85725ea4558d5ac2e93902818100f5d08b4c00542dc28d435c2656f2d5cddb121ec37d0608910c49c78adc05b3dc715d8a9cd6587fc84580a317fb56143e06cc243c38c205e9a0deb619beb8de1bb73480e91c60b448dd25e0e49b6f86255cfc641de7ee4a1e14a0393012b8adcb20c25f4bfe2d430950417920f421e32db2f59d8fdfea6143a61d1109b40b366502818100e0bf3407801551262430211b1480822c88e4f9a0d9dc1b1a2a34265adbc019262e40fc3b06dd026bd9db7d9e85d05ebe80cd4c368926e551f663b68cfc7c6f8a09fd66e868c904f60caddb0639b6a87b8e63abb3053556ddcf79128629ff46463b62ea986049edfcaa7641f10423149c191d4e09cde934de6e817d8c08ab905d0281807f60594e40bd5e18fa6a754dc8b07ce9f723249dd823503d194902058a8dc9ede930b7ab1dc72e2ff113ff6f65e5ed07572e61787350d70f8134e6d7e0649b737133dbb8efe38c885550538122aa5fb0ecc63c7ae2bc2fdbf684301e211561b96878503968b4bb900fee5d7e1e03915d14e701869459379d7e6e816dadc641a102818100db4530b9f098dba75ebf264d895f27a1d39db27ee08f025230c2d878e4d532b431846d92194c1f44a234a706b67f69306bf1e05d84ca5209f95da7893dfd19c58fa18f7948627758a75e27c697204298e97f0cd1884f5604ea9ab11bfc757656a73206b7cb99d57b21c466e982a3c743d4ace6aa621f18d9baeed3528053027102818100f4b5c83a4a1b563e8443ba0c7321535d0c6dc4f15c7a279a55f07c5f961103bdb55c5ca6401c6c6916610c326be947b949e5c07bebf39905be7932322cb134484a54b10ff1685c44261233704e7a9331e5af80647dbd720247f97b5ad6705a2b12e406825d5d9148bae2e304e7f1b09eb6cb18fa785db11db2ffe73c04c35f38");

        checkEncrypted("EC",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAOogjjeo\n" +
            "aVU68ltMP+q3tDAAAACAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\n" +
            "dHAyNTYAAABBBFm3+0a4rGSMMSdzzD+b3pU4QgP06PXWlapVNUbysIwqAxBHdEwWN5igP7\n" +
            "Q4iquLqAo4sW6BklV1USinAq9nUngAAACg6WvPeWBJ6gxRwdQzAjA36LMgrex7YOLSHmqK\n" +
            "OS2Pr9jU6U916Y4swTWkPTOiZd8BtZQlxZDO8j+NH9u4Pf78a6KgOFqlzNpLX2pEbWvJdH\n" +
            "C8UA5hT2URljyjXN0Cl07+ZEa/RlaefHTwRz8Bt0A644dRW1DzEG0ZMYJI7SgSe2xHZixE\n" +
            "qyf39Kh0CFR9w85riewHhkhqirjpXEDfHmqYKA==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420216628564e8dfa84c0c2c25c6fbd0cbe7f32a307129d39f9b60631b87dcedacea00a06082a8648ce3d030107a1440342000459b7fb46b8ac648c312773cc3f9bde95384203f4e8f5d695aa553546f2b08c2a031047744c163798a03fb4388aab8ba80a38b16e819255755128a702af675278");

        checkEncrypted("ED25519",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCjrr6jc4\n" +
            "ZpEUBJsIVatOqYAAAACAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPNMWHgvCtqcFVVt\n" +
            "ewr+2mcc2LQI8K/sFdr7aybivPuYAAAAkM2eCuYHnnTyBrWfum8j19kabdXIWo5n9SGJYb\n" +
            "i5mBMsBAye8TBPHyXQ4+nhVGAhj6n6SUEEHqtr5RgGDhztyQTiNqNiE3qzwHBnC+T8OYga\n" +
            "t7omiXDvV4kBYn9e2ntjzQBbrGvc1cF8Zz/0+w8jkMjuYX/oJyFjryhu5C6YzzHCct/KBe\n" +
            "7xZT4KQTBi4SkdsQ==\n" +
            "-----END OPENSSH PRIVATE KEY-----\n",
            "3051020101300506032b65700422042063f03b6c96b23fd6cb3f92683d7b26890fc7139ef171b182702ae118e757995a812100f34c58782f0ada9c15556d7b0afeda671cd8b408f0afec15dafb6b26e2bcfb98");

    }

    private void checkEncrypted(String algorithm, String encryptedPem, String expectedPkcs8Hex)
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");

        byte[] encBlob = new PemReader(new StringReader(encryptedPem)).readPemObject().getContent();

        PrivateKey decrypted = kf.generatePrivate(new OpenSSHPrivateKeySpec(encBlob, PASSPHRASE.toCharArray()));

        // pinned against the PKCS#8 encoding of the key independently recovered from the same
        // ssh-keygen output (decrypted with ssh-keygen, key material extracted without BC), so the
        // assertion does not lean on BC's own openssh-key-v1 parse of an unencrypted twin.
        isTrue("decrypted " + algorithm + " key does not match expected encoding",
            Arrays.areEqual(Hex.decode(expectedPkcs8Hex), decrypted.getEncoded()));

        // a wrong passphrase must be rejected, not silently mis-decrypted
        try
        {
            kf.generatePrivate(new OpenSSHPrivateKeySpec(encBlob, "wrong-passphrase".toCharArray()));
            fail("wrong passphrase accepted for " + algorithm);
        }
        catch (InvalidKeySpecException expected)
        {
            // expected
        }

        // a missing passphrase must be reported, not treated as unencrypted
        try
        {
            kf.generatePrivate(new OpenSSHPrivateKeySpec(encBlob));
            fail("missing passphrase accepted for " + algorithm);
        }
        catch (InvalidKeySpecException expected)
        {
            // expected
        }
    }

    public String getName()
    {
        return "OpenSSHSpec";
    }

    public void performTest()
        throws Exception
    {
        testEncodingDSA();
        testEncodingRSA();
        testEncodingECDSA();
        testED25519();
        testEncryptedKeys();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenSSHSpecTests());
    }
}
