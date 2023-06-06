package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import java.util.Enumeration;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.DeltaCertificateTool;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.DeltaCertAttributeUtils;
import org.bouncycastle.pkcs.DeltaCertificateRequestAttribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.encoders.Base64;

public class DeltaCertTest
    extends TestCase
{
    private static byte[] baseCertData = Base64.decode(
        "MIIXAzCCCg6gAwIBAgIUKVPIYv++YikElsn2jRhO6cKjwwQwDQYLKwYBBAEC"
            + "ggsHBgUwGjEYMBYGA1UECAwPRGlsaXRoaXVtMyBSb290MB4XDTIzMDQxMjAw"
            + "MDAwMFoXDTI0MDQwNjIzNTk1OVowGjEYMBYGA1UECAwPRGlsaXRoaXVtMyBS"
            + "b290MIIHtDANBgsrBgEEAQKCCwcGBQOCB6EA69UFcFR9Ce/qEbr3v9CXsBYs"
            + "e9WtnyfarolVKWSp007hnquDh6tYkhDZlvdXDI4s/qB5pDhTCy4dL0jVaE8t"
            + "IAxy1bRHe6jWltDwmOEtGGvMQ7ORsHxhx0ZbRnyQPxwc/oAeJYDQ+SY3nNae"
            + "IxEIwS5UHyLNVa4mjr84JvSai1ZxgodgH7AikNSJVBmiVnvToenUYjddrDG3"
            + "P9RPP7ouvVFSXnVFUnwPvJoN+Z/4jcHIDZnzAN2Lm4tbAyu8SS3IEf1Tl1v0"
            + "y0AC7vErJ1cEllTnakjSJHBbT/uEjecN9DReGfQjTVcbMj8ajUS1muWMUio0"
            + "OWT4u+tyFWi01zhoxGJBViOwGg9+gQarvF3ymLpvRaZTI8e8FjiwYa5ZXHOa"
            + "qYwDqogkbw5ClOj6GeVProDTHgrrwcG7WFx4QpFDbI7QynDLL6dmj0y7lOKk"
            + "BWqsBNQawLwkDU9j0xXNXhP6ZP7Y6G2Mc0UVrMu5+I+/6PYoF8GSrgQ2npn/"
            + "0huyXcVdy8uxVE0EPv5csAm/3rw9gswNw+ZaFDrVtzutx4NQDlHle/VX8g7T"
            + "C8iW/FJQxIvrrD8j3iKaWXO4EElrEyJedlWwT576616CRQndVhCpxypEKHQi"
            + "rWdJVV0x/78GQ/bi/ljs+V1Q0+nNuD1w5s5yvG1K/0cucTHF1c3nFHf5XPUA"
            + "/gkUwg8q9m+SZoulkkr9KuaTDKjRRHUyPPGxxE2Wcv7hzhbD5p7sJxuCCmuy"
            + "9D0REWS9S/o+1GhsMWXZVJhze2C3UdsSiVX/Xn9/LVnQNKcRZYRnlSb3bMmU"
            + "+tJXV7TpdZOTrpuHL90Es8Pw9b+BYx0pZbwlu79f0E24HgsEoc+C0bTe9eRH"
            + "JG6f3oB5DxA1Y/SXAq9YEltKAlGVN3KwpAmo7w+yshF7q97/v7/QD3sxbmel"
            + "QVpktSX/QeOmCpDme5IqebQWONSQvoe63VTbDfO3ktzKQW8X874pPyQgL5O1"
            + "WGzEc5SaGJ4VNcWEt79pU8+8yy3WDHa3YH6TtvpDlEbbE0o5QSLL8HD8lpPf"
            + "reEItdBJlJf3I/BTLh1NV9/AswgFxfF8DK+a6w5JyvgRgEmNXDIhBvSxay4B"
            + "UxOhbUfY9cFeNd0FYr8KHWH1Odr7xxkRtXqPw/lJe0/FE2FF3CgHQQHpWo2n"
            + "Hd4XSGvLBEfZGeeWzVj0mUYbk0uAnWVxenNUfqY39D3jYTnZPUkSyWq5LO+H"
            + "sP+DjmYq1Fo142hmovIxoXBdhcGejmCoTLA0Fbpctm8yixKbrp7WEk+myx7t"
            + "ilN44IGYPPwn84oaPCEqqqQnhhPCWPkF290kap2ax0kshL0XNC+YfDpO8mO8"
            + "ETkPy0OjS89OnHpW0tfpRGsafnT0E4KMTJejo04k+dhJZ8VDr9rn4a1t88uf"
            + "c7Sk/Ha4loRV7UVpZKsc8GTnXt2beslsD31LNom+QHnakrGFko3/3/EPL4lV"
            + "pX7eUzIJ4XKQRNtuQtdZ6bXOHppv6oJgB9/UT3ZuN1g/F3QJNuxSX2hi4O2P"
            + "dWJm5lIZEgZIdY8MHaygZpj+CiW4/pqDd39SelJtP7fyhYkAY7w5i6hHLhGN"
            + "Tkw/cDxXeC2lTxXeGObX5nEvgyncCFlTxOIGUQ7ajFJXY3egQmsQaNb42GMo"
            + "cDgp7a9QXvDVoXjwVhJbAtB6Xb0FpxIBuOaaXFkF6gmPLB0f16VHhSw+XiBP"
            + "MauDAkXrJUYbGr6fjU6kymSALUDkRbUPOZ9tBdSl3L3IOy416HAlnj4QwHl8"
            + "Jj4+yMW0SsDYX1zWO0e/z0q7tQPBBKM2bir79nWWBauFPGesVp94uuVw0fto"
            + "YZnbjcLa599bzxotndGcWWyPC/MeemWMilJXaxptIjwa+lBM5M+IQJLxzDtP"
            + "GtdvQ0PGCFpWX2FSvnifG5sm5r83x0J6dOyvD4VJhavGUIw/1+wVPLY/ruLM"
            + "OdhN1ZZwqDHT7L8coHef+sRx/phIDA11L+tzg7MX5r7zdfJQFDH0QcpBg+wp"
            + "E1Iv8JWwN1J8nATp+R318cZ+s8cooS5ctxyEi47TZ5w1yFQzqhTwcUDwVkCc"
            + "L9T4hbfhDgJ+rHCVftrYoFrWoh6yMweSN+0lFbOMpBIt+EXyG5ahK8PJFCiB"
            + "L81T4CA5kUBT3bhAMPre5Q4jmTiIAkojUqrOGRdUuyhiP4nPvLhh6IXX/3dI"
            + "o0aHt8/sMBzJEpkOg4U65jNZ29TGEbId4w8VtG4syHB71tDEdIWsdBrQmXM1"
            + "BWZktOGe7RsCUIuoHaJoUF8kajrNFxJOhzSbf4o9biWGx/mlrEqnFs9V/aoG"
            + "Wk9Bg7yVG34l9FMKHALTC9pUB5LGjE8RAyvpCpH2spDAsmYc5CVjvelqCBfe"
            + "zJEXNXx9lBumje1v+iAc/TaBpfAfX48Vw98xtA8tLSVtt99RfswkmG4ns7eX"
            + "keSj0cAxI/SRAypUXfDmp7xR4mIi7up9w5QAfpPTQpryFVzwJ6c/XXz+gUUA"
            + "RuZqdgn3VLt4o6wBXUtPkaV9Ow0piBC9PJ32ExBvGVSX4mWhpANBw73Nat9p"
            + "gIz7UPUb7t48cBGYcOLOR19pCmASD/7y8tPMREyyG/q1GrVsPpsOvnnLroWj"
            + "ggHQMIIBzDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAfBgNV"
            + "HSMEGDAWgBSnR0zxUyIgM7vgnjuFITOEQ0wMbDAdBgNVHQ4EFgQUp0dM8VMi"
            + "IDO74J47hSEzhENMDGwwggFnBgpghkgBhvprUAYBBIIBVzCCAVMCFDuDlxbL"
            + "cbyTmD/9Owt+7pXDgyvPoAoGCCqGSM49BAMCoSMwITEfMB0GA1UECAwWMS4y"
            + "Ljg0MC4xMDA0NS4yLjEgUm9vdKMjMCExHzAdBgNVBAgMFjEuMi44NDAuMTAw"
            + "NDUuMi4xIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt59pmAR8k"
            + "YICA8KkPpdqgwGQZuMXxYVKBsrr5/Bx6aOBLgS38UJoAD2vOM576akBtIvZr"
            + "N4/3QlvAz1wJ1kOupEAwHwYDVR0jBBgwFoAUMtR0tjyJdMysRkYQGYx7tf2M"
            + "59swHQYDVR0OBBYEFDLUdLY8iXTMrEZGEBmMe7X9jOfbA0gAMEUCIBBJNwwD"
            + "LScv1AU9Bql7yiy5q35yq5UjVM9Bi7i7I4sNAiEAk0H8idnkC2SdKQFg/RgL"
            + "D3MOB36FwjMCCS02S9DlV94wDQYLKwYBBAECggsHBgUDggzeAEnxsoaaxg+k"
            + "z+y5KihroSOcrotcMaQ8pYS5GY7eOQx6Ov9Sm6SyNGL+SQLwVa4WGFbbB8Mx"
            + "DHviHkaGpyNAFth+zRqDQ7EAJhWV9nhv50W7H4cgFCc+A9JnGf5KA/s7ck6d"
            + "71+T0qv5c3FYWRI4CclobHQ4c0EsDVdtoi091Lozs0AeQ0FsjD1R7gzeSFej"
            + "u42Wga89bfc+BLCA/TJ/RJD8xXhs4Fo2r4d/EvOuKsG0X5CThuHKI2DM3jwI"
            + "Ou2+Y2ZP0s7ofZmPW2diMAsfEFHZPjSPsSIgLkeKectzoR9+FgLDXpozHJz1"
            + "IZTEV52Y+jPw7dRZhtFzkugMjwtDzKsb2xxka3bAPjuqlqHvh+2AgoR99LzF"
            + "mnKIKMexKDhMHusxcM7wrcFXqSXRPJ/mg0tkijCYHKUUk+fp11PqUeQ80RKx"
            + "Q+oJLjwvDkZklLfHSpoolbWQctxzSedlvXWhXGN8M5+AXyy9yeJIK4vKSWWW"
            + "P0qbB4wpg8la244ID8UHLxcIbV9T+uVXfA1DmuX+h6UcBcd2RRCcjAjV1lll"
            + "sg4p2ygDXSfj8/LTiHvx/gPOC01cvJm2fikG89QLVRcn1oVBDZsy2Z2xcxzZ"
            + "gSLRToeHNTEH/afBzzy58isoM4nYVuTInxJHDMwIVFaFYrJZdiRtxE8o8tOr"
            + "kENttU6BKhAlSxltN2n1M49zehO24xCcpRoTdGdtvrloMArV9JN9iHvOGi15"
            + "zoBvpRbGzIm8RUsSnWa6WIAwRbjpuJ1iMWP/07T57feyRHXNC1ZkwwaAGdau"
            + "nt0yJakGEREWYO12gH42OsBUZlqe8X00AJlTCoozHPeMdRqYgj+UCUCFgZzu"
            + "M3HLctyLvYMOzDAlqz7EUtfVS4NsszJSHYYueFuogPLTMUA4443D+1omNZUN"
            + "z5ZbLtqOelCu8aQE6NlmZ4Ikfq0s1BS4m2JzrpLlOXzQHGDqdxXoQDMhwv0N"
            + "G0j6V3pOedWaeddsIhCrX/7a4BOmqoYX28NG1x3CLMT0LJAnuogUqS+OcqHm"
            + "2XVZoMQovGJnGFrBonBawKFObIAyeP8+798oTzFiPyaHkI0RVHk0aERMOPAf"
            + "IGVh8JBMfUlzWLXrvBLRVIKVrF0H9n6VZaImbowwt4kEQoPstAKoUWlxeAEG"
            + "2naxc1JYWEx/pLRB/aw0X7rAas+P4aG/epiR/nRIWj1LZQb+OAkPAnZgn4lj"
            + "NxoEMM6Uos8mFjcA/uIH2Cd17XlZ2Ez4sQUxk+LrLbYqxAhI07XjVFELLRmP"
            + "U4f2ljRqryXyRD7R2QQJ8GWuO3RgEUIUI8XcU8rWSfPgo1EWaOVUi2yGFuiw"
            + "5KJfcvifSn8IRFL0OSoDmt5+Iuoz+zmfdi85ZhaBwLpz6/qHyBQAX3jZwUzN"
            + "A9QGi+NhVWdLZfGivAwaeo24p2tPbe0lC6ED35G6fHY2+6KPxKWt0gbd7teg"
            + "QQg7BdBDSzW1rSkQmNFLG4AG0V8UXKEPuAqBu0n4hautwRInfDHVGAzdlgcN"
            + "v9NXsMtsDKwTlFk8eoZn1oz8xGqSNbTudvjUEUsKLyJETlDQxH9CFlS0EM7o"
            + "IvV2ofAt6qDo0kuZcIwFxEyMItF7Hq5xyo44d5IMG0yhtGiTbsuqIJcn9JRY"
            + "T8QgRYvUsgIP+TuyUQlPpsKwN8BiT0stdOZzTRkAzY9+Pxl8eR5sb31+13uG"
            + "eUQ26Rq0GLxEUEDF2npKK8j6ojTK9CHCESiKzFVU+531ecriq98s4Os+azgI"
            + "o/ti8oxobm4yWBv5cN18/GFWBC1+HJ8T6M5H/FuuOM8kMo+/Qh5W8853x1bY"
            + "mC5YCSJ++oxfWxdwoOU2gGCPTJ89rF8ZYjcw+r9qiPS60r+A99W2CdHl6wOB"
            + "faPjytFD6ITRwygFjA0oOFiqiYfXQ1FtpQ1hz3EYMlEdWHeZDLAbA6WZk5ue"
            + "PNQLL3IA8ryY2h57FITA6s/6tJ4szZQO/6Pr2fqUjISab+BA9XA82UtIEJ11"
            + "wWwMGtBTIi7vXsya09WnWvnH1sEV6mbh9cxj16LRMj/s7rHmspyy2g7oqRbN"
            + "ToqrBGNJJYEeGQNxeqW7tm62whc7DgYrm4k24vW4sHmp0pZ2+l6K9GzG65dV"
            + "eHSRJgC6vK1HZA4jl9pilIVAGDzEV3x2QWr3qOxQf0WZcuRvLBGou9Ym7ISG"
            + "nKvCaCDNAPzlDDRiNMGKBWef839yJPkTY8SPic/VRuaGZOqiH/smv4i+JBEC"
            + "1FvZm6qUaaDV46AwkZnJF8TENZEUHOzDx5l2NhcwNikgBYQ5Qlspw/nuLzkI"
            + "v3gS3GgtR/h/bymiUPu6aJcPIbNd/T54iYmiDW9ddnI6/Qe1lra6AAP4aGR7"
            + "O6xp0Alx8IirNBYmp76PL1ZFiJJK3EfGxwRUAQn4gy64TdTDkdoxWjHohR6N"
            + "hPr4WtcPRzf/Qovd6Ip00KYdrmD/1RdRcsy3nWFaYVPXMZ+3SI7asWQfhohT"
            + "qPlEX0vT7teUW5FJT1ROXXSvy5Fer0PN646ke2qtmQADQfMc/Gtu9m1s666T"
            + "EIbUdXL0oYeThDSRs3adGmzQdD3SnC7cyIAqlLlokCr0378+gGGrlz6d3bNd"
            + "SGFNd18iPYvYsfYJycX6BOmZwIGeh7E9DwwGYC/i6mfpu8+eu1N63SAW2rlz"
            + "aPH5TTUUiLr0HvJIfc0yJObhAK4vAdOaaAs10y99obcUZZ1Vb5gqcZdh3I+V"
            + "T2oD83xzkcIknHAvdhuxroLsBNz99SamXrpkS3RMgh/Q1sV9Zk2hETLeelwt"
            + "6XkU5vf/M/ohbbfU+PcRcLoHWwtXBCuOg8pRC/Gzk1NukI423PizRPTAhYnI"
            + "axdB3XfZ8eNqzeCORmXldmng24g6/fybLphXfcF+d7r57wPlRYcf1lM5Ag/H"
            + "alds3vwqQLhuLt4XE92UwdRT2ZBrdfHstXQW3JuLylmsLp3Du21sMYQ0fpFO"
            + "LQObT71JBJiGYY2TfoNOP2EhTsvPz8Pa8pp9DKYeB5rLdoHUs140wnGpvQnJ"
            + "UIk2HBdi5SqaY6cdpUHRbtFTKbYaYcrReaMtvrQw8VzpIG7wytYRrLJD2LKj"
            + "E2bw/sm/aBkawLw5CaIXrR04nHeiryHcxO51bEKz+DCr+MpAxB0y8uuEJ4/M"
            + "pLc8OAvWfcwRjv1nXIkex+o+h/kGWBGF2ZHsePBuuoarzL71Wm1uBlTHRPjv"
            + "QpmNVhL1mDnaLXu3e4briiSR8dcwYhgkbUaa0qscMFKbnWRs6qVjAHlF+JnB"
            + "B2Phy7unAVlW9wKPWKEygbSmsAW2ua0CoFBoHFSaS+0WLgfLNq3CbfTrvSq/"
            + "nrgjRy3jme6vZqSyAN2QqdD5gBAyygnYNB4/iHIME2iLv2exLMDCRYwhh0VZ"
            + "hP5vlit9IJmbmSt8fgP2Y0hv1woGml0WXs43GgPd4zx3AqfDiLt6C9Ukep98"
            + "z2c/rUDx6bpYIAJeNtTSGMl9woNK7/sfrd1xpmR/aJdT/dpZROB4sk3/ctx3"
            + "5nXe3CylvcmUMEbNyOKp1naOBAojd5N7gydGvnMuEbMVWnl2cYuDsi6F6CV2"
            + "KGmRIInUNbL1c31ATjfSpol4tJtVTyr08ANL7/pqa1xBp5ddn9CrraZywgc3"
            + "lfDIrqOFMa6mWRGOS1n8xxCeYLS/R7xflNpD6rhNsgUYnP4L4531aa7gxngq"
            + "p/4XVWCgVt+4Y4UvNpR+/eJSFNDKk0nn7LNpFT9J5hJdQWkhmCQRohICyUvC"
            + "DHQMjaYcP+ggrLn3M3O+ViHG0siX5UJhwfpbnRBqWl/775QXiiQ4PZ3IJrfK"
            + "w33P3ARnXjzxmxNWOiFRR/PAs0qaZCSseuSWNgenoQyP6l9ljcg1GUYYS9R0"
            + "CIZJImcOqslxL+dkTwL72xLW2HluPwxYkioWnfReUfmeUg3OmzJWUoEcZBjr"
            + "YnxMsS2gKzk0CKTuFJRTsVg8/iWrQNYtJuBcsFcyQA5j4HKf/qCdfMsrqEld"
            + "4ajRq5WGNzr3/65bPxgnhuJ9xP54zJeprBcGa72/FPkMDMqWJP2pN3mlzvOT"
            + "721AJClfKY/YSBoM4GyaAPUWI4q3PFnKBeqmaD83JywnMa/5mJ3+bt/KthpQ"
            + "gmjV57N7g9wOdk2iho8VYtQGiRfDXKkeen8XKk7Z3weotA4k3wop5YxM/ZXb"
            + "bO4uAYaOUETUKZ0TghAITj0E9LDlVy0V+AHrY/4/JZ6xdUsMXjs67lYFAuCD"
            + "dHVxSizHj5212o4ciYYqhjeGN6XtM2qhZJM1uWZswYZljcbtM9ulW5jfg0d/"
            + "0J2Y7pcfJDdq86i4oSyex5+iLi2YAfA+hhpFJFMsSV+n4BUgIzlQaXB+1wAc"
            + "aaGm1UpSYqG99AcPRF+b7k1WX3iI6AAAAAAAAAAAAAAAAAAAAAAABQ4UGiAm");

    private static byte[] extracted = Base64.decode(
        "MIIBpzCCAU2gAwIBAgIUO4OXFstxvJOYP/07C37ulcODK88wCgYIKoZIzj0E"
            + "AwIwITEfMB0GA1UECAwWMS4yLjg0MC4xMDA0NS4yLjEgUm9vdDAeFw0yMzA0"
            + "MTIwMDAwMDBaFw0yNDA0MDYyMzU5NTlaMCExHzAdBgNVBAgMFjEuMi44NDAu"
            + "MTAwNDUuMi4xIFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt59pm"
            + "AR8kYICA8KkPpdqgwGQZuMXxYVKBsrr5/Bx6aOBLgS38UJoAD2vOM576akBt"
            + "IvZrN4/3QlvAz1wJ1kOuo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB"
            + "/wQEAwIBhjAfBgNVHSMEGDAWgBQy1HS2PIl0zKxGRhAZjHu1/Yzn2zAdBgNV"
            + "HQ4EFgQUMtR0tjyJdMysRkYQGYx7tf2M59swCgYIKoZIzj0EAwIDSAAwRQIg"
            + "EEk3DAMtJy/UBT0GqXvKLLmrfnKrlSNUz0GLuLsjiw0CIQCTQfyJ2eQLZJ0p"
            + "AWD9GAsPcw4HfoXCMwIJLTZL0OVX3g==");

    private static byte[] rsa_ec_cert = Base64.decode(
            "MIIFKzCCBBOgAwIBAgIIaLtn+ZoOPkAwDQYJKoZIhvcNAQELBQAwMTELMAkGA1UE\n" +
            "\n" +
            "BhMCY2ExCzAJBgNVBAsTAkNUMRUwEwYDVQQDEwxKb2huIEdyYXkgQ0EwHhcNMjMw\n" +
            "\n" +
            "NTIzMjI1MTU0WhcNMjQwNTIzMDA1MTU0WjAxMQswCQYDVQQGEwJjYTELMAkGA1UE\n" +
            "\n" +
            "CxMCQ1QxFTATBgNVBAMTDEpvaG4gR3JheSBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "\n" +
            "ggEPADCCAQoCggEBAPTegns+vTNALyCqUhWCAe22B1hDi63F4orq48sgQDl98zLd\n" +
            "\n" +
            "xrr4BwpJ3Q+9y8f2SiRjH7rjMo8+Ry/o0H+etSzYi/7nf8sffc2+w3cVRzYd3GBV\n" +
            "\n" +
            "bXaFb+7OP0AlBS6lc2w4j7zm6thV2hz9L7XKEEt8O8MHCttbODVGXGihb3Dvw0XV\n" +
            "\n" +
            "UEDarspb4/zN1eKhK+6uZLyl+WkdX3Pev2RDbUH/Mz990YCpC5eWozDpA0NxgOP8\n" +
            "\n" +
            "RDxkBwx2TuUYwB2oCmyVsZ6vaGVCSL2kSWjdBVM6f60LgyMvneanx+PET5IX/znH\n" +
            "\n" +
            "+NQoiJz3Hb82KuPZLg+L/CIG0DiDEYJvD1yYY/UCAwEAAaOCAkUwggJBMBEGCWCG\n" +
            "\n" +
            "SAGG+EIBAQQEAwIABzBOBgNVHR8ERzBFMEOgQaA/pD0wOzELMAkGA1UEBhMCY2Ex\n" +
            "\n" +
            "EDAOBgNVBAoTB2VudHJ1c3QxCzAJBgNVBAMTAmNhMQ0wCwYDVQQDEwRDUkwxMCsG\n" +
            "\n" +
            "A1UdEAQkMCKADzIwMDkwNzA3MTg0NzU4WoEPMjAzNDA3MDcxOTE3NThaMAsGA1Ud\n" +
            "\n" +
            "DwQEAwIBBjAfBgNVHSMEGDAWgBSLhHJw3CWoK6tG+vDHA4+A3WZQfTAdBgNVHQ4E\n" +
            "\n" +
            "FgQUi4RycNwlqCurRvrwxwOPgN1mUH0wDAYDVR0TBAUwAwEB/zAdBgkqhkiG9n0H\n" +
            "\n" +
            "QQAEEDAOGwhWOC4wOjQuMAMCBJAwggEzBgpghkgBhvprUAYBBIIBIzCCAR8CCC8r\n" +
            "\n" +
            "86yn2wm8oAwGCCqGSM49BAMCBQCiHhcNMjMwNTIzMjI1MTU1WhcNMjQwNTIzMDA1\n" +
            "\n" +
            "MTU1WjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENMAU79zHGMdY7BrUcoi10Y\n" +
            "\n" +
            "2v9yGwq6rF/el0HFrAVIW1f9GfPZZQI5OJnqf60/X2IRc4KecyfqiVjkD3GEWJyk\n" +
            "\n" +
            "QDAfBgNVHSMEGDAWgBTWuDKUFK1U61Y5aP6Gm9/hU/81LDAdBgNVHQ4EFgQU1rgy\n" +
            "\n" +
            "lBStVOtWOWj+hpvf4VP/NSwDSAAwRQIgH6haXFeIfy+TOPWFEsxfFzehVcQAy4NL\n" +
            "\n" +
            "gH1wiKp61ecCIQDGD0NqMadMAnrfIy8MiH6kkZ0LEKDVpbh3k1CvaXVB+jANBgkq\n" +
            "\n" +
            "hkiG9w0BAQsFAAOCAQEATtjhu3Yuy8mw0FIbvxm8LwE18OAb4De7XZXBBQrHHlA5\n" +
            "\n" +
            "HNkvcPPba7171LcpIZx/SW4C5sIxfwn0rFZ8uTUKdiQSmmqfwH1t2NZ1fF+oADF3\n" +
            "\n" +
            "goxuxEYHczqVUYSugllqMJx0T/7HgD3JEd3DOYrk4k2ksE557xVwEm5OBBNTiz0/\n" +
            "\n" +
            "2M72GRsSbma2xo6tFiQ6iYfI3B2NgW0jekN9wOlF7p+SZFeq1afSEDrfVSi0DkVQ\n" +
            "\n" +
            "zyn7PMrrZgyYpjWr1GpnvNBcZDEpH7TML9GUxchn31w0FvaLMMgYJJ2ha2ohPQxV\n" +
            "\n" +
            "tV9dNL7ivNP74nJQqT1x05vXhjrL86VOlwxa385geA==");

    private static byte[] deltaCertReq = Base64.decode(
        "MIIV2DCCCOMCAQAwIDEeMBwGA1UECAwVRGlsaXRoaXVtMyBFbmQtRW50aXR5MIIH"
            + "tDANBgsrBgEEAQKCCwcGBQOCB6EADgP9Zs5yca7mEmzlHR0k0N0IE1th8SwOx4yl"
            + "dWNmbQQhbV2qVaRUsm5LP++HSpv1eDWw5oA/8OJTP9hfCJDFJzV4avX2zfcNyQhL"
            + "6ETIoL2IOfJ7wtEj346dbV9kRu9X29Y4jZpS71KFZSysr9oU0bxY/eO2N72zBG0I"
            + "rsHhdkNnR1kR05ys7Z0fsHfBeaUnTaY+rBwMsMBzrJzlLXree/MDkFBmwWIneD8X"
            + "9INfbMW/zWVb2HETR24DFcX3fICjIHKbk8Y26jqlvvtMVTunXRTzCxiL2QVGwRf9"
            + "A4OyNqAAxLud/5EdmjJZv5oEba+fJAOaxCIJT4DCyP/Ntdo2bzNF0C4/lqlwswDG"
            + "XZSBery/SypI+ZO03iggG6aPmWlwGK+z+UnSxATsExUSbjt3NSomRSIEiot83kmZ"
            + "rI3aDapBW4SU4bkac6oGLyelWs6uF9JpiIczjWLPrtkzYroD5YLbqjJlYoYZ+vNG"
            + "lwqRh7jKZWgV8kXMt8RhgcDZCsJPhKCURljNwimQ6yUHfQpRXU8asjSv3TtM8lBN"
            + "ipvxGG8UK7wADNqtbGv5ReVgZ5GNG2CsF9ulKBIQbdLcFELdj+Pt3qIinftun+YB"
            + "0JELMo0OE9v+3/TyL2pD59hWtg0IeeO1EL+xVoig+eYbqmCOg8wF5r8D0qLPngPE"
            + "fgDPPM9l3dToSgvaMmqyS65DV93yJxm/lfRW57WzRcyJmphfsviHIanEcWxfr8ir"
            + "gXZ6lCBRtrho+3Jz/PUpb4DFGjuSl+RECkxX817JoZY8z7Mxra+f687OnH6D9HNF"
            + "nQct0ECufsI3Y+g4Rv9924mNnF6vWihtSQMRlmtoSwsPAML3um8ShQ9aZhsyYaI5"
            + "lgfXHlgHBjzxhqySVz3bc+OZft2DD/XbcpoWUFBWRHz47Ws7ikClfAJU8tLSVPdy"
            + "KddSusSZiAqkBg4frSWgVb52GrsspfvmIietjZia5hUXxyDZPwuohh9VIliKaBf2"
            + "zi6r0MN1btNvC9/Vic/l4wrAs1CPeszvQXmLrBHQ3xTqX05AGHonYwy2tob0wcCH"
            + "mdKXZrDleyO8kHBEZTDlLfFJ8z8IaKyuAjxbW5+IL7hgX2N+rUzMobMOZ6i4Yw2o"
            + "B1/Icf/9Ev2yhmsQS06uPStPAc6nzm4kvBg2VcvbiD5n6V2qRwUKFw48cZkwqe4u"
            + "1Mo+jnUcaY5oktZ5pILWT8a42oBqE8lfcQgKaVDORrEa8yJX/cUh0MoExxUt/TOJ"
            + "2/h16ksU1plDf/rqRI777brHFJYDkaTP384q4NP4SeU1mh7atMyO1MU714Gwuf8A"
            + "mqocXGhmqJQYgYY6ruPqorGwrUZaFrYPoU1ejQeYspjBAJfaerltIok07klO1YVW"
            + "ui7VA1pj9H5UrMdcUNqRskkX2Dc8TE1A/gPpUOLC1he2z+jw8lRd/hJlue1ukqRo"
            + "vOGIH31UCGAOKjyCxzDeaWuVH90xJyR1f1x0EdSRpV/EWCI+hxMa8+mayPEYA6U0"
            + "kiFSF6ZrLmNo4GGD1d1dY+LtNlZe1X9qzRnMWyz3PbGfB/P7ObWANlojparQ2Yp3"
            + "K7isLSm/jxnu356M/YhrMFvvXT2AIwRZLhBUvR2VXWGhZNql9jS5uOSjuFqMb85K"
            + "NZSro6kxFagacgWb4P/TUug0eNwe7BXKUZeVfHpYTy6wZmiXk0SjLIrLTI+nr6Cu"
            + "dhjkeG4eBd/0LCGKSMoFN3nfXzK3ORxK6zEKqbVmrBZ2CW+N7+DYB+GcWPQu94de"
            + "BiN8I2IfouFpfTQ3irygb3HNa3pb5ndFoP3SOVoeowQoaQ88DIZWUrFEInE0Ux/Q"
            + "LzkWUIsMiA6D0M8rHTFb4GUG0+hU2RbzFkhSP8idT6Wn/b7AenrNYRYxgS111gTJ"
            + "9m+K5fPjD6+a92AsWyhB11pMhIfPYlR1nC836Bahv8C3WudeSTlPrRXhfUhoVsS1"
            + "lG+QCO/uNQPg+vmmK8wq80eNh+rBzwgEHZerPFAZug8BD4iLE3i15eMzAbL3H4VW"
            + "2QS/yTAnMq335nUYbKzDhsp293FoQ3k4Vv/4Mvmt65gy7Bt6ZnIAoL3ypTgHqkoG"
            + "jwAE+eNlZAtsgBKYrnm8uaZb3EQNojJPtfKyhs8dUS5dojNrfPimc//isj+RkoFd"
            + "NyaplYwmAccWuyHsi9zjT3O1dFZguySFDb4uLrwnPixCEJIa3UdQNi26fi9fgJ5t"
            + "bV4ik0/SP/iX6/xR3U9NB7MKG6PCGbqctYvIb+0RJqfJ8KPZTw93dU1eZRlf8PDW"
            + "5rS/MPgwu+JgNA2PaY+69/xtIA4tipABzD3HK173+LQ6YACA3ImObHE4qAWVVn7q"
            + "dMHTDLiKlwYb+Bn4c3nOUrXmyRNynCKMt+V4fmLLb/WndRjzYSeVMEizmU9sExk9"
            + "Q9kIsywTfLkd1XnX/ONA4PLnTIerkjo1iud1fmQd3DTukVgs3u12yc+cX1X2U79p"
            + "RFErlhnWf2UK36FbYjhKRmiskWKW0HXpIVB3QQNegISdm2t+KdWEIRxrf7JK769P"
            + "kBsERT4Dn5jxbVo20ng3lw0KmMbGEzlb3asKrkOBfFCgDP0FZtdP7uIilLEqQ3/8"
            + "2W52PPKgggECMFkGCmCGSAGG+mtQBgMxSwNJADBGAiEAuzw3TSKB5aQZrCczI3RL"
            + "inpTq5o9pLd58kOsXI98x7MCIQCsUeHBmbxrgLI5iIDftpbXF3/WSVip2Ydv5851"
            + "Qb9T7zCBpAYKYIZIAYb6a1AGAjGBlTCBkqApMCcxJTAjBgNVBAgMHDEuMi44NDAu"
            + "MTAwNDUuMi4xIEVuZC1FbnRpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATs"
            + "pv9stFIT9jtUry082Imkfq7KxMR5rPW+KtMUMyWAdU5dNcsRFzSPrgW65OMqTFDj"
            + "OnKon9jebVgGadJbMeIcogoGCCqGSM49BAMCMA0GCysGAQQBAoILBwYFA4IM3gAQ"
            + "f2I2kueNW1kV/bTRT8kxdkHJ/Pyp52YygU4qp43W008N4s9ATxo4bM3wl+92aLzv"
            + "eqHFg5cowfwYxChP90gFkJni/0jrXFe8rI/h8i3sqoqwJu5n+XZRx/ykcVPrgbfW"
            + "8P6G6su5A8KE+gy2TrM1RhBBjPnd6Y4XlxML63f4I642cC+WNGAhxhWsxmeY9NNx"
            + "N9UgG3G/XsRVuROp1BNw3H/YyVVi20TTLXeHDk7vREhSauqkNUO+aMJUeYb+AHW1"
            + "oHiT2oT7vlK+ir97aFPG9Jih/mKLLHl+V7ye5ZASbR2qMfJEUicMTlbVgMBOEqPP"
            + "a6mDZeOGqxFBReLjgivo9cubYDbjwN1cvhFzk99Qua82WQW1A3vOPIEhb8MIchcj"
            + "+6LRQaKoFbtV7W3KqY+BhwPRQKp/f7jyUTg2gFe+URii3HgHaPngyUuiVl0Xq73Y"
            + "Z/qREXDR2JoFHeYqC2mrTYTNRAMkXR8hAUXOxV5VGy6d/L3ZQOkt095b3Fkyus0I"
            + "wdgZ96NtdblD9IIp8ymDjTufJJCRhj13kJtVpRygQ1KdNJNrb71w2ePjnU19IYWK"
            + "FXz81d2xJssLv8VxfV2ldqdLmlr3CliyKdEULqAH3DzGhvifKkHkTzTd93KnUXrV"
            + "oywgC7LaI8OqF7GeQDICkSg6pN1SRpN+DAWgmoycI6ufNSHmrSCgVtd11Xdj/PV4"
            + "vz9MZXsLGdO/x9F3Jbc1K3cN7RRxlWRiIk4c6idVJmyCdssD/XvJGeoq7jltAjrJ"
            + "kpmjxsvd938LatwVXGwTi7lRg2Jrun2jE1BoeJ3vISb1xm8mvM3OSG2ol4q3DQmf"
            + "/uIPhDwvp7EASAN9VUKNB7O0AcocNSisEHzWDSL1b0yXyQ9Ygg5xx/Xm+c5xXzf+"
            + "U+BaJ8GrjHMvuVkq5YjfcYsiuf3YwrZLGUQiNsr1AKz31qGnuuHPFJdQPcuGagKL"
            + "wAV4Sg7TjfFelqiqRv886nY77ona+GFmk6KaQuccbYWZUfS8pw8Y1yNPS832MuYi"
            + "vbUUcx+q42do+0L9GtHi/FIF8XQYAbSWEh6V+AQnGP75EyCt047a0Nux/YG1th9r"
            + "O2LonjYu+nabUpLAUPDGJRbwu/fh6+St6zBTbBafJHjE0Nqi38e0/z0y8NqKIOFJ"
            + "BG9O0QihAYG9XYaUeNq9CAEMlEu+gzRgq6OWdURIobVvYWtKg1WLx5MORwH6ssZH"
            + "nS6zi0HIJ2EQ0MaFFYOH12ltiD200eazXgyJ1nZyamyABt8dkZEbRz9RwohWS8bQ"
            + "Cgc686vk+wVmV2zLkyKBjeYngQS4auofe+xwxQ0D7vu8i5NmfxSep+iKKXn331Xu"
            + "GUvSuMyKzkzdgOKj1etH8Xi8qv8iBVF7zBTwMg0pyX3Fg5THvrkqMai3DgLCIzNR"
            + "awJL4SkjyokYyhafrA5fUELCy5YbO/fc+v1isDCZdcDILvqdH6ANavmK2+sNOXF+"
            + "wSpRqttPY5/H59lCTARqXCdVyhBVBLYyMQeJcGrUuHVfV9yTXg8vJ0fCLOyxRUcD"
            + "HVE3p7p3rm+cpHvhg0JeI5ut4/sMIk7/vigK8V366wnItFdhHfKogMOJN87o31hG"
            + "0mX4kRkvx6fIJ0X60kJmUK6cYDRn6/85A/5BzBf0IagbYjdqPTxdesnJixeRILQf"
            + "CT9B2qPvfKAd+3W9Oh8mGaQoup0OWDw0ESbccaBO8951a6h4RKheizQBTH3uFslb"
            + "tm4htv2wk82yM6am4xe3Il9l54swLu5voAPbH/BacHegq/6KuG6UTygXkh8a2tAt"
            + "wLi5a1/j58f9q7d5SQC96K9FyvPxuZ4cjd/31ZLwJQ1g18CLsJMMTj60rq3OwfKH"
            + "tG4Qlxa7IB/wNAhljGezmpt+MZeOdLxkLI25MiPounGoLdZ5um3XGHosOn+/XqEb"
            + "SgMhMvsNYhM5VKvuutXqAaw5S8IUQNqHwnxpgyETQ10tY4caE5Yhse33eE/xucZq"
            + "h3VIL4wfAEl2n9gJLOzY++N7lgA6thICGgTA30ZMfWCq4IPAuZPKvUeeG2OZt3UN"
            + "ui5CeGnYcpV6AxrbvF9q9ScmqPs/tn0EkDYpVyz7mvMKhAgDNZnUQwdrZVmKnAal"
            + "v945oAbkEsMC21pUDpZyfp8rYKxMmwU5RLbkadoL44ReUGaWSbKmxBRCSOtTWeng"
            + "sCk6s0Te1lEvRPdlluPjlBEq49vxw6aBHzUMfpUsWwv6ip7N/6x/kd0ztMCeXHwE"
            + "W/FSd0lhCw0XaWzV+7URjQAeQswATXI4u6KBNRKM9LScsRlBlUV9/luttYjhUM+g"
            + "KvXmXuhhgCl1izQlFiErcB4haT0yf9why7jvUwy7Z77LmyxSn5RWXlO5jWXxZLXm"
            + "fu2+EiSpQ45G0M53suYZ/5hdLywab+etXRSxWUQqr116uPBv90Q5Mvfo69MHqf6H"
            + "FEJGfwwzWeAgkHiAhNbCVqI1DYWtlpU5LPNHLahc2fcQGBqhwIIVRnL/IMm/NKD/"
            + "IbxPzoLSrlPV6XL6xgw7gj28Tug+7sd8o5b5vDiH+6ZY30bxe7e8g+FeEf+j9mM5"
            + "GQk+s7VfhH9SGnoziBua/q+D5lkRfsENoFHR8olfsJxj6/kAJk+qCo0u6p/yOHqU"
            + "iJxXoqjSPMhdjw56VbJej3rql/vFGWFjBk70kPFnNCDK49I+6s85idzknpTmMEzP"
            + "U9f/8fUFmWyv+FsGrIzdSNIG/P658XPQFWLuNTwlABTvpBtvg01wLf5Fua9MenJX"
            + "KC1nElJ+52DCHKBO+olRGByFQqfppXRWiW08mSX+cv3afCPIT2TayiUnGKIpHLMf"
            + "/7foHDdmrGCWRdOT5F6S3LFbsRIHiMGSyFYQ0uaSR7130cx0V0r7lH8TyrgxOhcv"
            + "vHhRtS/OE6k3i17dn/2aENySAPRhsuanUFmIWPoWqM2tDHN4TnoR0MZps8SJEkHH"
            + "IuwgWKiTj4A8Yl+bzuBs5B7XHmLm6iKP/TSa7fggKz9rbOEoL4jQtHt4RC+ml6dn"
            + "I6hQzeGzuS1g5x1Ty9vaWoNExLsBt1sUbTvNYUWQBJoQC9iNcjF7IH9L4BarfMH6"
            + "0LLGC3K1AKvGwMKISY1/I6VHSDexEPFLrrEI/E6TyNzbqBWr5CwPO0otJJ04Mu/w"
            + "pgxDmVaNFuYNwkbwuuXDEemQRGCxQfMUessLKqWxmy+U5oWL/T2/8HtZq3wrbAj5"
            + "IPZ2lYua6nOlhwfd9rDhKEvyG3BLG6V8Abpx1/iXI1V+mZdKuP9a76TWDKdw6Z3G"
            + "DD3wNUKN+PvOIzaDQpCTAEA97+mKbPD7CwsLYZWHDGyZ07biSVukTr0FM8Qpo9HC"
            + "3kjP92c6+jRpA6cb5pumKetBwGRQot/1MkJ5YNTutBiX5p2sRBTWeW2ZffrmZOEy"
            + "7msPhtZdQnTUqh5QomKw4KyF5DCNxggJ2Y/aNq2hD0dGbkzoXCy3QQPvr9aS51yq"
            + "5yQiXlwW8eB4C6ZF7SPFinM/okX7jlxQ06JDuX0STDP7j1umN/Wtj+3XZP4++GW+"
            + "dQzBY/t/TJQyJWYvEfai4d305DUkgLfpvWkvmFaNfQdx2+RC0+Pl4XLNtRn7dznl"
            + "P1CgeQ7d2shQJitol1VQpylVIK2n0zNF+c8wWkPgJVQYtQ++7qcDUugIV1j5JVNJ"
            + "QndGRz/7RKmp6F8zDa2QmuQzaOjiPwvlG9inMkWORCvuXazI5C0gZTKRVMh+XPc4"
            + "bj0+JcfGL2W1xN0igTaHgzXNsWBHXyN+xXfCR0JLeP40PvqyNqrqeVA4KyyWNXIK"
            + "7vve9v4PcB96D0UWmO99Le7GftR+60KP7ZD77Fu1uggEyazCx2dxR4CeVT0sYgHG"
            + "u+Jd4Ygk7h238ejniq81/bDObJqn9qhWcmKttbhcEd9y2QIRxFHpKQWSdI/ssy3O"
            + "IvpKbXcOdxn22oCKk+QqgiVTs4qg/1V/l07gj3GzATyzhjyMYsXe3nPcZiRi9/TV"
            + "ldYNO+V4kWqOUeobVv+Dm2dAZbTEtq7H0wIlCrRiimnoOLOQJkSwsYCIbIT3X0M2"
            + "DM2CpQ9FhssuamheZWfMaftOZb0Xg4EJEXiXfj2dx1m+k5VDPeg3ZptC3dsjb/RJ"
            + "LN2pbzM4VCE6A5BAQlqNIgXaA3HjmNeET1HQQ1DCaX10W/kz9DNVBDhAVpg5bqm5"
            + "Mk/J7meuxSPZcKYMUMZ7s5/e41HWXWk6AJ2ttrptulU0ZlagGwDmAKDciaDdJljd"
            + "IJsHKAjK06M0CtvAhoZ65hUWQtinYtX5f389QPlWltsUtVhTB0puQsL2tDBbDkPg"
            + "k4w6W+N+6u+Sp0VCr0x5ChAePVJccXKDhPwOJOobHTdedX6Gq/QBNICJxNXe+zJV"
            + "n9XjUnvQ/gAAAAAAAAAAAAAAAAAAAAsOFx8kKA==");

    private static byte[] draft_dilithium_root = Base64.decode(
        "MIIZTzCCDFqgAwIBAgIUONT0zs5OI1dwa7N+gcOBNTQEwSAwDQYLKwYBBAECggsH\n" +
            "BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg\n" +
            "UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1\n" +
            "bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg\n" +
            "LSBHMTAeFw0yMzA1MjUxNjUxMzhaFw0zMzA1MTIxNjUxMzhaMIGPMQswCQYDVQQG\n" +
            "EwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5m\n" +
            "cmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERl\n" +
            "cGFydG1lbnQxHDAaBgNVBAMME0RpbGl0aGl1bSBSb290IC0gRzEwgge0MA0GCysG\n" +
            "AQQBAoILBwYFA4IHoQBxNIVkcLajfd6f/9uOqGfiWPTxem6oTmbQ5N0TOS/j0tfI\n" +
            "qxjz2CW2h5wcbs4UYc4KylsmNbhy+lo/3s0jbRmOOPuBVmv8dG8NmDty2ZWK5m3Y\n" +
            "hJIaujOAYSNfzRPax/7pDX4+oDL0zfO0i6S71BmBzcamX/11WxdI9okKN3Z7NQns\n" +
            "CMmfBtWab1POC/eoRwQ4+Sk39xpp2NPlSEeLVoQtgdLvmc0DNL87Gcoao2YfxXbf\n" +
            "Gyx/HsKbi03o7/nmLuT0LvTe0YhQ1dE5c1fxCVQHUeXFwyW10TyHfZMK+0mT77ig\n" +
            "NSfsUeHMEjqNPNhO94QLds26awaJAbnZDR9LJQ//TvI91FlwruBxnZtp0+2DR6jN\n" +
            "4lTIuaKjEX+HzxZe6k+jjg35erc3PEXNH3+kzIEWHgjYmANftoI4wulK9FOf7RVD\n" +
            "6k/G1/vIupQUZQ7brIVbWsevwUWgxpxNs0+noedA02nLjjqZhkM1bIqOt8AKZJgX\n" +
            "5ie6btnrkMMUFocxG5yvuO4fn7rreWv2T/S+kmKGou7scEyUowwjYv4t3sgFw0tN\n" +
            "4iK6htNyNo/9jX1Tei9QUibhlcqcMkVw6dGZAGSxdAvH0hD5NXi/dweENCaOGCPn\n" +
            "9Wza/g44TnLpXLH97U47tC0Gg2+do8jspmBBu3CQ6i51qJUE5vJxUCmlZy44PRXc\n" +
            "E9K8VUwtlma44yyfGmg9tZdWwZggt+gv+PION2T35HGzA5Nih7zCRK8knn4yhKoR\n" +
            "0H4IV0f5JrtoS1QlqTkaCJ5cv7I71hPPjQ3Ghtq3pudHDL/taFUApcgcaIsHQTPO\n" +
            "Sicp5/yW6+8xjEwiW3p//XYlrB6tsLkSXAz5UyxiIjwdgnZra/225ORg2a+bvfHb\n" +
            "wEircmGzVQEAqem+60l+J44slM1pR+tWSKi/AUPHl2yK7W83/uz4uZmYrqO1GWCc\n" +
            "2cb7va/nWPCKFEcX3JbBXpT9Xvyy1VFDf8WV6CxRgIk3E7ZxK04hLnTRCYNLuTc4\n" +
            "Bp3Io6nWmE0VgJs+jl/n5kcimU76p7s3YfnF9TOCtoQbrfIRX2FhBFsOeKZsbMDQ\n" +
            "zlsBZroMOAQ+cr+UwohSYX+yXKKK1ARPFFYdyYgLaOYzYB5pFr1BeM4fQrCoF7EV\n" +
            "PvWvYcaeoBQ0y7mpGVsKbPsp2EIZUIt/HY519acbHjkbIoAgTijBKBZuXbHOm5xj\n" +
            "58bvUeZt9k61U/c+AzJc7NnNf3HfHEBaXhvT5pm4GiVoFKmQZ9v8kIRNhuJ/ZGu5\n" +
            "Jhw7s/E/kznehECO8/iKn/gwoNiBCHWdyYrokv08G7XzMVunma9EvZCYY0O6bZiq\n" +
            "n2r0m7rvhMLkLHTrzGm9Ar6W0aXBwm03yeFo+zQIBr4AdNWXpy2Tt4NJYa4iIW5x\n" +
            "RuIyA6yDiPICBrT0VAWadtalLNf+t2ZUgAB7QPX7Ixh5gUBlBRa6EUqCvQ05GzZP\n" +
            "o689fzDqej+HQcRO0mU9QELnD6GsvA/+FWPaI0Cx0ONN/fpq8F7/GscTQkxWocEp\n" +
            "nWgWnqGh2k7rIoPBSzZ4MRG9bqeYJkQrUv+Ky8gwnRD3sUTWs3DZgVKvhd2X8PRz\n" +
            "Q5Dmqv8XIcY7mpR5nBDdY4O6z7jc8pblnJsjWNBd/mx5j2DRlH9mF1z8pACIXYNY\n" +
            "/YJ5him7ZN8M0Wk9q/Dp1HK40EQMfRjg3budcRpg9a+sUMeq7cljfPaw/RPv06Lx\n" +
            "rtbege1o6va0AE0s9QUrPRUS46H+VmQmth/QW8+P0MDEGyPsOh92NUprbQmgVTf/\n" +
            "hACbb6sMeLEx3Kw0mndUz8PieOdt2d05RkfGE9SXjMLLV27NMRUocd9x4wCj2j7J\n" +
            "2kNp8ujQIg/CoYdVa5pEdmG7FlD4UBnRsoPjCgX6vC2Lnjl5y+AXtWzrQ4d6LSnI\n" +
            "dZpH+5kRPssNtIRdm70jZgRq+KDYWQwvKbu5+5lXdQn2Fodgj96cQJbFfKlC9kfh\n" +
            "efykwuSn8uE8bYRwegx32px9UkeDhaPwUcLF6OC0OGgpbxyfbcqhdWhGGvTFhh3G\n" +
            "oZrm8ssBJDiiLA6azYJs2pCh9CG43CCRoB+DwS4c6xLkCWU779Pi8gIovpUQBwUx\n" +
            "EdQu/d1GTN9J6Vy36ZEoc7KIiddC5sH+CHxju+LX2IIv2OzqLwFiwH6r+7NQ378z\n" +
            "aCOMMBTNMEQsyauJS1vfLkl/mnHyxVYpbwi9NoJCfAnUZntsEEP1mn7G3S4+IPYe\n" +
            "Qy7hBUQamFs3uT7xaOcbnoiHvlQ1rm88HrohWtVQV4FmODrKHut4meBLUdV/ZVIC\n" +
            "acel/kmq/767H28n8PaKiQOrXnPSpwpXxeKKtO+aMdvFhL9ytVOh3JTdX7y2rO6m\n" +
            "XmauwfpcEWh1P04kCSl39Q0fi1ZzNw2O3/fdEdn+k1hNd05utNuD4YPF8t3ph+Gm\n" +
            "fybXAgWaKx5qEyrBKPKGSpHNVCM++9nrVNzSlPcDcrtrGTd2E1iQ/eWdoN2hCi2v\n" +
            "m7EctANAg+XPcrCUYRqV8FDqP7BabLLXvl/2aJ4tEwYq2MkgA/K2svXK0NsUbzC/\n" +
            "703auA9NG0XnSGsM2ir4ZzHtrbb1jW6ipAvc3sdlDI+y6Mv8Ju/mJUPQouvsfaOC\n" +
            "AzAwggMsMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW\n" +
            "BBQu8UGIwoTmWRQQ7brqObj6sy3nPjAfBgNVHSMEGDAWgBQu8UGIwoTmWRQQ7brq\n" +
            "Obj6sy3nPjCCAscGCmCGSAGG+mtQBgEEggK3MIICswIUTggpfah2kbN+5mHbCwF8\n" +
            "takhZ/ygCgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxS\n" +
            "b3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkG\n" +
            "A1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UE\n" +
            "AwwPRUNEU0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgws\n" +
            "Um95YWwgSW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzAp\n" +
            "BgNVBAsMIlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERlcGFydG1lbnQxGDAWBgNV\n" +
            "BAMMD0VDRFNBIFJvb3QgLSBHMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAdD9\n" +
            "cleoTHR/ViV1wHOF2+vy9SvqWAg9uC/dFTHYquPMh1/wL/f6LaJg2Oti1tL11kkn\n" +
            "jjIXNqBijLuzAwi25hjbAPYq0gTGRgNZvIGKuJYb8PD8DsWq6KQoFzzlbwDemxV8\n" +
            "HlyCxk9WL8re/EpMKPbTQs8+9hb8gtM7coXJIfK/Nv3YpEAwHQYDVR0OBBYEFI7C\n" +
            "FAlgduqQOOk5rhttUsQXfZ++MB8GA1UdIwQYMBaAFI7CFAlgduqQOOk5rhttUsQX\n" +
            "fZ++A4GMADCBiAJCAYVKnORbBIaDuB43sDb38eb4BB5y9o+wTLrIGV5DGA2yOUck\n" +
            "H56/L7H4yVFatiUZok6sRMOgGR7BY6BvuczFo22UAkIBGEMII9tQkwp/0oikSbkp\n" +
            "OMZH5UGlq8AL6TnD+YzMBgRq6dGZE/spGKLef6gyKQ1dKEatK/oLSgf9l7jgandU\n" +
            "ENswDQYLKwYBBAECggsHBgUDggzeAGjxVa2J1Vv0ogdEFtU61BqPvtG23l6GBrsg\n" +
            "kqPSt+6WHeHypIpiah5DKuCbbt27HvgnCe87G9+ktKlfx8N0+Sa8Y9QXfQ1gODHL\n" +
            "9GeDBx6AWrLFoZ9mcXcc2VrFgFwMqCgaUj9KqeQp69r4oHWsnm/1AaxdswKMakev\n" +
            "xqlYIeQDSspshGjWdxO8AuUd9ytW3f3P+IitJbG8wLnw98+LTotxgXwL4zOagkZW\n" +
            "KsIC0qCq/m/RUAA7SZIf1SXyJu5tdA/b1JK4NT6H74K47mk/j+RpF320DCrVPHkB\n" +
            "eyb/JmfEGuh4oJPyNL1Y5aYoGcX9c9WZpso8Hx6qndFeBpXsLGBU3XBwoKoUTiYb\n" +
            "JTmZmjcUHmYH3FXfHs+2HgtyoQ+tsnN9HaLkzJzwvbxZ4dYtGXm4uz3xj7mGGKkZ\n" +
            "j3LJyxzIuoW7yeOOKYXJTK+9pmmZTJw8m7qC4yXGesy7KhnoZ1/eujIFfZj5CP0E\n" +
            "RfRhj9wXS3YNLDvJ1LnKtA5syjR1oYuoQ/BkfdwULtTHeuzykf074/z+nqWGOpZU\n" +
            "K/Js+GJlVm+Hdi9YwS2c/QbzRkXj67gc2JNnRFid/omBJGt9bSqM04muf7kgn/FQ\n" +
            "ijcj9ANPvCs9Ltgnn5bYU7RpGJZQWO13u6KwYAkbYwGHyDm3WAH8CWUduxBPj2BB\n" +
            "GHyYhRV8hM0AVlOzGA2ZquzIDnnR+rzbBd6GjEuW41ZMTpKFPE1aUh8uC13biPjT\n" +
            "FpEptBLEsd/69umHSoME9EpQKAE57vV22NYtSqfPiiD4KFbKHn/hQ/VsIkLsi5Lo\n" +
            "9Ae5YVQoXMagHrl5R77s5fFKcjN+enRt6VyfC2mIWtBRU+QqTyd+cGTHgu9oKMsm\n" +
            "x8MAzsvKe+MjmQEUe2OdcRCYMqcf0m5bbpaeIBPdqHmdLAOepCGI43CAyJGPKzEq\n" +
            "+hz+iQZ1d3bG76qUErqDDGD+VEWlwcxf3qc3U5OJRb1SoA1ctLQ1d/Qp6u0MDFPN\n" +
            "O0yYoby4+ai3KCGGs6xPE8N/kqFpa8vyqlQzWeKkLPJ7rdJF/JWBWag4v1noHHdD\n" +
            "CvEA6x5z2UnntXr5FaZvbZV0SeDMIZz8bDeMOiHJ2np8hWoEFIqw+s7gz2IIxTvl\n" +
            "pFYiayZYy0Wjo+HfzetxOUFM5as7NmC1TClVy27+I1DgVZoBVjMkXYjlGmT4u0dc\n" +
            "GvIhkm5FE0o/BiNDRYB3UHAXW02Zzz6qa/xHLAQU4gdQyfIsv4D55NKlv4CoGhDf\n" +
            "+gj7AYa17InmHlbux7lgDoV88mUkf+po8iCX6EeyFmbBxH5p4zYjzECdJP/Sd36S\n" +
            "mj1qtSRA8oiV5q9gtW0wuXH94O9AHJjRdAqkyVhya4mzbVHZGz1MeRlUxZYUIX1k\n" +
            "Cfxf6JSxbz5yXYn5e3DD3cdCX5wUT+ueJHdNlvLPyc4/dzMovY5PGzGH8/yhSwD8\n" +
            "EAxFnSZEfUKdx/0crZ+nQn2AVDW+bGMPYMgCf86M35Jf0rk3AWUUwzQiGJ7Ifb/f\n" +
            "txfhbn5LdMzUnvFaMulf94YWBUMNPw2rFypSACWjYwN3JF03aDipiubDt+5O33pa\n" +
            "YRq5AfaFMNNRltdLfm0hZyyv8Qn7aNuDpVNsct0RrRl/lMAfLuCOv3tamh8Gsuci\n" +
            "hC/qORpytvzwDBwh8GTstiJ8T6IAKTjgPDmVW633YVS0YRAEB4lTGIRMchG2APek\n" +
            "qZ23L3JpHujColFHaQrHBSKh4ktZJwRjaaziwG0MEFQR0D/UBgjFCeIEj1ZaQb4C\n" +
            "UOAx2+A1qpoYmIRywEPLXyF28e+UmstIEMymLZy03AZknIK43KuMPpA4J+gxjsHF\n" +
            "/PjypAzKb07ey6xArZaW3PXIr7EGB16NDaAG1CdL8J2uDkt7vKNWL2Mxj2+JgzId\n" +
            "VsbZkQoOaCO94Uz69Yg3aoLIlWukWWcHYxIH2bBouvOpKOVr27PNKRoZ7KvCke/l\n" +
            "Sqa4BzPa0u23/oWqdrXrcaYdecDAv3Hdz29TSMu5Bzqz/XuCS/6ALCzzOPBzCmlB\n" +
            "JdeLADlS+Vj2BEA6/rtJjxXSMAaWnHZzcepsYxsKoUX3qY61JjxX14YHnQjJ54QR\n" +
            "DiKDhzmg1UahmdO0XaUqGnjYSf8sCGM4pkqik97GwgJWYy84QM/5YIvQBCJxWggd\n" +
            "00IG3rFm0XiwbVmhcVrXazh4q7YflE3eN00tQVznmiuFZS+l+o1Y0L0VulinBSJ3\n" +
            "bmyHn7TLIMCyZ5TN8Kbh6qTl+h/DPgKWkqIrACeTZ9gHOmzuxi6JppfKp17b0SLp\n" +
            "E2YM24TIHNxl5b/pHmivnH1QsbwrBRc9EydHrIlGTC+NZfOCQ8vdlQkNK/gxe4ta\n" +
            "O6bmloP0aryQWAB5C6RxLjA4Gh7zGsc16QovsZ5+BbdiW3XxQ/f/ESAkV77t3Luv\n" +
            "+X1sVLBlsXlFn45PpJ5br0ncnBx2p0yihy2wCBPq1Sa7JkR/0AlhNSf5e0G7Ii0M\n" +
            "4ZyKThRng3uy5Axu8H8F7TUE1gm8JAkkOl948JN4GutSypBbhiLABzbtmQOzE1E7\n" +
            "8gOZYtlxgtmxJcPsC7bUiwaDCGcI6hzb4hGyCEWzPlqK9QqUP3fjoXPN0rJ08qlc\n" +
            "rhFwTkrHuDn3KSvZTsJuyKeyI1MwYFEFyH2zA3rWY69QNvOgOp4J8qLNNByFWg5i\n" +
            "Z5bBe8ewqAh6Rqvco9kFp5IPbHM2ZTCJFKe0CJIuJ5x6zJdfpuAwoxXNJkgqzojS\n" +
            "MzjiU2HWsHUO3cU7T/qhDlKyVzXiz7SOq0j2+S0myeAz727WXPC4Ost6omCUDHqb\n" +
            "M/sRXzWjJ/Egg3UftE76/d8yes8FVT4hAohLxaTGeUh9X3BwYCtsLJt8uyxvSiIR\n" +
            "yE56oMVIcO/SpKHFQ+g9YRJgosYLZ0XOTSw9NM1T3eaAFjf18bLrH8VU5gbE4zul\n" +
            "oDP2gv8MwMPwZzsgWlZ2da5JBwkj3KVvaNAaWSZXiHl7rrpQwt3fD3v3cZHaVD4h\n" +
            "8/FQEyDA97cb/ZD4qU9KpR6rCM3GkZMy6ouAVd7/sQ6jhijBYd8wmc6IW+6uZ9kf\n" +
            "uq7eWp8jvKKeSoXLcp0cHwLGw5NX47t0Y/o3O0ZGJLnyjTOlqh1n8eWZ1LFOar1y\n" +
            "iEwsdw6HyemvrviZB1xSeAwentJFkq2V/GWDmlOnePWLT+uROA8FC5Qe59yLHem4\n" +
            "R8U7fMUvNEhVY3c4ROptveN6/58rd1X0xqdxjQrMxH3+Powj0ZORPe68vLGT/uKc\n" +
            "rwsgIGqzky+XHwT9HDOWEaKKctSqArRYqR5NdyoRb9zv6taByUjLkjgt3pXYsWjL\n" +
            "5LfKusuyrtGcMFaZxiIBYtr7Sm1zmXUxikcT3Dgzt8McjwDPyonh9EtkHSyk8GFj\n" +
            "cSQoNTOYPbteQpMeKbPYwkW3dCwxBABSVO7wTHXT4AxyUFMvFTIeG/mGG8KOsNsY\n" +
            "iH1DhqJecXaI8fu0mvlTELyZ+KeBBd6/nrCWVvnNYiRjJX/oKvos+wqQ/vxgYQX0\n" +
            "tnJnxvttNmHooO3GyQD+VOOZObpT2AhyIbVY3mxow5MnfYji8/jNwcUaGeqS5WQp\n" +
            "+y5NaQ7Dj/xzp4rQDfncHt3k0JJW9do714CsKvMM9uZfCuwwBXXA2ygB68oesbWi\n" +
            "QUpq65ClVmjwdzQunQb5gm1Bkwunx5wAKp1ipH2wl5XbOaG2cP0iw01pJrG/RveQ\n" +
            "TlWKIDbHd+82IsdvtKMOr9Vv/KEnT4N5Cc41li76PbvWo1O9scTJu17xCfw+D7Qd\n" +
            "Rghvih8CcZH2icbWncBdb79tIQUVA0vH7wSoE/HRu49OLewnZcTPy49DvMcabE+b\n" +
            "YkZQD8fzKsJZ1EtQz4bGCRppezLdepIiVhO0uYRQ2JAW34deFEd4dA6EYAjg3QRm\n" +
            "S5CZia8XIKguANXsX7Hl3Yqce9uERhs7XW9w7I7NT6WNYnLQXARwaDWMT20Sy029\n" +
            "ny4awNVQmqWSxdE3tL3BsN3KRuKyxSEdAqDSBOpOOXDn+7ola7sQje5v7beWjglD\n" +
            "4EHlMScraxoaHHPnqhB3AxbEslqArMKvF0rHJfYI03xMeYJDTBhOhbDax66NI64O\n" +
            "vZPiMcb6KcZqFmNBw0taYxWO90jBAL2mvmMuYrlFP4ymr3kEksj+lgB4Aawy1VBj\n" +
            "y1QVDimOJv27Fm1hDKeYavmrKgx4o7QV8mLu/xmdzS9rUKnj8ByX8thTW8/e9R9g\n" +
            "VlLsaegFmjV7v9mgTRl9hw+OsAKK+HSonuU/Uor/ZJzYIhT8iWYgA0/a7cW94VhN\n" +
            "CeFwA/1VH/19lcanYM58D+mnaJkSUnQzM1VupAAn8/nxthCMN7QNLjN/zvMoRFBs\n" +
            "e0V7qq1OZoOYnKvoR01jp7MTIi5UuwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgsP\n" +
            "Fhsg");

    private static byte[] draft_dilithium_end_entity = Base64.decode(
            "MIIYFjCCCyGgAwIBAgIUTVOt1yqx2TcoR2H+lxsPUk2gCzQwDQYLKwYBBAECggsH\n" +
            "BgUwgY8xCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2Yg\n" +
            "UHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1\n" +
            "bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEcMBoGA1UEAwwTRGlsaXRoaXVtIFJvb3Qg\n" +
            "LSBHMTAeFw0yMzA1MjUxNjUxMzhaFw0yNjA1MjExNjUxMzhaMC8xCzAJBgNVBAYT\n" +
            "AlhYMQ8wDQYDVQQEDAZZYW1hZGExDzANBgNVBCoMBkhhbmFrbzCCB7QwDQYLKwYB\n" +
            "BAECggsHBgUDggehAA/E/9EKaexVsYAlE0FBfYaEOa/5RbzDfHLkzkymPIWn2uCy\n" +
            "TdSVMPHt3n9DjdYEAXZD+sAyKiRRXKmqtgN4Cl7o96+9V+zqDXNNuD+Ol3uJ1fUf\n" +
            "UxDQDoSHmEPSJFUl5sm9veB6g+CEymf6fHRVJmqMe5m3fo5SBj/v1WT8o6blqQhd\n" +
            "pOn5QdrGLkri2OHEBwyrfOrhRJuXLK7867q0rzCHGecHXb7M27GtY1JdsS3f6LR6\n" +
            "Xilrw77tEJTeXOw7wkEWTqVuWOQk0MteZpb4Bnyvpt6q1z/M8w8M/Xng5O9h6vEv\n" +
            "k2drOrJbtYWaAaemyW7oZq0OPDQSKJuV0BzhEc97cZEW1JG7CFyO8WutBnMVaD59\n" +
            "DbVu6I3UdSIeqmtGRpG5DiNn5OH8yw/6KcTB8C24GunblXbz/EBqhvaM2DGX5/4t\n" +
            "V/QvnWK3LwWraYD/tby44cRhhZ95Qtvo5nX+yQMDT2gNQX3Z1X3G6ttjey9nbFhf\n" +
            "vtAKXvD9n4bbNtKwXFDxIjNpf5dswLaG23eemRp06hX6TNefPIRbjcfpiaxwNs6r\n" +
            "XxNYCphrLNS8ul48D+GLaYs2lto42xhOzjdPlvsSQz+kItEWZ4tqoolQXcW4BNGK\n" +
            "syDtTxJQxLaUCNVoSoQ8PRcFXVGc18sk125/qp7TOKVFZ0ygGJ3RO34wjSIbqfaP\n" +
            "KV7o6eWPEFbYy545M8uUG+nDAlS/aj+TYi5nEmvnDYfzzQGfUQuEswu9IdYZSXhg\n" +
            "W4IPZU7TGayxNFNE1FTK0BnOyw256LD7yZvu30bAwOUphxo+8bWCgrYXe6hHLkx8\n" +
            "ceXSpCmKr8y2Pibzw5NrtqpstFj/SN1HMo1p3OZrALdTPBKqHmpWMXodNWUJ0H82\n" +
            "yLKxvZyTOKXpPzK1fKTQTriwnxSRiwXq83E0DJqGaukbBEEqAEa9DYkj37f3E1j+\n" +
            "pqtdEMmd+zmwY+zcPOPbzZHnHjICnNHlGQboNSXuGD9AOes1IUqDpnFh3MJYAjeP\n" +
            "nUAxLVjrUqTCaCZZHMutZeNT1IxuBNrkxOL+Fv/uw6XplXGUUvVl2frp6z4t+4uA\n" +
            "OyIt+aNtT+WRdMB8/dJT56TjkOvJXXZxS5KBE8ru+kIqTFTBG5+3qSPYVe35qXRS\n" +
            "XMpNZGZ2GJrcxdKpsAegAH+XCN0u+fIR6QrhXphVrE77/tISp+S3dQLrXpq9eDqa\n" +
            "xACaTtj0rxvIgzYp86lqtvNqcXjB9t3AsZxZzVyQT+Ih55Ak68YmPinnLHQxuSMC\n" +
            "XG88e1EQqPh1Tldt8n4xpY3z4aBJ9aH/4UPLBvYsm9N9eycf7uXZjOXYhqombmKn\n" +
            "KeR2c4pc3mqEAjsI6QvbxMtS8pnyNS6gIhtT2DQLVTMu3V4URxDFR8LU9Ky7NdRd\n" +
            "Z2KaUqwAaw9V4FmB4ycaPWyo9xaYH4hQldgk8/Zaf+Segz4llDEK6qcqeQaavvnZ\n" +
            "2a4r3DO87Yw8Vy9OCfmUXCtSOXCaZXqHnwXEMTIcThqEKdqkFxLEaPE0M0kTnXAd\n" +
            "uWb6JFELV3h0Q8QcxK9QLiWfNTjy/lVZ/r4eqAnrtBAIFQYYJBfA7rryu5MXIPmp\n" +
            "w2F1Ei3kP/2BnZ5XD+i5nRNOo6cOEcTUi8oPvidfj2LqQAOIlID8rKhtx1FmeJJ+\n" +
            "IH/wOkifcduGVlLDQKagJI7AXzkgkxFyQxnp5g34I0IRBXtsrZdmqOlv+JA08uPP\n" +
            "I+vaPzvRL66vG7djHCbiLjdumwTrqbfiXeIoZjF2nP4O+X3+fjSckPOT8Dr+OMSx\n" +
            "E2nEsb1lYiQcguoF52gn0Ltcf585pa6Lezey7S6Qc+3j7XdhLH2OczWgJ4zc5SBP\n" +
            "9t1EzOpVFiCMQ5V4GWS6OEizdkbaKDTAEY+9TyiXXwxU5nrMWxzGhwQ7XNaT4qpt\n" +
            "Z5TFEJBF94xciP4+4EkwbBFdPo02n5AD4K8PAbXj5MuySnPSYkBfMq6DwB/BlFfc\n" +
            "RKVz4Yt6KR//jJjiM93G80WhlL+DAYx3w2VtWrNXhn/W9VP0KK5Jfaecbl+tHWfQ\n" +
            "87HdXqx/Z8hmPEYDXidLNGOLLj7GIt2I2ZUtC7+49q6qQEL/8y78J2q1Ef1F/jUP\n" +
            "xsBMzMgGTolEyz1i6X7fO+yHY5CkJAnNVkZK2wvpSGFqIuyO3BjCJfNMlpUCmhMS\n" +
            "gmv6KQ9sEdF8tbYsk9ICVzqXV3O+03y4swUaIe6o0MIiL5X45SZv9HArhjs9Laku\n" +
            "BjgQ3BSWtyfFRqdsLZn+MWBX4H8YkhTxfJzofSJPqNuPUwdcdIxc7LOpkOGPkAfy\n" +
            "yI2uqo6YGcgMTGMBGk5iJ3SBelrz4k9YlVi3gy7gsW4FbIvXD97h3Gqd4tkM5S8L\n" +
            "A9FGl2nT/0RNag91vJ+89Zls55sm3d3Hi3ZxuNr9KgNiIuNuZaFSXdrHDo/ZinFV\n" +
            "BSn6YakeJCkUkqA4kqjcoxrIF6bQWu2LcM/7PeCBPhtVH6hMn5hAF+OymGCw62+m\n" +
            "ha72rqBrkUhdAMjrv3eubo0AdlUD9v1z45fs68kPEsZisHBbmAZWBcGGGieupmv2\n" +
            "VYkELI9mBUYJdnDhfFVSqdmqQ68xveMvb3VxIyo/eYTLuofVJp3DJ4IbhB6ro4IC\n" +
            "WDCCAlQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFANK\n" +
            "iIG5mZXV+IMcuSPREB/od032MB8GA1UdIwQYMBaAFC7xQYjChOZZFBDtuuo5uPqz\n" +
            "Lec+MIIB8gYKYIZIAYb6a1AGAQSCAeIwggHeAhQs36ItK8bqD/FlXfx+e3IJLemk\n" +
            "uKAKBggqhkjOPQQDBKGBjjCBizELMAkGA1UEBhMCWFgxNTAzBgNVBAoMLFJveWFs\n" +
            "IEluc3RpdHV0ZSBvZiBQdWJsaWMgS2V5IEluZnJhc3RydWN0dXJlMSswKQYDVQQL\n" +
            "DCJQb3N0LUhlZmZhbHVtcCBSZXNlYXJjaCBEZXBhcnRtZW50MRgwFgYDVQQDDA9F\n" +
            "Q0RTQSBSb290IC0gRzEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARCJUj4j7eC\n" +
            "/7Xso3REUscqHlWPvW9zvl5I6TIyzEXFsWxM0QxMuNW4oXE56UiCyJklcpk0JfQU\n" +
            "Gat+kKQqSUJypEAwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud\n" +
            "IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++A4GLADCBhwJBJyKG5vGDiDA8iddl\n" +
            "vY44yI0wK5D8ayYCx2aM8fuh5XjZA+14rI50v21a41uObnW1KXRHoQeW4SZTUBuz\n" +
            "yo/w7B8CQgCqwK1+cbH+YecTjnfWQHgSk1dqgPCDi0ezo+QVOHhtzfXbIs1y1z1k\n" +
            "SU/BF4spioFCeKIkkJaLs+8Evy5gdx+u6DANBgsrBgEEAQKCCwcGBQOCDN4Azno4\n" +
            "4bYnpwVdpeaWAaNjchhKdPxrpn4JresJGnrJnsLUrUFtUdzipe4ZhLsLRJKRC41b\n" +
            "Rg0zwf4eIxRBaERbWnWDzBl5x6LlnNNtkNsBzSVyc2OkyC6Js/AFKueK7348ZSAk\n" +
            "0CeWiWRCAvg8o3o1YX+Nk0J3BYcLWyf4ZH6fyExqjnikx2NgXZhPe48l8nqjAkct\n" +
            "f9tdKBkMOqP3GAKvQWhDtMNDMeUoUBXXJfJWdIfclgoGmqLe74N1wgIIDCMkMmZ1\n" +
            "+G8W2E9Xix7nvwzvjFZSqcnjP17yPizCAOeRAYP3FyaZb6lMZ1Pusc9Uun9c5E8P\n" +
            "8vJG7CXPYH8lVrhNpMG8y3jDAW30xphkeE8yxnYKa2k4nutAijt1XPb0p9ihTcM+\n" +
            "K56fSCnFFlgXZYsyEI4oCqJQFgUf+BKe+XVSR5K5hpjkH6WT+LoAgWhm5ocyUasz\n" +
            "2x2vvMeo282bdFhdnHAyaDCYBG/XjEggFpzXQ1G7Dv7ECiVjdbAnLREViMSu2sDv\n" +
            "dFgE+Hzmv6IpFdh1OynxkUJ2k22do/YDvo3x9008M5HjqMYGp1I4i1wfx6X9zCNZ\n" +
            "k+mzPX1QQpMoZFC9RK52XpgPECe4ssDA2vVIn3t9ZufE6M8Pzc7SgMk+gANs9yKy\n" +
            "1GZyTG6CxGjVpuupXtlWFyT40U9G/GZF/AYSG/qguFu4kG5QxtafpfD+g267pX4Z\n" +
            "eM2p7x0J+CCUlVr81vYs9jrhBSPnc2CVxDyj+9Jokn16ek7Ulmhu34mS5TWA9Qn2\n" +
            "h3eDpTDAILyPEyKEa5mWc8WnHKtfYBl4L13QUT9VScOHvGszmrN1evuqsXdblxgL\n" +
            "DH3u3cDWoF90M9Y7Avu4mS38q0bnbN8emUZRTbBlH2vHcWrOTuAWmhVpNDXlmPuM\n" +
            "KV/9l9cN2B2xn+vUXccGgzltZk2hjXTigi+/ZUXAeGAq8n74LkjBkwUh4RQCwH2e\n" +
            "p/5VyoAGAHwtFLOLVO+OJyE+SeRtEdV4hAeqSiXl7pwqJtO3/DcQX2bxEuolZirK\n" +
            "l/THY+2hm6FE8SyZwMfyj1yjzsgJ9fK/bm7pe1g7UmDNEfepnzntPUcrRYvzD1U4\n" +
            "BJ1UliWDehPf3qXolcFT0lrfxeutiFz9xkytlx/MFnDReqRKBNhZ36sq4p96o8V7\n" +
            "b9+X3SZrI3fF07R5C0SgBCcZK4W/p06ZUcAS9CX+g8g7H+4mupZxe1MXuetgBPZF\n" +
            "rYe6xOI6OoELchWdpuIrXq9UWLJUEUjS+Cr3HKlOJWp2+xJqV7qzMKN9ky6VgfnL\n" +
            "TC7smRxGPAViMsTHaJ8FnuzZeriYr6+2n2TmpL8Ubj5iYnSW7E5zFmCO1JZOPxWF\n" +
            "jwfZz6RmZUBzJCf7MBxoPdPGihpWWRheyQ9gPC3TjOBV8XRPKh+OsWkeYd2cvPSy\n" +
            "xNzpPgAhnpuU36kRUarmOEJANc+p7HoTENfwzQrydDmp4NXmJNV6yWNewD8knczL\n" +
            "Dp6uhlWMmm5K1o8LRWhf/BMvQkVhI92FbM7RJFwI7YoxwX+hdKX44z1cIPP+CNKJ\n" +
            "3YQ4GsAbWFkuDmGjKroTmFfMaDIUioci7k49YigCWgcWfCJq1YpMnUy6U31t0lPS\n" +
            "/AOAmkln/D3osf1OwQLHArH4c7rdRwrOwmzM6FaG2iyQPoF4xVWNSLYFP6tUA+JS\n" +
            "C2OiSFvrN1EzBfqWRXTwMjGlBXf3WQg2nEm2n/JU7i6QVXw5kQiQICN+koCHqoWc\n" +
            "0dAxxNoSq52byCXbn94aR2Hc9ycyxNLOB1om4uemIuE8JeoD6V+HQeaa113LsK06\n" +
            "U3ypdmZ8LMKuPMjQYG8iBC1NB+q9j2b1NRMi2DNZmDrpG5IGEh6KLISWN6cB4NOl\n" +
            "EA2D7o6SZ69emLjpwaO/IX2pS6vzZnraLvCqaWr5CJo8Exp37kAqHTU4Y0EO5h8V\n" +
            "Y3h8bpebYRgGIl6iypPlyDz4zzVj51zUudI+TH8z4t5eazXSkMcHiev8qpb5kVYH\n" +
            "JTtut0ndqY2u9Y5GcMc7uFHnKr2jen1DAVEFol86xikRL27nJtCpZ88IXTfrKloJ\n" +
            "k8vN8guI+PU1Wd7lEOnKwXScHhbmYSrz9FQqizACRtuYiqCUv5GrPX7E31bY+B0p\n" +
            "lhoVO4ZRMmFAOWNkgi9x6kMeJFhlS25t8vKspE+DJOuW+Enz7uneig5K3yiI00NW\n" +
            "GveQTkoVnO4eoSjwj5+JuVNlBlZdKbfX6T0ycS4QqnH+HOEF/SJvot4Coae0Fi0x\n" +
            "z8/11jAGU//CeCktsysFcUMd640JIrxb8EnB8AdG8CPp9Vpv13emPnORusIXPZKf\n" +
            "33B8n8MGl09c5fh9KhGtdYV9/bnNFTIxTlRi5tNBLdOQb1t3MVuv4csBI1SR2qLr\n" +
            "cWA+PUddLG9d+hoRdfy4uGb5uLkRM8ckPqtHhpOsrxdVlyDKMQt0HxniG7tZXmdo\n" +
            "LhdvDOZdDqRjh8Ms94WXf0TDLrlRfefEoZ4T96aZW4qeFukBvR2rEfItRd3os2Z7\n" +
            "JD7yS6RPUfBAqzGWSTsDcmjxWXZQZYO6ygd1rMkr7EbabS7FJXqb/VxVEMrMFKGx\n" +
            "BFy4ujJf+cJtIDw6y59rmnaVOyAD9b4a++Zz06PnymlFEi/jlLy92xYWxt+hOaJC\n" +
            "AeiUoKHLbH5KiSTWlwdbjshGytlZaAjLyuC0BxfGrQurl8VJ3OkfeDX20HgntkTu\n" +
            "wJhvZpbhzth9y0cpo1z/JLyMfZV6yGccEATgRP2gciEgssBFhB6FT8tWmf5IgjkS\n" +
            "pYUaCqnSn2gu3MmYZF8+h++tJGpH0hrq/MhXrqwJnx3e0c1nTC6IWbrR12s8RWig\n" +
            "RjEBlFt5cfgswMeWnb7UdM/vXkefNBjiWEiDGU5R+Od9N+siYh+ZyFVkrXeD1nab\n" +
            "YOTtolImcu1fP/jG2v62XVC4KoBGG53Ym2fIfkDwIjQFO6exl1/d6FoVsX3D90Hd\n" +
            "7+njwh8+2eJ9AU7XXwlNi8eOklxMxPeMcCFANAx+kRy9jqKvc6p1LziOXDT3yaqT\n" +
            "OPHnGffVXL966PtdGK4sP5Hf2BwMpIPv6fAjprndFKDcqUOYFjGEf9wyCnrWy/+U\n" +
            "TIY1PHwtgLPqVA3Rm7lThze+OAglbFG34ErkZEprLuNxtfei3hzWE5f13O47di35\n" +
            "OBnxlv/LtD190fZC1rKJjU5RT9q+foWeGtSca8McXVQ39fO1QdaGm5EGpRN0DyaK\n" +
            "JbVQkNDnXkHRvgZ78npwo8pmZ2Tcw8ocnHW4KCj6CT0lf4Q7THnS4BYfLtU622Nf\n" +
            "LcThYTR46ItceHlsB2Kksyx0oamRCj1kvUURCj9Pl1A9Z30xeFcJnHLaRA6BJutQ\n" +
            "J17N/gF4DNzAMQK8mLNEESocdeFe6l7cWWhpjZUY4QydooN2Cv1l0REehFNiDKNz\n" +
            "UUK0iJ/HbxfkI6IHtR31pq70mttHeJA4UIIdU9HbytqSehKXxSrSGeXMft0tqTG5\n" +
            "pu09xlcKbP800gVp680ZMye2Jsg6ebyxEz7AKmbTDoR+30o2n5IwR/wFyrSLYgp0\n" +
            "cAkBozlDWndEVdACXDCKcS/WWHhHMtU7CDUlM52UWQ9Ofsj9smfv0Q24bIEadsLX\n" +
            "WGiJdYWGU4iSyn6iwPqFpWFIIASuKCom6lRhNHpumcqWaNks8oGBfb2XNbFVerK6\n" +
            "WxuJhDU2d9MTtfbubfAS/ll7VFChbSML3WMfZuGEHILCwtc+MhuMsQkllii7APwv\n" +
            "kicHmTTTS3gg+3yLIZT0VkBcAQfAPW9WaHz28TIFhHPt8omBLP+oB+eGcYPZL4+1\n" +
            "biS3ulxNNQeV/xagXVBnQsW6NBermbpR04YHrRatkv6hddsHY7cAd+c28hMr+RLw\n" +
            "/aeOG2LyZw0nOuvDHYURFnarBaZJpehAZ2Im3IQjY4riBacR/nlLJy7rznZltAoP\n" +
            "A+2AdIXEWX7JfnpbtS1joXLB8kbCAsBVsQ46D4S5egFMmRDNlwPf1hrnbLR69lCR\n" +
            "ugT7T0IL1tbC67ieAh5QknesVLq17hPIPECQeYTOAJksr7eT9G6M8SAKevQVOipd\n" +
            "ANLVQ9/jLJUQUp5lUJOK+jduoWFUHGMV6lguHzUHT3KPXIFfQrpNOJoI1t4tEewC\n" +
            "7LlbOrHF2vFU3YPoltp/gpWDEfDqRUVBEgU9gMdVDkYVn+yZwxUpRhaxihKW61yx\n" +
            "P4AHo26WMuoNKJ0ALgxJ4zVYFa+O+kzdNP6Lul7ihUdAVjFXUVErhJ7d7tM+GL69\n" +
            "gvN0QJgd6aHYmSZ/7QjSfsVti9WcRzCh4LZHUbmW05In8LHxvNZ1/nNyVz0iUL4P\n" +
            "0C7Ox1btY/JsFYAcXRggSVR+qcDFO2J9J1CCz/Akk5W2vCktmaPtDx8nTX+s4QAA\n" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAICxAVGiE=");

    private static byte[] draft_p521_root = Base64.decode(
            "MIIDBTCCAmagAwIBAgIUTggpfah2kbN+5mHbCwF8takhZ/wwCgYIKoZIzj0EAwQw\n" +
            "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
            "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
            "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
            "DTIzMDUyNTE2NTEzOFoXDTMzMDUxMjE2NTEzOFowgYsxCzAJBgNVBAYTAlhYMTUw\n" +
            "MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj\n" +
            "dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu\n" +
            "dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj\n" +
            "A4GGAAQB0P1yV6hMdH9WJXXAc4Xb6/L1K+pYCD24L90VMdiq48yHX/Av9/otomDY\n" +
            "62LW0vXWSSeOMhc2oGKMu7MDCLbmGNsA9irSBMZGA1m8gYq4lhvw8PwOxaropCgX\n" +
            "POVvAN6bFXweXILGT1Yvyt78Skwo9tNCzz72FvyC0ztyhckh8r82/dijYzBhMA8G\n" +
            "A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSOwhQJYHbq\n" +
            "kDjpOa4bbVLEF32fvjAfBgNVHSMEGDAWgBSOwhQJYHbqkDjpOa4bbVLEF32fvjAK\n" +
            "BggqhkjOPQQDBAOBjAAwgYgCQgGFSpzkWwSGg7geN7A29/Hm+AQecvaPsEy6yBle\n" +
            "QxgNsjlHJB+evy+x+MlRWrYlGaJOrETDoBkewWOgb7nMxaNtlAJCARhDCCPbUJMK\n" +
            "f9KIpEm5KTjGR+VBpavAC+k5w/mMzAYEaunRmRP7KRii3n+oMikNXShGrSv6C0oH\n" +
            "/Ze44Gp3VBDb\n");

    private static byte[] draft_ecdsa_signing_end_entity = Base64.decode(
        "MIICYTCCAcOgAwIBAgIULN+iLSvG6g/xZV38fntyCS3ppLgwCgYIKoZIzj0EAwQw\n" +
        "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
        "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
        "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
        "DTIzMDUyNTE2NTEzOFoXDTI2MDUyMTE2NTEzOFowLzELMAkGA1UEBhMCWFgxDzAN\n" +
        "BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMFkwEwYHKoZIzj0CAQYIKoZI\n" +
        "zj0DAQcDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV\n" +
        "uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcqNgMF4wDAYDVR0TAQH/BAIwADAOBgNV\n" +
        "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xEbCEJ17vUMB8GA1Ud\n" +
        "IwQYMBaAFI7CFAlgduqQOOk5rhttUsQXfZ++MAoGCCqGSM49BAMEA4GLADCBhwJB\n" +
        "JyKG5vGDiDA8iddlvY44yI0wK5D8ayYCx2aM8fuh5XjZA+14rI50v21a41uObnW1\n" +
        "KXRHoQeW4SZTUBuzyo/w7B8CQgCqwK1+cbH+YecTjnfWQHgSk1dqgPCDi0ezo+QV\n" +
        "OHhtzfXbIs1y1z1kSU/BF4spioFCeKIkkJaLs+8Evy5gdx+u6A==");

    private static byte[] draft_ecdsa_dual_use_end_entity = Base64.decode(
            "MIIDyzCCAyygAwIBAgIUHfGFg4ZrE6+0wdcuN8sDeelJ0vswCgYIKoZIzj0EAwQw\n" +
            "gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi\n" +
            "bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg\n" +
            "UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X\n" +
            "DTIzMDUyNTE2NTEzOFoXDTI2MDUyMTE2NTEzOFowLzELMAkGA1UEBhMCWFgxDzAN\n" +
            "BgNVBAQMBllhbWFkYTEPMA0GA1UEKgwGSGFuYWtvMHYwEAYHKoZIzj0CAQYFK4EE\n" +
            "ACIDYgAEWwkBuIUjKW65GdUP+hqcs3S8TUCVhigr/soRsdla27VHNK9XC/grcijP\n" +
            "ImvPTCXdvP47GjrTlDDv92Ph1o0uFR2Rcgt3lbWNprNGOWE6j7m1qNpIxnRxF/mR\n" +
            "noQk837Io4IBqjCCAaYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAwgwHQYD\n" +
            "VR0OBBYEFArjoP6d1CV2mLXrcuvKDOe/PfXxMB8GA1UdIwQYMBaAFI7CFAlgduqQ\n" +
            "OOk5rhttUsQXfZ++MIIBRAYKYIZIAYb6a1AGAQSCATQwggEwAhQs36ItK8bqD/Fl\n" +
            "Xfx+e3IJLemkuDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEIlSPiPt4L/teyj\n" +
            "dERSxyoeVY+9b3O+XkjpMjLMRcWxbEzRDEy41bihcTnpSILImSVymTQl9BQZq36Q\n" +
            "pCpJQnKkLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFFtwp5gX95/2N9L349xE\n" +
            "bCEJ17vUA4GLADCBhwJBJyKG5vGDiDA8iddlvY44yI0wK5D8ayYCx2aM8fuh5XjZ\n" +
            "A+14rI50v21a41uObnW1KXRHoQeW4SZTUBuzyo/w7B8CQgCqwK1+cbH+YecTjnfW\n" +
            "QHgSk1dqgPCDi0ezo+QVOHhtzfXbIs1y1z1kSU/BF4spioFCeKIkkJaLs+8Evy5g\n" +
            "dx+u6DAKBggqhkjOPQQDBAOBjAAwgYgCQgDrJbcn+dLO5HqHlhaW6G1FuNWLz1h3\n" +
            "OXYNb92b7aSsa478EsE7hE40her99+33/ws5EJp4+mtWBb6+09Be8ARC0AJCAJ9C\n" +
            "q55HKUbwR5+sYUtXk1021jyjhTeRVzCXcq1AiVYriSSC9ZbBGjdzPmhtmuHWRXKY\n" +
            "5vbNh5DO/8/9ucvLiIrS\n");

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testDeltaExtract()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(baseCertData);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BCPQC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = new X509CertificateHolder(extracted);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDeltaRsaEC()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(rsa_ec_cert);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));
    }

    public void testDeltaCertRequest()
        throws Exception
    {
        PKCS10CertificationRequest pkcs10CertReq = new PKCS10CertificationRequest(deltaCertReq);

        assertTrue(pkcs10CertReq.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10CertReq.getSubjectPublicKeyInfo())));

        Attribute[] attributes = pkcs10CertReq.getAttributes(new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2"));

        DeltaCertificateRequestAttribute deltaReq = new DeltaCertificateRequestAttribute(attributes[0]);
        
        assertTrue(DeltaCertAttributeUtils.isDeltaRequestSignatureValid(pkcs10CertReq, new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaReq.getSubjectPKInfo())));

        KeyPairGenerator kpgB = KeyPairGenerator.getInstance("EC", "BC");

        kpgB.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair kpB = kpgB.generateKeyPair();

        Date notBefore = new Date(System.currentTimeMillis() - 5000);
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60);
        X509v3CertificateBuilder bldr = new X509v3CertificateBuilder(
            new X500Name("CN=Chameleon CA 1"),
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            pkcs10CertReq.getSubject(),
            pkcs10CertReq.getSubjectPublicKeyInfo());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kpB.getPrivate());

        X509v3CertificateBuilder deltaBldr = new X509v3CertificateBuilder(
                    new X500Name("CN=Chameleon CA 2"),
                    BigInteger.valueOf(System.currentTimeMillis()),
                    notBefore,
                    notAfter,
                    deltaReq.getSubject(),
                    deltaReq.getSubjectPKInfo());
        if (deltaReq.getExtensions() != null)
        {
            Extensions extensions = deltaReq.getExtensions();
            for (Enumeration e = extensions.oids(); e.hasMoreElements();)
            {
                deltaBldr.addExtension(extensions.getExtension((ASN1ObjectIdentifier)e.nextElement()));
            }
        }

        X509CertificateHolder deltaCert = deltaBldr.build(signer);

        Extension deltaExt = DeltaCertificateTool.makeDeltaCertificateExtension(
            false,
            DeltaCertificateTool.signature | DeltaCertificateTool.issuer | DeltaCertificateTool.subject,
            deltaCert);
        bldr.addExtension(deltaExt);
        
        X509CertificateHolder chameleonCert = bldr.build(signer);

        assertTrue(chameleonCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));

        X509CertificateHolder exDeltaCert = DeltaCertificateTool.extractDeltaCertificate(chameleonCert);
     
        assertTrue(exDeltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kpB.getPublic())));
    }

    public void testDraftDilithiumRoot()
        throws Exception
    {
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_dilithium_root);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(baseCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(deltaCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder extCert = new X509CertificateHolder(draft_p521_root);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftDilithiumEndEntity()
        throws Exception
    {
        X509CertificateHolder rootCert = new X509CertificateHolder(draft_dilithium_root);
        X509CertificateHolder ecRootCert = new X509CertificateHolder(draft_p521_root);
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_dilithium_end_entity);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(rootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));
        
        X509CertificateHolder extCert = new X509CertificateHolder(draft_ecdsa_signing_end_entity);

        assertTrue(extCert.equals(deltaCert));
    }

    public void testDraftDualUseEcDsaEndEntity()
        throws Exception
    {
        X509CertificateHolder ecRootCert = new X509CertificateHolder(draft_p521_root);
        X509CertificateHolder baseCert = new X509CertificateHolder(draft_ecdsa_dual_use_end_entity);

        assertTrue(baseCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));

        X509CertificateHolder deltaCert = DeltaCertificateTool.extractDeltaCertificate(baseCert);

        X509CertificateHolder extCert = new X509CertificateHolder(draft_ecdsa_signing_end_entity);

        assertTrue(extCert.equals(deltaCert));
        
        assertTrue(deltaCert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(ecRootCert.getSubjectPublicKeyInfo())));
    }
}