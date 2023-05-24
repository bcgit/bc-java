package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class PKESKv6withSEIPDv2Test extends SimpleTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 1EAB 969C 5634 61E4 799F  5677 A88A 4F70 1C0C FC53\n" +
            "Comment: Alice <alice@example.com>\n" +
            "\n" +
            "lQcYBGRuNqYBEACu+iyJAnz5ncLkoQ79MCD8LxrQzXvXDJlEcd/LyuA3iZHySTDL\n" +
            "YDq33fC1fPZxJtgUbz/8TB2mWmxcu6xnqD1oLviUh2g+/njSdY2cFlXnYk+V6jcQ\n" +
            "5whpEIKXIan2s0lsx178wIgiETtr9PwyoJYi//6jgha944I9GxUBLpob8e7BkGao\n" +
            "EDfO18oVohexo1WWyxtwTTkcx/VRD67Z1hkE1YqKalGSRbZaLX5o4P7aeIc2xDbd\n" +
            "UKjOnegPM0p5mpqd3lxmFjJ2auoC5s6RfeQpg+mk0qwSdbGVlHjkN8iHzF+36hbG\n" +
            "RGX6WSgm7AElfOSubF2Hj2nCViChOnUYGewnDFM4Q0QJcLBj7GcEbMY2x2NgDcuM\n" +
            "S1VtGFGhF301s/pAfRUuCbByyXVd5E+fXQf0SYPPfQT0revn9gU0/xOzF7S9Lael\n" +
            "P/VTaaPiVhKg9x9NZekDm20qOP6GlzFlFqf4iQj0UZ+nQ/4hAXkc2cp6YHt+7F3r\n" +
            "LCjGzpKHu16TgvTdr5fS+GMx5/T8a/gxlzeMbVOGEca2okLu7I7iov5eKBj8N7C6\n" +
            "4sB5brQMxuD9Jvr6BbKE/pmD1Bc9eFTAihJ/of0YTz9X/d+uDp3PhfAszug7D+0P\n" +
            "F3JLeMWbY6gRTeoSABD9u18G8unGeSzQOkAptb1l8bmqFLMngd1N/e9rOQARAQAB\n" +
            "AA/+LHFyumIdaDF//R5Ddl+xIRy9zOdEWzzh+RaLZ3HiPXj9zvJ0KFQK1gTTTOWu\n" +
            "mtLo81fGgsi6hzRUbcFlava6kinMDb3O5qEwAxTEoS6zJxA7crKIxgxIgJcm9Egi\n" +
            "qXykW7LQF5a3fR+vXh5dqGZNfBpVjSZPrG+K9wZX8XLqxcpPgG6zBGEKK8l3lMMV\n" +
            "DZOU+7YfBAk5RmwrjSlUmhPdSvMKO1oB2gtG4+TGRNFRKiCPB4QTA2enWMOW27WF\n" +
            "ZxmzyAFgqrVcn+NMCOyi7yVwvHK695hjCFVIg9uwURcyIfvxG/+jRTy+QjY/EpPD\n" +
            "PshYNU1k/Dea/zdtFkaI01RSPLVJ/I6CCkdMHNCmoPfVXJmO9NZtpQ4pBw7Pev7e\n" +
            "j8dPuJG/aU7mnskxMtb6zpuKrVCnfJX87CEUDADFc+OA3S8sd5QGvybuiOOhdwTa\n" +
            "inx1LtvBN0FL+hAxmz7j5K6dWSZxL6zuk3+5ech0NYlcS3AxASyVADIM2kxySlFp\n" +
            "ydsNU0EcsKyP8UWUmar7ITD8jp/YiJ0GVpRRpSA8zZ0DPzVQpK6SnQgNhUhPhVRC\n" +
            "dgs6Hrk3YQ2O4KFLzc409htgCCkIfpXp2ZdcLYNkjcRDZsaI4Z0gbGKsXKjupeLA\n" +
            "ig5zm7uq29kJD4N9NZeXdKdy4UpoYYfKQFqRYGuFgkh51VkIANIPZRzlmPUOQPTs\n" +
            "Nrp33ADL6C/NBeMcyCJ/7mg3Z8jko+JP6EQhM3kGjKgd4hEiQahyRkSnnMMXZovh\n" +
            "8dDWqvOyN/fZw4vRwcvmqZd9Yll3/+2XtePecm8pvs4vJd7NGo8mepf2AEE7KuSw\n" +
            "FJwAnei6ZQ12bdNH9U0aDGDkW95tcBZC21uKwIdreaojy/1nHZvIJXSTAKHOpNLQ\n" +
            "EeX7gvUYqt2E7kZDnykBfVIGuw5U/lAUkMMixesmF9F/dSiHqJT6HqqTxWl2d9Yq\n" +
            "y07k8CD9yFce7tJTbeGo21DNIBpWF5PWkr7gRxZyaRFCBdY818lSzSiYGRTJhimt\n" +
            "frsxZ8sIANU+mSnGHOxbHUPEuJ69I4UdSnJlFKLAsxyJDNy1kcnAEz80M29gWJHL\n" +
            "TnrDBDgpWj2Vl6dg2Rn6yGRNVFQ2j+AxiblaDyNtPMB9itVCLVB8h0/G9/x3sJ5/\n" +
            "fyhXbD2DlECH6/WLgLZX5l2IAncnsSchYkBARsQdnzI6hfBUVaZTWZGU6qzMqkGY\n" +
            "r6PERucFX6YI3RF74Ck8cPMs/ktBG3mfzH03J7Tms5yjbtNQZUH0O5LT9hA4DclB\n" +
            "Ic6Ht7S9sL2Vg0eW4UVteUekjMyiLpfWNP18zxz4Pl3CTwv1eVo/BXngLlU35689\n" +
            "nX5avxap1U1uwAfJ7yshx4hDSFMyMIsIAMpXk8hzW3xy53v8Tabq4+JtR4smpp7u\n" +
            "oV0UksMiyoVS9MnOnJOVM0lnRw/kYugI8x0svE5cvsLx35DCfZTt16thV/Or7fSb\n" +
            "3D3CdXwqCi3GBr99P355T+E05fEmlCifwyXsnBhbKVT0OfbB7WJ7YqouPDkAbmP/\n" +
            "ZBaBo3jUUPtDxowYX0cK2QVFrtad01JHpR7T5bC74yZRkfV8nwM2rEFDnquAW7PG\n" +
            "CijjW1HXKF8zAz4iUyl5UIIDE427EpbV6uuNpyug7CflMGgM8sO9oJ6ueyyh0X80\n" +
            "9OqYnzRfQGMbGX9s++x5zIVnjPpt1sn2UFAei3xuLevmmV35IfAyJap5dLQZQWxp\n" +
            "Y2UgPGFsaWNlQGV4YW1wbGUuY29tPokCTQQTAQoAQQUCZG42pgkQqIpPcBwM/FMW\n" +
            "IQQeq5acVjRh5HmfVneoik9wHAz8UwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkB\n" +
            "AADGaw/6Ax2nIwzt9/yuD5Lh5jhI9O04U7n2dQUcAvSRX0oJCXOuKvZ8UTIfxBNt\n" +
            "WJaomK0yQpTIkgzv0IjpP1sQW0BaEyDCJc2zXh5KLNqHP1PAqRpZhuHRztEb39Ts\n" +
            "e5aEgEjEEaAGyjd7z0Cewxe+uQ83O/G7c7JphJGBhaOhG9XrGsXyARqapptequLv\n" +
            "BqkEffV8cZTJw8Yh8xNd5VKQLdjL0iLdzq8fp9GMyR/AIEoC/krnt8D82N47bkS9\n" +
            "E4/QZVDfRorG71Ub7GJPX6FO7vtWdOGr5S5YJ2NkCy7VWVJnzm90e1bMZG2YizeW\n" +
            "chYPRhJr3oSGVqjMsrseag64n3DAJd+UYtM0Rnd1X/1iP7KUP7VeQROiX+r09fEW\n" +
            "PQCku0rxOzpTyBYkSIIpWEGgdhha7myCF8sidz0s8/anno0LwmkHXOj789RYKWug\n" +
            "cV17HmLueQ2fRQ3SEtbn28ROJhxuVZdgNFd33WsUgUwbhA8CXZgqVUqixX2Hp9Ae\n" +
            "sVW9LZWrWc0Zk6se//5JVgn1su6t+athMe4HImEVYcMrGsN6Zo3UhVVuwibkZPzA\n" +
            "c4LLSOuW04jyQa6Bmw0pgS3ol6sU6GC+eAWAIvjK1lgFtJffASlN5KcK5xdbrB2E\n" +
            "JW2AizRgUdQz6MFv1KjQjacGjt6AwaXUBQfx7nN4F7laRnWNlrOdBxgEZG42qQEQ\n" +
            "ALrsDvuygG79bNFTYwoTu3zxPKB2BEsOShRi/Yifsm8BeVMptOCrUwDbx44GD3O6\n" +
            "YF+cdg6OxTPPbwwsWOFwqbPj5osnmz0RYW/ntpOLi/kj1C//Hdyf11eGpVs76fwF\n" +
            "SLvvJT0Z17WiheIg5oQHVAgYJSfFPh8W/1DHPr+pshq85Ak+odRqF7XMhGpd7glz\n" +
            "0hIIDrxacNhIskOrbXOCdkZ3FzokPq+YKN+SkVNZKrCKNxMGIRROW+uV6vCBfWp2\n" +
            "M/TD5uClC1aGY3y1E7f7rlSboDJExj0rlneYA4OSXvXN5zWq4Bjd9KGNfPIgsS1R\n" +
            "k0UuIiPlpwprF6ZL5VDSLRfG+GzxZDoAp4VxMVXSY2OYnSc1j12L1uHB11D4jO8F\n" +
            "b5RMz1E8lf4FtV+TI+qTOKDSo3nUfu9OhJCUk+BUS3EpWAMP3uhaX9oABBb8HpFv\n" +
            "orV9/gIM+/pAWoyDs41LWbVlMYK+CHJy4JpbZTE2CIAK5HEqeBTH3rvIDCt93EL7\n" +
            "jImh0T5pt2tsmYxFe6NBqxr4rimOGBrCtxE7e7Ttcv4eB0DSI9yR9oVTzkgXbRG9\n" +
            "mWGsBjKusbS2ywL5tF80MyqFlA6nr7A2AvLTbSyQYiRR8fijpDHgBBxv3d8k4/Hv\n" +
            "L279tnb/peEDa2twFhXk+FCqnYIS8rx/R9pkkXqFWfLJABEBAAEAD/0a9QtOIlai\n" +
            "axsD70YzwFfEM5g+PfbtiiCF4ybUSs+1cZ15MGUdF6gvUgLsCRS2aHUYpNxjyhRH\n" +
            "ng1SUJz62kAnKOFpRSt+uaB3PpAWpEPqCNBDocPBOy4XudvkFfZvOaXdMKaKsszo\n" +
            "rYkobP1Bojrsteq52xjT7AGjOTDj/Emq0H4ElUtKcoh72ARqwKQhKdpsbkwNvu9S\n" +
            "Sd2no7PzuidrjyZC5NJDiaqvX5hk0FG3Rx+dNz+TCZ/5EFRjHhGjxmtEy/HiiPrj\n" +
            "Hht/8y9mU743BoCqbz+1t7EKC1rKYVQfl/PVyhBqlav/loOj+bIDqqWWDwquaaLW\n" +
            "/k3ZVk26g60r5xX+f8iljxIFOsoX6ITps9IjlvWmcDDeKGGOCjchP5Hloa5QSOb/\n" +
            "E1tYMIbzZxBjGYJMUCbe0J44aPTelRXqzPASEG3cWHAOouzi+pNVgh+TdwQO5c01\n" +
            "NiGode2ulhe114MZEGQhIqBa74KBf4CmaurjmX+EWUf9LqZ3Hy3CEGPkz17IXIoa\n" +
            "zgLabtBYNxjoWXqjjLkKRokGt4JYGgUzn4OJX3KotfnCzrWsEQmHOlvot+1imv6I\n" +
            "C4Sz99GNHE6Fhit7tCw0FHeevp5iq5+PLT48FD4ewApCuNPq9ZS0PYQSGEn8ZOMA\n" +
            "aLvmaj8g3NKkW/O9gVy4bovAD/lqFcwu7wgA2lxvjx5qC5cmsLnEIniICe1N3AWs\n" +
            "UjTfBynpVg3q5Gbk6BWiEwdhtVQ/Vb9IdgMFa4Ob53N2jmyziASKzZD3NVJtpO2C\n" +
            "aTS4yxHch97GVAS4RaYAR6oF3Z3dZrsT47QQWbSs8V9673/J3mAZTC5CI5iixS69\n" +
            "nFelYss0T3XnhYpTgd2zEHQmG+BdKrKm4yRl/PpPYaLG6CS2d6RHHRfYRM+HZJdb\n" +
            "PNUgb7dAQX21YDtPJcju/9ylEleUpMqqgaPSPEoK5FxRZH+Vr1epDsOmfqzYTt8D\n" +
            "cHTM9Q8+DiapolEfFTgeC3qgvBiNgGZAJSL3wXaaVtH0Mvr32XTy97ZMkwgA2yRS\n" +
            "ta3TUtUSTsekd9B4YH8jTfBPHJa4VOyjbrsbS59Gn8KOQs6L/7T7WkaxJW+DAGC6\n" +
            "cfL5Pre44orgoDdNvWS/wKvLUMiQIvXxEQoe8+FV0JP6FQ6zW37DhRV/ARDPk60I\n" +
            "MU4YAlC5ToPy5pWtOUM0wV/hQhS0riaalcaErmpnjIkCnJJPl1hM1xO23nm4iNUn\n" +
            "PG+4iusNn8Z74ADanL6goaWwyG9P1SqUNwVcVzcfAHJrSRFaSgFVQ2pBmdPBFsmo\n" +
            "w7iONrMfpmqpw7qcoIOQQ2A4Ru5Yzu5u/nPimesswTsPz/w/3a5pkoZL0SePlKDm\n" +
            "bpbatYXso+izEvz4swf/QGHiffHkNmR/Pm7WNxN/kL0+fAcL0uvwC9b/kF/vxAmo\n" +
            "C/h2FkdmuFyJtSsikD8VUyBNpR4v2ZYmeUKFb+Ox8bVvxUKug6fyR0aZUCqfQeWq\n" +
            "zKiFH/budEmk/XUS50NCPrGijVMNkl6xvfn5KFx56A66XoGT2jP1TvagEjQsyXJM\n" +
            "xa8BWQfy4V2/wIRYcIEclpYUHOELwxEQzEv/Fu9N8GpY/r5AQFpq6ce2WDfxkcr/\n" +
            "wbUV8LOrag6G6MB7Rdu3W2rrsWn3bt4gWFzQcnNoXmNEiMFIiN53EkLSezl2sxV/\n" +
            "WQUBY9uKrUFk18kMV9ZaYSAVHGp6SvinDsh6v9QXF4CriQRSBBgBCgI8BQJkbjap\n" +
            "Ap4BApsCBRYCAwEABAsJCAcFFQoJCAvBXSAEGQEKAAYFAmRuNqkACgkQhJEiWfwl\n" +
            "S2198A/9GjVuyLhG4iRyb2v5x1Kpac50yVcFyUvFN7nyCvlafDC5WPMkr7Xb7A0Z\n" +
            "S/FepApU1lQsBayjW0lXZ6wfGASmKAl2g6esuiXXiPEAnq7sdTon/liqDzze1n6E\n" +
            "xXx0CpU5GPcNNJSe/3BfhEsUYE/BSJ2S/Slo65ASPE0ho0kXfWOtW4L2fUKESqQy\n" +
            "6c8Xi+PB8SofFBEzxKsVPLPFavuG6A7Qbr/usMtU6CLOdfS/uxMa5ycO9xrdzAvx\n" +
            "tyvNDzJC7mjmkMkEsa8Zup2xTzQbKlLLoKzvvt0djLhhMqGCkzrsr+BcHZRyFaiz\n" +
            "enNnyTrjGlR02FCCc3GM+gVXKenfO4RwFVB8nc7eRWMdATTbOPLn7ug3kRmHo39f\n" +
            "sC/YjXD9a64PH1kudfJsRJkyGfayu8lL/FMfGAWwjE17nD8ite4XM3yeRqbOfpvj\n" +
            "D75qo+QxD7YHbaeB69WZ3frDI5ASoZ/9obC7NaXTG9sAPrUiVNMJboZOCWU0omgy\n" +
            "/EiSKHj3sk7pxU/DvoVowy3iqw1BHbTt3sZBLujlags+EN/IdbgtQzcv8JxkJXdN\n" +
            "bpCawi4R1vJd6CDrrikjRj8jCHA/lcewfBPgaXiuKdAcnnPxkQhKVt0ySogPZyoi\n" +
            "F2hhSsU61Rj9ZAO+mjjDbWKW8daNjtzIa042uEnBK+3KmHuAeHMACgkQqIpPcBwM\n" +
            "/FPP7g/7BfvzStQFfPY4//0R0ZKFtgo9500zJ9F+52gUPW0vgfXvrMTjokPAWLtp\n" +
            "3jucsaoVfY/flnuxs4Hhr/XKGdcLh5TjgwhZT8gRUluh9oX7Kx4WPs2CClj42Kwn\n" +
            "30OPxbccAdnirmq6kAL6jVL00PlZep8AOp9lU3FaeAGzWQ80Dk397PnJhx4E3B5Y\n" +
            "02WlpQjVZE2HkwMrjRDYrtBtQ3bsO729+qi1EnjH6kPa5Y2ft2Kr1PjvB78/Oeqf\n" +
            "//5+7BOf/znRXCmHrcr/egAlQgjeNzB60yi3Rn/HfhpPyXKhpqE+uOL9Ddnbb0jb\n" +
            "4MH3EhabDoGQxXm4pz5of+VTQcpydlqPxs8gDPpkKkGqcIwcAOWtZ1ovGMN3oej8\n" +
            "Ts+/7kFjHI27syrw3kk9jxensGS441Mhmr3YWxX9msQpJuHzjKbAXuZ6r+hYC1lR\n" +
            "f6M+/Y3U/q1zqH4JayDuMZJ2ImeYoWVmjVFRZ/gFBkwTrwOjlDS2RV7bDPrNhAwe\n" +
            "h7iHCJ7lSIyMYZeThg3tbeqj3+upHvco+sCbL9k+uA0lwlxU0mCZ4j7w6LrQ1XDt\n" +
            "5b/OpuzKvSQa1bdgzxfj3LiIYAje0CHIhSUY0WVd+NMh04u5PTOqHV4tkfvf8kxx\n" +
            "4RVgv2rt68tmJCjPhdwqJjShOfjSUQQH2VKL0xW5scA4Avr55B2dBxgEZG42qgEQ\n" +
            "ALSJIEApF56A6bA/Mzp5Q3eyKiIHOo8cetddZv5KNbIEt9p1vdM8G2bCa0Dxmf13\n" +
            "/iWMLfsN5tslbEzZkAYXDUElOWmpeYxjvIlRCmCFFhPAZWAtQpsLuCGnfWhLGwrs\n" +
            "mIpx+K1SpqChFMlm1EeUBKgQzq757Mx6yng6B6RKbaJGE74EdkCxQxCp2vBwfxGn\n" +
            "AclUt6ioYwUwWaPQxyyIe9PhuXodl8IDtcqISBCmxmtXbCqsQIhBETwGXy17I2wJ\n" +
            "/RORnLIiOQvvAn1GM62p0f0LU03CMJGO8wRWUvLwrNidXS8o5UxTl0HcFa6rxWwJ\n" +
            "0gwmvDanwzzzE7fJrJTfOIG4BIeTxZq83SRytyoTDw5nYDjK46dphIj8Wvf6FEN8\n" +
            "T6X6IfBbtredTbamJyW20ZQU2waOtTVGduXv+fcReQLpwa+74r5ZlU518IxBR3mp\n" +
            "WaplfF8SeYps/e8N6ACjhJrTCWhAeSMvkLIz0mxOPN981hEbLQL0mnRzMkQkoKUb\n" +
            "GJp/SPjYO80I98FSdt4q3fd+ijkO0yCeFQuzXamP5BzxTk4gOtMRNf55fXvBdRn9\n" +
            "DMruLDHd3haZqfBbzpHAjeJpwkIazd5dMeOTZpvPVuQ2PBaDrApkTcuC1QBQze8t\n" +
            "O+7i03UOdi7DulzNjU7wHjbPZfsg79XXledOcfN0t8WFABEBAAEAD/0b2ir0UxKe\n" +
            "hL9ozjtKSmKHASDgapKVeRyXhMSqtwq1KeauaKtOPy/wCM8QsCVkdiJqqwd9+61R\n" +
            "wmKEsaz3T4+fLQ3AOCH1L37rBWpvLSEUj4JkVd84edSgto0RrcKgixNWipJFtSJZ\n" +
            "VjiVgMx/tX2JazxjwNGQU2JQrY03wrbKyfpqPph6zw4scDQDk6t67vPG2o/SEJZk\n" +
            "Ossdi4xq2ayW6fRaO14KE9X0RtWtYflrHovkwnnbO4Sb6NS+uMhkdt8JKZYN4ltA\n" +
            "NNHCv3WiFXi8zAZAURT6o93onaPC8LAN5Cs35xyHC79ibQCYV85HpnU2JDS1zuh/\n" +
            "SvYQDOhX+F8oW8SludcA3hlVF/0BjMAtSQObyfgFlMczKKBV9EUq2sOHcmR3pAnf\n" +
            "SdgnErmBP97FPdj2unrVn6W7vw6HRdUmoxaeMSimcx5D05iWi7tYfAKi7THdsg+j\n" +
            "jfN2n/yQ8BQaYy3Cp83zBFAENPOwuDnft6YWOVcsDj6GqGzCyLKV441zTkcev+9j\n" +
            "/ioRVD+eorBTJZFJcwdO3Bg4rY5+CZKH45sNipPRFCMQP150Lmdt3mROBImdCpJO\n" +
            "pTxY3e5CdtyOX9wlba6BcmcrBZ+I1PRpk1qT72emdv1OP6EInw8LtHR3gruP7QGF\n" +
            "rpr05z4q0M/Ev0sAiyYckuKQo5NxS2WNcQgA1kfFqvrSjf6/fRwbY4sEU+pek7mc\n" +
            "LctihFk+40j++tZ/MRP5J/uTONyiHqOwbEVFRBQvgUWz/uLwswUH9wRbrxQNUq12\n" +
            "Q0wPlOuay3qanfv2Mc2HqVmGeA+FMnYPsQEMTS+/JYJuUBXnwJ3yYRVJEG3LkWFE\n" +
            "3fagONACVMq+VAzD85B0jKtHB+e0XmLA6f40CQsJA6SkXMrVa7Pv7HRsP0Q922A2\n" +
            "8ejAJgKY4Ot6qEecZiKtC4IASX3fJvBgQNhcUgJj2DxDoLTIy6Akzt/jlOPLc52L\n" +
            "SYdMYEew1TL2IfoXq3W971PKSSyPkhKCFrbdObfBMxpohl684ajJ/FdntQgA169w\n" +
            "g3ayWuG7T1+ulb9TArUzXr/3WY4lhHHzNRxzojIHoBIV5uRfhu9QJb1tkmeQ+py0\n" +
            "0mOB2YlNFVmYqNLEU/jvIO5YlRGJoDwnwZjiepXoniG7WiCdJpBF+woBl15h0gBg\n" +
            "34xzen97FItC2iGExm+hVHZ5ofpXmZgGNeouJmKHkxWVpN6Xhh81+23K+Dh0suRl\n" +
            "XXUXhGdas5IcvNYgvmwL756A56bqay/Mu34DRaZqF+f0qpLmCLH0X4Wb7tlQOjv3\n" +
            "AGqsHTnABXItVbJyHLrMTpZnFd6DNowdNvwso5GzFIZEVwJ47wh8zlM+QZXZDflU\n" +
            "DHdqhP8yOEVZ/JLokQf/VmcAie5/wG1N6JEDktXagmIJl0Fxv6JpHlqJOWXtxzRQ\n" +
            "44IZOpFECiGD7PtIDzhVLEJb9dEBerDOZkZXtGLDI6MwND7EQGQr4oopE8OSEy+Y\n" +
            "6Q3I37GkmRaGVCh6/tX4hvAI+l6EDdWNDKf34LeXwakH8v2RDxfGa5Ls0IdvZV2R\n" +
            "c3+zVmlsuaofazWy7QDH4e6Px8Y2enuKtd81vhO6CO3vYfaBjTlBVNUJvWf2uoK4\n" +
            "qempXHYfg0Q6Jx3+rJ85LCnPI6EX0phEzMvJC7K8Hzi3IwjNuw9vsY3f/JoHuu0w\n" +
            "HOFTQcOjKVPn4N7MSMNDd7jM2iNWqzLXhrvX/48HPn/6iQIzBBgBCgAdBQJkbjaq\n" +
            "Ap4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQqIpPcBwM/FOmGw/7BXDAJIF4vUPg\n" +
            "8Pe/wDPUgSTz6CjBsChDzAwV+ZLZ+uzZG6vHzdlvJYS0axODMwkADl6XXdYXoAT+\n" +
            "3Yc/cOZalOomzok2wKFjCA1SqLg+SUt3jDwJXSLOplnUGbNg4QGhPLYL4CF2p+gl\n" +
            "iPiL936Kg9G8lZS9dVrzHylCbAWvAZ3tNZSZIeMjfm9F5kxNpv98qeUyDkXqvERP\n" +
            "k7oe9DgwByPhYMGooq53S6yIjBIUqVrkji3ZLJxlVcpYBrfnNmZmtoTtbij+1Wwo\n" +
            "P47rix3/oDN1FfBiri29U38dOxTkkaDC65/Vn+OJMGB2b2qEStyBmQWq7h1t3sWR\n" +
            "Qz7R4XBcTxQYqZV9NbGtshvPPmKIo9Ey5HSEptz6GQJlgFt/LAK/Oy6DP9AhEqNg\n" +
            "wGoDwlUhIIIjx1Zj3FZuCrExYR1/j3TeHbPe5vIsLxztOQQdW4rDdjcCwmGs038x\n" +
            "MMKH+q2J4/OfsmYvPjqYV/6IE1KFlJYWI65QYzvRxIB0cdzOq4uESzux1LYQ4Kz8\n" +
            "XR0AS7tZa2DpknBJfTLqscAg4VaMjMdPIN1UjZy5LSFrSYcQ7LGqvwoPMuXoQK7w\n" +
            "8u2PuT0elW6M/s3sPgp08+mCjdE7XaECmTvXGwRQwKnXVpfuiBZN4uhtimo8KlnB\n" +
            "agFMI98+JI+Nc/HJjNKL2cUlAts25L0=\n" +
            "=00AY\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    @Override
    public String getName() {
        return "PKESKv6withSEIPDv2Test";
    }

    @Override
    public void performTest() throws Exception {
        System.out.println(KEY);
        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        PGPSecretKeyRing secretKeys = readKey(KEY);
        PGPPublicKey encKey = secretKeys.getPublicKey(Hex.decode("4D912FFA0293563B54B50F59C0031A08DF4A2CBD"));

        PGPDataEncryptorBuilder dataEncBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        dataEncBuilder.setUseV6AEAD();
        dataEncBuilder.setWithAEAD(AEADAlgorithmTags.EAX, 6);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(dataEncBuilder);
        PublicKeyKeyEncryptionMethodGenerator method = new BcPublicKeyKeyEncryptionMethodGenerator(encKey, true);
        encGen.addMethod(method);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);
        OutputStream encOut = encGen.open(armorOut, new byte[8192]);
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.TEXT, "", PGPLiteralData.NOW, new byte[8192]);

        litOut.write(data);
        litOut.close();
        encOut.close();
        armorOut.close();

        System.out.println(out.toString());

        ByteArrayInputStream bIn = new ByteArrayInputStream(out.toByteArray());
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(armorIn);
        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);

        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyFingerprint());
        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);

        PublicKeyDataDecryptorFactory decryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
        System.out.println(Hex.toHexString(encData.getSessionKey(decryptorFactory).getKey()));
        InputStream decIn = encData.getDataStream(decryptorFactory);
        objectFactory = new BcPGPObjectFactory(decIn);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
        ByteArrayOutputStream decOut = new ByteArrayOutputStream();
        Streams.pipeAll(literalData.getDataStream(), decOut);

        isTrue(Arrays.areEqual(data, decOut.toByteArray()));
    }

    public static void main(String[] args) {
        runTest(new PKESKv6withSEIPDv2Test());
    }

    private PGPPublicKeyRing readCert(String cert) throws IOException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        return new PGPPublicKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }

    private PGPSecretKeyRing readKey(String key) throws IOException, PGPException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(bIn);
        return new PGPSecretKeyRing(armorIn, new BcKeyFingerprintCalculator());
    }
}
