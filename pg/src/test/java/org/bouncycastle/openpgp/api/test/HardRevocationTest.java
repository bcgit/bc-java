package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;

public class HardRevocationTest extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "HardRevocationTest";
    }

    @Override
    public void performTest() throws Exception
    {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsBNBFpJegABCACzr1V+GxVkrtfDjihYK+HtyEIcO52uw7O2kd7JbduYp4RK17jy\n" +
                "75N3EnsgmiIkSxXCWr+rTtonNs1zCJeUa/gwnNfs7mVgjL2rMOZU/KZ4MP0yOYU5\n" +
                "u5FjNPWz8hpFQ9GKqfdj0Op61h1pCQO45IjUQ3dCDj9Rfn44zHMB1ZrbmIH9nTR1\n" +
                "YIGHWmdm0LItb2WxIkwzWBAJ5acTlsmLyZZEQ1+8NDqktyzwFoQqTJvLU4StY2k6\n" +
                "h18ZKZdPyrdLoEyOuWkvjxmbhDk1Gt5KiS/yy7mrzIPLr0dmJe4vc8WLV+bXoyNE\n" +
                "x3H8o9CFcYehLfyqsy40lg92d6Kp96ww8dZ5ABEBAAHCwLsEIAEKAG8FglwqrYAJ\n" +
                "EAitUcrkcPAGRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9y\n" +
                "Z4KjdWVHTHye8HeUynibpgE5TYfFnnBt9bbOj99oplaTFiEE4yy22oICkbfnbbGo\n" +
                "CK1RyuRw8AYAAMxeB/4+QAncX1+678HeO1fweQ0Zkf4O6+Ew6EgCp4I2UZu+a5H8\n" +
                "ryI3B4WNShCDoV3CfOcUtUSUA8EOyrpYSW/3jPVfb01uxDNsZpf9piZG7DelIAef\n" +
                "wvQaZHJeytchv5+Wo+Jo6qg26BgvUlXW2x5NNcScGvCZt1RQ712PRDAfUnppRXBj\n" +
                "+IXWzOs52uYGFDFzJSLEUy6dtTdNCJk78EMoHsOwC7g5uUyHbjSfrdQncxgMwikl\n" +
                "C2LFSS7xYZwDgkkb70AT10Ot2jL6rLIT/1ChQZ0oRGJLBHiz3FUpanDQIDD49+dp\n" +
                "6FUmUUsubwwFkxBHyCbQ8cdbfBILNiD1pEo31dPTwsDEBB8BCgB4BYJeC+EACRAI\n" +
                "rVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeH\n" +
                "LGXtWodbY9gI8X3QzLB9sL0hMGY2/+9yAip5uwckkAIVCgKbAwIeARYhBOMsttqC\n" +
                "ApG3522xqAitUcrkcPAGAABmBQgAoipwm9jQWWvyY9WiXuEdq8T2Y9hEV1nt2ySj\n" +
                "Tyk+ytK1Q5E8NSUYk3wrLgGNpWPbCiXYUGZfms15uuL703OoRBkUP/l7LA5RNgyJ\n" +
                "/At+Bw3OPeWZ68hzQfA3eZdR3Y6sXxiGOhwTyVHcdHXncD+NjorIPbeSrAvM5Xf/\n" +
                "jCEYM5Kfg4NC1yVZw7sFhD6KNjeloQK+UXi718QC1+YbfS295T9AwEmbwCsvQTv8\n" +
                "EQq9veCfHYPwqMAH5aMn9CqPiY8o2p5mZ92nMuQhpFTdpnPjxVHpBmQw8uaKGJIF\n" +
                "zvwpgKbkzb2m3LfgOyFVXVljOUlm/dCb2lfUlo4up0KYVZu0rcLAxAQfAQoAeAWC\n" +
                "Wkl6AAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1w\n" +
                "Z3Aub3Jn1WXYy2GcQ19ob8t2hq7BOItGrywzM393vZFR5mg+jwICFQoCmwMCHgEW\n" +
                "IQTjLLbaggKRt+dtsagIrVHK5HDwBgAAUGMIAK3yEcaveZ6VCgDj17NuZ2Zb8vsU\n" +
                "G65rE8R4QGFvHhhXM/NkMLpqKq0fFX66I8TPngmXUyPOZzOZM852A1NvnDIbGVZu\n" +
                "flYRmct3t0B+CfxN9Q+7daKQr4+YNXkSeC4MsAfnGBnGQWKf20E/UlGLoWR9jlwk\n" +
                "dOKkm6VVAiAKZ4QR8SjbTpaowJB3mjnVv/F3j7G3767VTixmIK2V32Ozast/ls23\n" +
                "ZvFL1TxVx/rhxM04Mr2G5yQWJIzkZgqlCrPOtDy/HpHoPrC+Dx0kY9VFH8HEA+ea\n" +
                "tJt1bXsNioiFIuMCouS3Hg7aa46DubrVP9WHxAIjTHkkB1yqvN3aWs7461LNEmp1\n" +
                "bGlldEBleGFtcGxlLm9yZ8LAxAQTAQoAeAWCWkl6AAkQCK1RyuRw8AZHFAAAAAAA\n" +
                "HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnOkYsewniH1sJ2kI5N2wa\n" +
                "5AImO40vTfrIbkXR2dICirICFQoCmwMCHgEWIQTjLLbaggKRt+dtsagIrVHK5HDw\n" +
                "BgAAn/UIALMbXwG8hm7aH46107PZbChFrxoJNNn0mMioz28mkaoe9jJSJVF8KqtY\n" +
                "odkyXN78BfGjVQ63G/Q5wWm3bdjNbyNz1Gnht9QZmpAv12QjQq22yZMnf73TC6sO\n" +
                "6ay66dGrlTTYS2MTivbrF2wpTcZbqOIv5UhVaOQfWovp3tZCioqZc6stqqoXXqZa\n" +
                "JnMBh2wdQpGdOA5gjG0khQBsWKlAv2wZtG6JQnm8PyiM/bBKIzSrepr7BTeu/4TG\n" +
                "HiUtB1ZcMHOovIikswtg+d4ssIbb5HYihAl0Hlw3/czVwJ9cKStNUiydIooO3Axa\n" +
                "7aKpHz2M2zXwtG7d+HzcfYs98PWhB/HOwE0EWkrLgAEIALucmrvabJbZlolJ+37E\n" +
                "Uqm0CJztIlp7uAyvSFwd4ITWDHIotySRIx84CMRn9xoiRI87m8kUGl+Sf6e8gdXz\n" +
                "h/M+xWFLmsdbGhn/XNf29NjfYMlzZR2pt9YTWmi933xXMyPeaezDa07a6E7eaGar\n" +
                "HPovqCi2Z+19GACOLRGMIUp1EGAfxe2KpJCOHlfuwsWTwPKQYV4gDiv85+Nej7Ge\n" +
                "iUucLDOucgrTh3AACAZyg5wvm0Ivn9VmXrEqHMv618d0BEJqHQ7t6I4UvlcXGBnm\n" +
                "QlHBRdBcmQSJBoxyFUC8jn4z9xUSeKhVzM/f2CFaDOGOoLkxETExI/ygxuAT+0Xy\n" +
                "R00AEQEAAcLCPAQYAQoB8AWCXgvhAAkQCK1RyuRw8AZHFAAAAAAAHgAgc2FsdEBu\n" +
                "b3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn3AGtWT1k7YOtMNzqOHbeBWvHChWG2WLK\n" +
                "g0h1eacBHzMCmwLAvKAEGQEKAG8Fgl4L4QAJEBD8vP8OjqeRRxQAAAAAAB4AIHNh\n" +
                "bHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZy+iNvlcjeU9RaFYI93HZzC2AqXA\n" +
                "eYvxUUglSsm7i864FiEEzqYQ0IT6UfIR4cRsEPy8/w6Op5EAAK5PB/wIYzPZam33\n" +
                "xS+kUUeB043pbKcuAN58k4nApY6w7lw1Idtxny72o00eYdemQagBe3KW/a65c9Qt\n" +
                "VnEuSS1cc1wHu3/ijn17vnsi4aU82fFU96St4RxmmMJVZV6wWT9CV4C/IZuoQ0l2\n" +
                "UGbXKbJ0NbiBwvTjcVAeJYjRYU6kAkGHUCRYhbNbplG6PwuCnc5QyNPGzNwqhCmr\n" +
                "fb1BbhhuvJg4NAq0WRFrfeOi+YvJGZgVJEkoSJtpOXtqhP5rmHjOqikDbMZcd1SH\n" +
                "+XlIbcQovX4O0o7x5HVEhbLWHMQHWqIVghQhLAySNdoc3CkGs0o77SheATQSoF/8\n" +
                "C7G1UJ2C3fYIFiEE4yy22oICkbfnbbGoCK1RyuRw8AYAADYzB/9TGOwycsZIk43P\n" +
                "485p1carRzmQwkplKpNHof+gR7PqLLVqpBguvu3X8Q56bcHKmp3WHsuChdmo7eJz\n" +
                "sLtMUMPzRBd4vNYeyInsGOxvmE+vQ1Hfg71VEHpnyjWFTqzKqB+0FOaOGKI3SYg3\n" +
                "iKdnfycia6sqH+/CRQB5zWYBwtk9s6PROeHZzk2PVTVDQjlHLeUW8tBl40yFETtH\n" +
                "+POXhrmcVVnS0ZZQ2Dogq0Bz0h4a8R1V1TG2CaK6D8viMmiWp1aAFoMoqQZpiA1f\n" +
                "GiDTNkSzLBpLj00bSEyNmZRjkDe8YMuC6ls4z568zF38ARA8f568HRusxBjCvAJF\n" +
                "ZDE+biSbwsI8BBgBCgHwBYJa6P+ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmf0NGelgx9vvPxdcRBLogKbI559pRjWdg3i\n" +
                "GpJSc3akDgKbAsC8oAQZAQoAbwWCWuj/gAkQEPy8/w6Op5FHFAAAAAAAHgAgc2Fs\n" +
                "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn61QE8l97YHDNs+NX6mKrsVYSUWrz\n" +
                "evsNklOMRBvvkqgWIQTOphDQhPpR8hHhxGwQ/Lz/Do6nkQAARlYIALAfDNiiOXMV\n" +
                "yioFRy9XRH84PYWpVWr5LX3E+mVQv/mg6feLbwQi9ehroauHHDewwE61seN9Pxnn\n" +
                "GOhO+6r4Q85gnJUm3S24mZrK1V/ZApk36ycxUOuCn7yEuRoGy9tfmSfqSlthzjAR\n" +
                "p+rIAD5k6jOVLAwqbBCg7eQiXCa97E3PA/TYRJ3NHSrEPdfp/ZrN1ubcshOq/acj\n" +
                "Ok4QQjIW0JEe4RPV1gEHjtSC0hRp4ntGhXE1NDqNMC9TGoksgP/F6Sqtt8X8dZDU\n" +
                "vYUJHatGlnoTaEyXQrdTatXFgActq0EdMfqoRlqMH7AI5wWrrcb3rdvLdpDwgCDJ\n" +
                "4mKVnPPQcH4WIQTjLLbaggKRt+dtsagIrVHK5HDwBgAAqtYH/0Ox/UXuUlpPlDp/\n" +
                "zUD0XnX+eOGCf2HUJ73v4Umjxi993FM3+MscxSC5ytfSK3eX/P5k09aYPfS94sRN\n" +
                "zedN9SSSsBaQgevUbMrIPPGSwy9lS3N8XbAEHVG1WgqnkRysLTLaQb2wBbxfaZcG\n" +
                "ptEklxx6/yZGJubn1zeiPIm/58K9WxW3/0ntFrpPURuJ3vSVAQqxsWpMlXfjoCy4\n" +
                "b8zpiWu3wwtLlGYUyhW4zMS4WmrOBxWIkW389k9Mc/YMg8rQ1rBBTPl6Ch5RB/Bc\n" +
                "f1Ngef/DdEPqSBaBLjpgTvuRD7zyJcTQch4ImjSLirdTLvlAG9kqZeg+c2w31/97\n" +
                "6sXYWB8=\n" +
                "=13Sf\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        OpenPGPCertificate certificate = OpenPGPCertificate.fromAsciiArmor(CERT);
        String msg = "Hello, World";
        String SIG1 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsC7BAABCgBvBYJa564ACRAIrVHK5HDwBkcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfM0EN4Ei0bQv6UO9BRq2wtUfV948cRynRMBb8TSGCG\n" +
                "tBYhBOMsttqCApG3522xqAitUcrkcPAGAAAlNwf+L0KQK9i/xmYKOMV2EX13QUoZ\n" +
                "vvb/pHGZaCQ9JtvEF2l2DT0DqByZ+tOv5Y4isU+un7CraoyvyajAwR0Yqk937B6C\n" +
                "HQHKMkmIl+5R4/xqSoWYmOidbrgilojPMBEhB3INQ8/THjjFijtLzitVhnWBd7+u\n" +
                "s0kcqnWnOdx2By4aDe+UEiyCfSE02e/0tIsM71RqiU91zH6dl6+q8nml7PsYuTFV\n" +
                "V09oQTbBuuvUe+YgN/uvyKVIsA64lQ+YhqEeIA8Quek7fHhW+du9OIhSPsbYodyx\n" +
                "VWMTXwSWKGNvZNAkpmgUYqFjS2Cx5ZUWblZLjrNKBwnnmt50qvUN7+o2pjlnfA==\n" +
                "=UuXb\n" +
                "-----END PGP SIGNATURE-----\n";


    }
}
