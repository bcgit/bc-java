package org.bouncycastle.jsse.provider.test;

public class PKCS12TestData
{
    public static byte[] _non_PBMAC1_PKCS12 = org.bouncycastle.util.encoders.Base64.decode(
        "MIIJ5gIBAzCCCZAGCSqGSIb3DQEHAaCCCYEEggl9MIIJeTCCBa8GCSqGSIb3DQEHAa" +
            "CCBaAEggWcMIIFmDCCBZQGCyqGSIb3DQEMCgECoIIFQTCCBT0wZwYJKoZIhvcNAQUNMFowO" +
            "QYJKoZIhvcNAQUMMCwEFFtDpayt6Eulzu2hBrwAHYm9JHJZAgMAyAACASAwDAYIKoZIhvcN" +
            "AgkFADAdBglghkgBZQMEASoEEOeGAPq+pg+DVhzoxYYYnnQEggTQUKfih/SptiykLerBEF5" +
            "kxSDAT5kKva58FJQex2xaXEHnqJ2fWlmXsg9id0j4kYMK3b+WAwigO/FrmMatQTS8NjTfYd" +
            "a3WAgeOXhpaULZBOZh+h0TXSsRLkXKvWRJku7kFUZZ5lhOlZL8fDYV4ct01xDyC7abRZUar" +
            "6fWnjYSH4EKVLFdRvf9dnoyv4CQldPygJRjTt2W8G8Ne4TCN5YCZAYEPEMnjeWxr3R/C7gn" +
            "4fD65nTHQd89JOL6MlvzWfv6pQnOs109d3HrQCbecdgo9mDQGQWmX29lE0Yd5lGxPWzpU+h" +
            "/JL78H1/8VJufnIjBHCAHN5Y9ZEnB2JaV2i+1EhMl4FT/3ve5Oom6UMmzfgg/5Osxhdm7l3" +
            "4/Jn6BJkkIgBGZ6OTnWSiJGpRdzlSA3X8RHOPR1blwrI6XzTLzBHzHHsQ8JmpS0gwOR09zL" +
            "opunPffW/thcypYwPk+8zwdvnYVTh+dlOrXpfqoykPOQF9mDSJcDFsHi0NU0ziy3zuJ28mq" +
            "eYWEKrQzj1zwWRqLLZUD82q97MDCYlp42MNZOnjzRoBdPr+zkXtH1pzHIajwBGkOWu16uKh" +
            "pT8oEhTa7ZRWh9k2BFlUJjnWv9OflhmMy7Afu3ZESeJX0wM5iPSXnofldkucZQ86maZtF2O" +
            "35cOH/whv9IssSpTJ/v2kqAzOlOxj0oLXHuTWaYeySnVfKvtu7x44ww5m95OFM8wq0mIuzQ" +
            "fvIiodTfNFsf5ejd5BfAR2NL18fgRTE1ec9EV6NtkTpD96v6aRPCkOkMH7khll+MMcUmpv0" +
            "Z1/oLVc2fy5Bvjv4bjW52xo0UU0yIQVfxX1pNptzvM14NhCVOHyfhA5QrX/DQvQ130WWo/C" +
            "U4DfCdhkSv+GGMftW3K8Lt7GX5+eie6ukF08qU3EXquRjwg8eKgba+vheZpYeZTjtlBK19K" +
            "Bbqcvh6zCXqnDlkVz0BNGfqoCMG78qBq14RGFd5Fuq0JzAsCQlxxQpFfoJmWEW7dJM4qv6C" +
            "OZe1RW7o/fHTuWTYdIHW6oWaFXSZPAlOBjgn9B9DRYIUTLoQsc6OxTvWKL+uvyKm8KnGYqw" +
            "HA79Bd2gYCUBnEodMpqLgUKWa3TF4uo/KGKHiL1jZnTdLcc//uBn4Fg02oQH6NGx2Zu21SR" +
            "2qyT2zRxwEnyg7wP4uo8mCgUT38fXrzk/Arm2njnLINeHqTg48AnwBknPBRpuFG4FgfAiDt" +
            "4UsLvllkVJ0+Vkukplk5CsN/6/qsvMivuOuq3azxpu3tJp+hTHhvmEtkpq82dpA/WxsqcLm" +
            "BuY7z2TUjwtycZmYN5o6ySgPIjL+gDNy3wVPNbIQNgALZBe2m27pfa9gv9z9a4kLCuAbp0Z" +
            "kTX1mAY4eURqVFziY1cCu+46GePqFcnLd1eXXItXPg3DZL5fFtYI4YWdHjIxtJCrKXcWneB" +
            "eHiKCGRv3Zyzh7ShITHVQGn3OnzHmFFwXT1P2Vem0bkrAcOLF0C/KQea81zqw5cZP/6DTU3" +
            "rtTC9nFmRcAuQPByz1Vb21d1ZmDiSoIurVLgujUoT/uuRSQiO7ZMwlQ7zQfkServAObhMe7" +
            "Pweg+wmJYN7CNKWgjtXPh3i3mrIkJYAJiYG4CYkq5DwVZUB41sCnoV1uRxv7tgxQDAbBgkq" +
            "hkiG9w0BCRQxDh4MAG8AcgBlAHMAdABlMCEGCSqGSIb3DQEJFTEUBBJUaW1lIDE3NzA3OTA" +
            "zMDAxNzIwggPCBgkqhkiG9w0BBwagggOzMIIDrwIBADCCA6gGCSqGSIb3DQEHATBnBgkqhk" +
            "iG9w0BBQ0wWjA5BgkqhkiG9w0BBQwwLAQUcY8T6zTJiBWPpJTPLiL7F+MuqI8CAwDIAAIBE" +
            "DAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBAgQQ2X5H83LsP1aK9dNjeAcqeYCCAzC9qMZj" +
            "MczRWYIRaNQlHgN0fK8bf3Wf9dH5GsvIEQp2M/FsZK6jDpK0UTNA+N95P47WpUFCf08TO4U" +
            "RoE/YYkKj3xurmVB9N5gYh8UwNJQAJdOxWGB7ZpYBMkXjkleNXDQfocm67i5cwGwG7qBFVO" +
            "O3cmiJxhBsq3JnMEA9XUzJ50cUlLRK4SNQelWlwHvTofvKiq6seyG+iuPlH+BiBdU5NwSqF" +
            "yMo7giSrOaqLl7/+3fH+0aXttMcWHc1tUOuuOz88L+O7ClBl6xOLaawXgITtHstdN6Gwr4B" +
            "erB5dsJxyUcQ4q1/bu2JSj3eJ8KAC1Kph22qOsOwFIYpNIdLIHbNWO0qS9AGOZgyHqbpnkX" +
            "uFLsAdf6DNotEB6YKEGUCTXRlWyvi2Hxf9k0lFAYTYqxUfMuFl/6onIK4H/Yp9Wxv3F8cP5" +
            "adoObC0WWrWD2fk/90wa3bGl4s4BAHwZGy+O7Om3bQl57n2s+NGBtcnjamGTSEjPkF0Fx/d" +
            "uOHu1D0SJeM0miBKi4uRpK4lC+qhnEZfOlka+hv6GHccozcROuSzS9pdU6+Tj9Lt9ujbXtd" +
            "RcHoitwdlXltLSBAKeiJKRMSkzLrV7tk9QkyC7KF0vvziN5efxjDbeNA2+0OwGoBg+Dbh7a" +
            "KaHu76my5xjBmLj8dgL0FR4HaHfRuUkJM6I+Mw6WBzTJ969SnQDxgXQ+wftl7bjWzjq/0J+" +
            "OHGMaSIIkeU2VZ6sn7e0Vay2n9S0uPvkEgDJrWhq9JQmtDxv7eWRWFAF4/tUKR4rpsyW7zC" +
            "fYiEyoQfqLzXI0leqQFYTzZPQfYMbqv48AM4Y1ZftCWth+wxQGX+67SAT6fX/taZQDe0VzQ" +
            "IPpT2UOYt9OF5MPCzc/QYIiRafjszcBirkMh9o4vR6M0oJbdJl5DV4/eVXmqhc4ZtzchVsH" +
            "W78BbO0GyVOxPswSiVHSPJFJ6DNtgIKwQHU4+Mc88EqysQJ76axZwvwmloAn7/ryAo2/NKH" +
            "tMj8tGooBfhQyQZumMHAyJZm9yZYGOtH+9YRGVaFvlTeh8T+/OrTHzo6eu/8BQAaONFaTno" +
            "h3/iBNfP6smXf9dU98wTTAxMA0GCWCGSAFlAwQCAQUABCCjZq2p5LKWmQwE7opEVBixqYkY" +
            "+5U4iy5noOLCHuIpUQQUsEaWG67NJjieRJpQYxBMKuevyEQCAicQ");

    public static byte[] _certsOnly = org.bouncycastle.util.encoders.Base64.decode(
        "MIICnwIBAzCCApgGCSqGSIb3DQEHAaCCAokEggKFMIICgTCCAn0GCSqGSIb3" +
            "DQEHAaCCAm4EggJqMIICZjCCAmIGCyqGSIb3DQEMCgEDoIICHDCCAhgGCiq" +
            "GSIb3DQEJFgGgggIIBIICBDCCAgAwggFpoAMCAQICBHcheqIwDQYJKoZIhv" +
            "cNAQELBQAwMjENMAsGA1UEChMERGVtbzENMAsGA1UECxMERGVtbzESMBAGA" +
            "1UEAxMJRGVtbyBjZXJ0MCAXDTE5MDgzMTEzMDgzNloYDzIxMDkwNTE5MTMw" +
            "ODM2WjAyMQ0wCwYDVQQKEwREZW1vMQ0wCwYDVQQLEwREZW1vMRIwEAYDVQQ" +
            "DEwlEZW1vIGNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKOVC4" +
            "Qeg0KPAPRB9WcZdvXitiJ+E6rd3czQGNzEFC6FesAllH3PHSWuUZ2YjhiVM" +
            "YJyzwVP1II04iCRaIc65R45oVrHZ2ybWAOda2hBtySjQ2pIQQpoKE7nvL3j" +
            "JcHoCIBJVf3c3xpfh7RucCOGiZDjU9CYPG8yznsazb5+fPF/AgMBAAGjITA" +
            "fMB0GA1UdDgQWBBR/7wUDwa7T0vNzNgjOKdjz2Up9RzANBgkqhkiG9w0BAQ" +
            "sFAAOBgQADzPFsaLhVYD/k9qMueYKi8Ftwijr37niF98cgAHEtq6TGsh3Se" +
            "8gEK3dNJL18vm7NXgGsl8jUWsE9hCF9ar+/cDZ+KrZlZ5PLfifXJJKFqVAh" +
            "sOORef0NRIVcTCoyQTW4pNpNZP9Ul5LJ3iIDjafgJMyEkRbavqdyfSqVTvY" +
            "NpjEzMBkGCSqGSIb3DQEJFDEMHgoAYQBsAGkAYQBzMBYGDGCGSAGG+Watyn" +
            "sBATEGBgRVHSUA");


}
