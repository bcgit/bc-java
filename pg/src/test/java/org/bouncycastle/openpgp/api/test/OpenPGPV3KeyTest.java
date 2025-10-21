package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;

import java.io.IOException;

public class OpenPGPV3KeyTest
        extends APITest
{

    private static final String V3Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQHYA2JqgDIAAAEEAOYdcIKFQ5ZWBx0D5DKwMMNFcIhFyqmfDJ0v23ehMxOkXN/o\n" +
            "HO/43+dq6ZqQn0gNw53Tp9no+EmcCYNrZuN0C4Zu8XHSyY6UB+CqzNkz/CwmV10E\n" +
            "dRDipcG1O6scJyy2MWpuOG67til+o+wOLgEkkVkSW8Bl2oqtzVVP4swtKLRZAAUR\n" +
            "AAP+JBiyRqt+DYr8GKE85NBX9nlS6DMaxUYgGKgibR5OSVsJjIjNUtG0sNmODjTN\n" +
            "sPMZqlNln6wS3l7APMWNoStNGc9JG9Puz3eR2W69lPDzhuxuxrHIUBO+3UlEQB/p\n" +
            "N3NPhnwCjh3OWHSMM6rzsX5ExUv0Z4FypnzvMG1x6GRJDVECAO6PyY8NDHsktMVN\n" +
            "HAdgC61iIOz+GbLhNGeikuB+DQpSoyckAF0N5reBxRbyjzNZQ7aVvWpxigUp5OdK\n" +
            "HMK7YcwTAgD275bcqhd+oWHDhyesi6RVswlqGfix48qahf9wOmDkc0nzp8evy/4V\n" +
            "4Qu5zUJGVzi4aEIbFaAnc5lMD9/ydTNjAf485vh4MDFRd3tPvx9mPrHQgaArCBX8\n" +
            "9oImPDk0oaKixwSIFzXeg1qZQeLiwv26Fs8gawWsLVZpR4+zZc1nhZlGnrQpSm9o\n" +
            "biBRLiBTbWl0aCA8MTIzNDUuNjc4OUBjb21wdXNlcnZlLmNvbT6JAJUDBRBiaoAy\n" +
            "VU/izC0otFkBAYIsBACykJ7s82vqCIKewgLpFuqoVGjlfwn9z+G1oa7vr/GxA/mF\n" +
            "Dr4E8rZ1ytUFMUCfzy52FfOtDQUVUeOpAraWQ4JfjXkHuDuZcW2VRh2ctT/hVHG7\n" +
            "1GgOWUBH3EeXASSnFjvUVE39vEjEsidaMxZtMj5jmtieTMB8pSG1QJXPXGoNyQ==\n" +
            "=p7Lr\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static void main(String[] args)
    {
        runTest(new OpenPGPV3KeyTest());
    }

    @Override
    public String getName()
    {
        return "OpenPGPV3KeyTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(V3Key);
        isNotNull(key.getEncoded());

        OpenPGPCertificate certificate = key.toCertificate();
        isNotNull(certificate.getEncoded());
    }
}
