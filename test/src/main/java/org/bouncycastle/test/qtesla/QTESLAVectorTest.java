package org.bouncycastle.test.qtesla;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class QTESLAVectorTest
{

    public static final String QTESLA_1 = "qTesla-I";
    public static final String QTESLA_3_SIZE = "qTesla-III-size";
    public static final String QTESLA_3_SPEED = "qTesla-III-speed";
    public static final String QTESLA_P_1 = "qTesla-p-I";
    public static final String QTESLA_P_3 = "qTesla-p-III";


    /**
     * Accepts:
     * [Variant] [vector file], or
     * <p>
     * <p>
     * The variant will be determined from the file name.
     * [vector file]
     *
     * @param args
     */
    public static void main(String args[])
        throws Exception
    {
        int teslaCat = 0;
        File vectorFile = null;

        if (args.length == 2)
        {
            if (args[0].equals("1"))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_I;
            }
            else if (args[0].equals("3size"))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_III_SIZE;

            }
            else if (args[0].equals("3speed"))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_III_SPEED;
            }
            else if (args[0].equals("p1"))
            {
                teslaCat = QTESLASecurityCategory.PROVABLY_SECURE_I;
            }
            else if (args[0].equals("p3"))
            {
                teslaCat = QTESLASecurityCategory.PROVABLY_SECURE_III;
            }
            else
            {
                System.err.println("With 2 arguments, first must be '1,3size, 3speed, p1 or p3");
                System.exit(1);
            }

            vectorFile = new File(args[1]);


        }
        else if (args.length == 1)
        {
            if (args[0].contains(QTESLA_3_SPEED))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_III_SPEED;
            }
            else if (args[0].contains(QTESLA_3_SIZE))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_III_SIZE;
            }
            else if (args[0].contains(QTESLA_1))
            {
                teslaCat = QTESLASecurityCategory.HEURISTIC_I;
            }
            else if (args[0].contains(QTESLA_P_3))
            {
                teslaCat = QTESLASecurityCategory.PROVABLY_SECURE_III;
            }
            else if (args[0].contains(QTESLA_P_1))
            {
                teslaCat = QTESLASecurityCategory.PROVABLY_SECURE_I;
            }
            else
            {
                System.err.println("Security category could not be determined from vector file name.");
                System.exit(1);
            }
            vectorFile = new File(args[0]);
        }
        else
        {
            System.err.println("Usage: <security category> <file>, or");
            System.err.println("Usage: <file> and it will determine the security category from the name.");
            System.exit(1);
        }

        if (vectorFile.exists())
        {
            FileInputStream fin = new FileInputStream(vectorFile);
            List<Map<String, String>> vectors = parseVectors(fin, "count");
            fin.close();

            for (int t = 0; t < vectors.size(); t++)
            {
                System.out.println("Processing " + (t + 1));


                Map<String, String> vector = vectors.get(t);
                byte[] seed = Hex.decode(vector.get("seed").toString());
                //     int mlen = Integer.valueOf(vector.get("mlen"));
                byte[] msg = Hex.decode(vector.get("msg").toString());
                byte[] pk = Hex.decode(vector.get("pk").toString());
                byte[] sk = Hex.decode(vector.get("sk").toString());
                //     int smlen = Integer.valueOf(vector.get("smlen"));
                byte[] sm = Hex.decode(vector.get("sm").toString());

                doTestKAT(teslaCat, pk, sk, seed, msg, sm);
            }
        }
        else
        {
            System.err.println("Vector file " + vectorFile.getName() + " does not exist.");
            System.exit(1);
        }


    }


    private static void doTestKAT(int securityCategory, byte[] pubKey, byte[] privKey, byte[] seed, byte[] msg, byte[] expected)
    {
        QTESLAPublicKeyParameters qPub = new QTESLAPublicKeyParameters(securityCategory, pubKey);
        QTESLAPrivateKeyParameters qPriv = new QTESLAPrivateKeyParameters(securityCategory, privKey);

        QTESLASigner signer = new QTESLASigner();

        signer.init(true, new ParametersWithRandom(qPriv, QTESLASecureRandomFactory.getFixed(seed, 256)));

        byte[] sig = signer.generateSignature(msg);

        if (!Arrays.areEqual(expected, Arrays.concatenate(sig, msg)))
        {
            throw new RuntimeException("Signature not correct.");
        }

        signer.init(false, qPub);

        if (!signer.verifySignature(msg, sig))
        {
            throw new RuntimeException("Signature failed to verify.");
        }
    }


    private static List<Map<String, String>> parseVectors(InputStream in, String delim)
        throws Exception
    {
        BufferedReader bin = new BufferedReader(new InputStreamReader(in));
        String line;

        List<Map<String, String>> out = new ArrayList<Map<String, String>>();
        Map<String, String> runningMap = null;

        int lc = 0;
        while ((line = bin.readLine()) != null)
        {
            lc++;


            line = line.trim();
            if (line.length() == 0)
            {
                continue;
            }

            if (line.startsWith("#"))
            {
                continue;
            }


            if (line.contains("="))
            {

                String[] parts = line.split("=");
                if (parts.length == 2)
                {
                    String key = parts[0];

                    if (key.startsWith(delim))
                    {
                        runningMap = new HashMap<String, String>();
                        out.add(runningMap);
                    }

                    runningMap.put(key.trim(), parts[1].trim());
                }
                else
                {
                    throw new RuntimeException("Split vector file line did not have 2 parts at line " + lc);
                }
            }
            else
            {
                throw new RuntimeException("Vector file line does not contain an '=' at line " + lc);
            }

        }
        bin.close();

        return out;
    }
}
