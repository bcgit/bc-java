package org.bouncycastle.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

public class TestResourceFinder
{
    private static final String dataDirName = "bc-test-data";

    /**
     * We search starting at the working directory looking for the bc-test-data directory.
     *
     * @throws FileNotFoundException
     */
    public static InputStream findTestResource(String homeDir, String fileName)
        throws FileNotFoundException
    {
        String wrkDirName = System.getProperty("user.dir");
        String separator = System.getProperty("file.separator");
        File wrkDir = new File(wrkDirName);
        File dataDir = new File(wrkDir, dataDirName);
        while (!dataDir.exists() && wrkDirName.length() > 1)
        {
            wrkDirName = wrkDirName.substring(0, wrkDirName.lastIndexOf(separator));
            wrkDir = new File(wrkDirName);
            dataDir = new File(wrkDir, dataDirName);
        }

        if (!dataDir.exists())
        {
            String ln = System.getProperty("line.separator");
            throw new FileNotFoundException("Test data directory " + dataDirName + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
        }

        return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
    }
}
