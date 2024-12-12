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
     * @throws FileNotFoundException in case the test data directory is missing
     */
    public static InputStream findTestResource(String homeDir, String fileName)
        throws FileNotFoundException
    {
        String wrkDirName = System.getProperty("user.dir");
        File wrkDir = new File(wrkDirName);
        File dataDir = new File(wrkDir, dataDirName);
        while (!dataDir.exists())
        {
            wrkDirName = wrkDir.getParent();
            if (wrkDirName == null) break;
            wrkDir = new File(wrkDirName);
            dataDir = new File(wrkDir, dataDirName);
        }

        if (!dataDir.exists())
        {
            final String ln = System.getProperty("line.separator");
            throw new FileNotFoundException("Test data directory " + dataDirName + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
        }

        final File homeDirFile = new File(dataDir, homeDir);
        return new FileInputStream(new File(homeDirFile, fileName));
    }
}
