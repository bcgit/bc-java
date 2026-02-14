package org.bouncycastle.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

public class TestResourceFinder
{
    private static final String dataDirName = "bc-test-data";

    private static final String CUSTOM_TEST_DATA_DIR_ENV_NAME = "BC_TEST_DATA_DIR";

    /**
     * We search starting at the working directory looking for the bc-test-data directory.
     *
     * @throws FileNotFoundException
     */
    public static InputStream findTestResource(String homeDir, String fileName)
            throws FileNotFoundException
    {
        final String separator = System.getProperty("file.separator");
        final String customDataDirName = System.getenv(CUSTOM_TEST_DATA_DIR_ENV_NAME);
        if (customDataDirName != null) {
            File dataDir = new File(customDataDirName);
            if (!dataDir.exists())
            {
                String ln = System.getProperty("line.separator");
                throw new FileNotFoundException("Test data directory " + customDataDirName + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
            }
            return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
        } else {
            String wrkDirName = System.getProperty("user.dir");
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
                throw new FileNotFoundException("Test data directory " + dataDir + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
            }
            return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
        }
    }
}
