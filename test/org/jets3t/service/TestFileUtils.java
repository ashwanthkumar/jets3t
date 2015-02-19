package org.jets3t.service;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class TestFileUtils {

    public static File mediumFile(String name, String suffix) {
        // Create a medium (6 MB) file
        File mediumFile = null;
        try {
            mediumFile = File.createTempFile(name, suffix);
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(mediumFile));
            int offset = 0;
            while (offset < 6 * 1024 * 1024) {
                bos.write((offset++ % 256));
            }
            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return mediumFile;
    }
}
