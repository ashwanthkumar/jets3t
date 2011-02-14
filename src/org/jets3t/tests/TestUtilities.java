package org.jets3t.tests;

import java.io.File;
import java.io.FileOutputStream;

import org.jets3t.service.io.SegmentedRepeatableFileInputStream;

import junit.framework.TestCase;

public class TestUtilities extends TestCase {

    public void testSegmentedRepeatableFileInputStream() throws Exception {
        File testFile = File.createTempFile("JetS3t-testSegmentedRepeatableFileInputStream", null);
        int read = -1;
        SegmentedRepeatableFileInputStream segFIS = null;

        // Create a 1 MB file for testing
        FileOutputStream fos = new FileOutputStream(testFile);
        long testFileLength = 1 * 1024 * 1024;
        int offset = 0;
        while (offset < testFileLength) {
            fos.write((offset % 256));
            offset++;
        }
        fos.close();

        // Invalid segment length
        try {
            segFIS = new SegmentedRepeatableFileInputStream(testFile, 0, 0);
            fail("SegmentedRepeatableFileInputStream accepted invalid arguments");
        } catch (IllegalArgumentException e) { }

        // Segment exceeds file length
        try {
            segFIS = new SegmentedRepeatableFileInputStream(testFile, 0, testFileLength + 1);
            fail("SegmentedRepeatableFileInputStream accepted invalid arguments");
        } catch (IllegalArgumentException e) { }

        // Offset beyond file length
        try {
            segFIS = new SegmentedRepeatableFileInputStream(testFile, testFileLength + 1, 1);
            fail("SegmentedRepeatableFileInputStream accepted invalid arguments");
        } catch (IllegalArgumentException e) { }

        // Offset and segment length exceed file length
        try {
            segFIS = new SegmentedRepeatableFileInputStream(testFile, testFileLength - 1, 2);
            fail("SegmentedRepeatableFileInputStream accepted invalid arguments");
        } catch (IllegalArgumentException e) { }

        // Just right
        try {
            segFIS = new SegmentedRepeatableFileInputStream(testFile, testFileLength - 1, 1);
            segFIS.close();
        } catch (IllegalArgumentException e) {
            fail("SegmentedRepeatableFileInputStream failed to accept valid arguments");
        }

        segFIS = new SegmentedRepeatableFileInputStream(testFile, 0, 10);

        // Ensure reads stay within segment boundaries...
        long byteCount = 0;
        byte[] buffer = new byte[256];

        // Read entire segment 1 byte at a time
        segFIS.reset();
        byteCount = 0;
        while ((read = segFIS.read()) != -1) {
            byteCount++;
        }
        assertEquals("Read beyond segment length", 10, byteCount);

        // Read entire segment using buffer
        segFIS.reset();
        byteCount = 0;
        while ((read = segFIS.read(buffer, 0, buffer.length)) != -1) {
            byteCount += read;
        }
        assertEquals("Read beyond segment length", 10, byteCount);

        // Read partial segment with offset using buffer
        segFIS.reset();
        byteCount = 0;
        offset = 5;
        while ((read = segFIS.read(buffer, offset, (int) (5 - byteCount) )) != -1) {
            byteCount += read;
            offset = 0;
        }
        assertEquals("Read beyond segment length with offset", 5, byteCount);

        // Read starting beyond segment
        segFIS.reset();
        byteCount = 0;
        offset = 10;
        while ((read = segFIS.read(buffer, offset, buffer.length)) != -1) {
            byteCount += read;
        }
        assertEquals("Read beyond segment length", 0, byteCount);

        segFIS.close();

        // Check valid data read from segment...

        // Read entire file
        segFIS = new SegmentedRepeatableFileInputStream(testFile, 0, testFileLength);
        offset = 0;
        while ((read = segFIS.read()) != -1) {
            assertEquals("Read unexpected byte at offset " + offset,
                (offset % 256), read);
            offset++;
        }
        segFIS.close();

        // Read an offset segment of file
        offset = 1234;
        segFIS = new SegmentedRepeatableFileInputStream(
            testFile, offset, testFileLength - offset);
        while ((read = segFIS.read()) != -1) {
            assertEquals("Read unexpected byte at offset " + offset,
                (offset % 256), read);
            offset++;
        }
        segFIS.close();

        // Set a mark point, read from it, then reset to that point.
        segFIS = new SegmentedRepeatableFileInputStream(
            testFile, 0, testFileLength);
        int targetOffset = 12345;
        offset = 0;
        while (offset < targetOffset && (read = segFIS.read()) != -1) {
            offset++;
        }
        assertEquals("Couldn't read up to target offset", targetOffset, offset);
        assertEquals("Unexpected amount of data available",
            testFileLength - targetOffset, segFIS.available());
        segFIS.mark(0);
        while ((read = segFIS.read()) != -1) {
            assertEquals("Read unexpected byte at offset " + offset,
                (offset % 256), read);
            offset++;
        }
        segFIS.reset();
        assertEquals("Unexpected amount of data available",
            testFileLength - targetOffset, segFIS.available());
        offset = targetOffset;
        while ((read = segFIS.read()) != -1) {
            assertEquals("Read unexpected byte at offset " + offset,
                (offset % 256), read);
            offset++;
        }
        assertEquals("Didn't read expected number of bytes after reset",
            testFileLength, offset);
        segFIS.close();


        // Multiple overlapping segments...
        int[] offsets = new int[] { 0, 1000, 1080, 3500};
        long[] expectedBytesRead = new long[] { 1234, 2000, 3000, 1 };
        int i = 0;
        SegmentedRepeatableFileInputStream[] segFISs =
            new SegmentedRepeatableFileInputStream[offsets.length];
        for (i = 0; i < segFISs.length; i++) {
            segFISs[i] = new SegmentedRepeatableFileInputStream(
                testFile, offsets[i], expectedBytesRead[i]);
        };

        // Test correct bytes read, and correct segment lengths read
        for (i = 0; i < segFISs.length; i++) {
            segFIS = segFISs[i];
            offset = offsets[i];
            byteCount = 0;
            while ((read = segFIS.read()) != -1) {
                assertEquals("Read unexpected byte at offset " + offset,
                    (offset % 256), read);
                offset++;
                byteCount++;
            }
            assertEquals("Didn't read expected segment length for segment " + i,
                expectedBytesRead[i], byteCount);
            segFIS.close();
        }
    }

}
