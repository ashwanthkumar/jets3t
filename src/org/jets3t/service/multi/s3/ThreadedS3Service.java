package org.jets3t.service.multi.s3;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.S3Service;
import org.jets3t.service.ServiceException;
import org.jets3t.service.io.BytesProgressWatcher;
import org.jets3t.service.io.InterruptableInputStream;
import org.jets3t.service.io.ProgressMonitoredInputStream;
import org.jets3t.service.io.TempFile;
import org.jets3t.service.model.MultipartUpload;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.multi.StorageServiceEventListener;
import org.jets3t.service.multi.ThreadWatcher;
import org.jets3t.service.multi.ThreadedStorageService;
import org.jets3t.service.multi.event.ServiceEvent;

public class ThreadedS3Service extends ThreadedStorageService {
    private static final Log log = LogFactory.getLog(ThreadedS3Service.class);

    public ThreadedS3Service(S3Service service, StorageServiceEventListener listener)
        throws ServiceException
    {
        super(service, listener);
    }

    @Override
    protected void fireServiceEvent(ServiceEvent event) {
        if (serviceEventListeners.size() == 0) {
            if (log.isWarnEnabled()) {
                log.warn("ThreadedS3Service invoked without any StorageServiceEventListener objects, this is dangerous!");
            }
        }
        for (StorageServiceEventListener listener: this.serviceEventListeners) {
            if (event instanceof MultipartUploadsEvent) {
                if (listener instanceof S3ServiceEventListener) {
                    ((S3ServiceEventListener)listener).event((MultipartUploadsEvent) event);
                }
            } else {
                super.fireServiceEvent(event);
            }
        }
    }

    /**
     * Uploads multiple objects that will constitute a single final object,
     * and sends {@link MultipartUploadsEvent} notification events.
     * <p>
     * The maximum number of threads is controlled by the JetS3t configuration property
     * <tt>threaded-service.max-admin-thread-count</tt>.
     *
     * @param multipartUpload
     * identifies an existing multipart upload to which the parts will be added.
     * @param partObjects
     * an ordered list of objects representing the part data to upload.
     * @param partNumberOffset
     * an offset (1 or greater) used as the starting-point for part numbers uploaded by
     * this method, useful if you need to make multiple calls to append parts to a
     * multipart upload.
     *
     * @return
     * true if all the threaded tasks completed successfully, false otherwise.
     */
    public boolean multipartUploadParts(List<MultipartUploadAndParts> uploadAndPartsList)
    {
        if (!(storageService instanceof S3Service)) {
            throw new IllegalStateException(
                "Multipart uploads are only available in Amazon S3, " +
                "you must use the S3Service implementation of StorageService");
        }
        final List<StorageObject> incompletedObjectsList = new ArrayList<StorageObject>();
        final List<BytesProgressWatcher> progressWatchers = new ArrayList<BytesProgressWatcher>();
        final Object uniqueOperationId = new Object(); // Special object used to identify this operation.
        final boolean[] success = new boolean[] {true};

        // Start all queries in the background.
        List<MultipartUploadObjectRunnable> runnableList =
            new ArrayList<MultipartUploadObjectRunnable>();
        for (MultipartUploadAndParts multipartUploadAndParts: uploadAndPartsList) {
            int partNumber = multipartUploadAndParts.getPartNumberOffset();
            for (S3Object partObject: multipartUploadAndParts.getPartObjects()) {
                incompletedObjectsList.add(partObject);
                BytesProgressWatcher progressMonitor = new BytesProgressWatcher(partObject.getContentLength());
                runnableList.add(new MultipartUploadObjectRunnable(
                    multipartUploadAndParts.getMultipartUpload(),
                    partNumber, partObject, progressMonitor));
                progressWatchers.add(progressMonitor);
                partNumber++;
            }
        }

        // Wait for threads to finish, or be canceled.
        ThreadWatcher threadWatcher = new ThreadWatcher(
            progressWatchers.toArray(new BytesProgressWatcher[progressWatchers.size()]));
        (new ThreadGroupManager(runnableList.toArray(new MultipartUploadObjectRunnable[] {}),
            threadWatcher, this.storageService.getJetS3tProperties(), false)
        {
            @Override
            public void fireStartEvent(ThreadWatcher threadWatcher) {
                fireServiceEvent(MultipartUploadsEvent.newStartedEvent(threadWatcher, uniqueOperationId));
            }
            @Override
            public void fireProgressEvent(ThreadWatcher threadWatcher, List completedResults) {
                incompletedObjectsList.removeAll(completedResults);
                StorageObject[] completedObjects = (StorageObject[]) completedResults
                    .toArray(new StorageObject[completedResults.size()]);
                fireServiceEvent(MultipartUploadsEvent.newInProgressEvent(threadWatcher,
                    completedObjects, uniqueOperationId));
            }
            @Override
            public void fireCancelEvent() {
                StorageObject[] incompletedObjects = incompletedObjectsList
                    .toArray(new StorageObject[incompletedObjectsList.size()]);
                success[0] = false;
                fireServiceEvent(MultipartUploadsEvent.newCancelledEvent(incompletedObjects, uniqueOperationId));
            }
            @Override
            public void fireCompletedEvent() {
                fireServiceEvent(MultipartUploadsEvent.newCompletedEvent(uniqueOperationId));
            }
            @Override
            public void fireErrorEvent(Throwable throwable) {
                success[0] = false;
                fireServiceEvent(MultipartUploadsEvent.newErrorEvent(throwable, uniqueOperationId));
            }
            @Override
            public void fireIgnoredErrorsEvent(ThreadWatcher threadWatcher, Throwable[] ignoredErrors) {
                success[0] = false;
                fireServiceEvent(MultipartUploadsEvent.newIgnoredErrorsEvent(threadWatcher, ignoredErrors, uniqueOperationId));
            }
        }).run();

        return success[0];
    }

    /**
     * Thread for creating/uploading an object that is part of a single multipart object.
     * The upload of any object data is monitored with a
     * {@link ProgressMonitoredInputStream} and can be can cancelled as the input stream is wrapped in
     * an {@link InterruptableInputStream}.
     */
    private class MultipartUploadObjectRunnable extends AbstractRunnable {
        private MultipartUpload multipartUpload = null;
        private Integer partNumber = null;
        private S3Object object = null;
        private InterruptableInputStream interruptableInputStream = null;
        private BytesProgressWatcher progressMonitor = null;

        private Object result = null;

        public MultipartUploadObjectRunnable(MultipartUpload multipartUpload,
            Integer partNumber, S3Object object, BytesProgressWatcher progressMonitor)
        {
            this.multipartUpload = multipartUpload;
            this.partNumber = partNumber;
            this.object = object;
            this.progressMonitor = progressMonitor;
        }

        public void run() {
            try {
                File underlyingFile = object.getDataInputFile();

                if (object.getDataInputStream() != null) {
                    interruptableInputStream = new InterruptableInputStream(object.getDataInputStream());
                    ProgressMonitoredInputStream pmInputStream = new ProgressMonitoredInputStream(
                        interruptableInputStream, progressMonitor);
                    object.setDataInputStream(pmInputStream);
                }
                ((S3Service)storageService).multipartUploadPart(
                    multipartUpload, partNumber, object);
                result = object;

                if (underlyingFile instanceof TempFile) {
                    underlyingFile.delete();
                }
            } catch (ServiceException e) {
                result = e;
            }
        }

        @Override
        public Object getResult() {
            return result;
        }

        @Override
        public void forceInterruptCalled() {
            if (interruptableInputStream != null) {
                interruptableInputStream.interrupt();
            }
        }
    }

}
