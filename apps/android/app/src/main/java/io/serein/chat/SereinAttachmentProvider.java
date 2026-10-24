package io.serein.chat;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

/** Narrow, non-exported read-only provider for OS file-open intents. */
public final class SereinAttachmentProvider extends ContentProvider {
    private static final String PATH = "download";

    static Uri uriFor(Context context, File file) throws IOException {
        File root = SereinAttachmentStore.directory(context).getCanonicalFile();
        File safe = file.getCanonicalFile();
        if (!safe.isFile() || !root.equals(safe.getParentFile()) || safe.getName().startsWith(".")
                || safe.getName().endsWith(".part")) {
            throw new FileNotFoundException("Attachment path is outside Serein downloads.");
        }
        return new Uri.Builder().scheme("content").authority(context.getPackageName() + ".attachments")
                .appendPath(PATH).appendPath(safe.getName()).build();
    }

    private File resolve(Uri uri) throws FileNotFoundException {
        if (getContext() == null) throw new FileNotFoundException("Serein is unavailable.");
        List<String> parts = uri.getPathSegments();
        if (parts.size() != 2 || !PATH.equals(parts.get(0))) throw new FileNotFoundException("Invalid attachment URI.");
        try {
            File root = SereinAttachmentStore.directory(getContext()).getCanonicalFile();
            File file = new File(root, parts.get(1)).getCanonicalFile();
            if (!file.isFile() || !file.getPath().startsWith(root.getPath() + File.separator)
                    || file.getName().endsWith(".part") || file.getName().equals(".nomedia")) {
                throw new FileNotFoundException("Downloaded attachment not found.");
            }
            return file;
        } catch (IOException error) {
            FileNotFoundException missing = new FileNotFoundException("Downloaded attachment is unavailable.");
            missing.initCause(error);
            throw missing;
        }
    }

    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri uri) {
        String extension = MimeTypeMap.getFileExtensionFromUrl(uri.getLastPathSegment());
        String mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension == null ? "" : extension.toLowerCase(java.util.Locale.ROOT));
        return mime == null ? "application/octet-stream" : mime;
    }
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file;
        try { file = resolve(uri); } catch (FileNotFoundException missing) { return null; }
        String[] columns = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        MatrixCursor cursor = new MatrixCursor(columns, 1);
        Object[] values = new Object[columns.length];
        for (int i=0; i<columns.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) values[i] = file.getName();
            else if (OpenableColumns.SIZE.equals(columns[i])) values[i] = file.length();
        }
        cursor.addRow(values);
        return cursor;
    }
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Downloaded attachments are read-only in external apps.");
        return ParcelFileDescriptor.open(resolve(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException("Read-only provider"); }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { throw new UnsupportedOperationException("Read-only provider"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { throw new UnsupportedOperationException("Read-only provider"); }
}
