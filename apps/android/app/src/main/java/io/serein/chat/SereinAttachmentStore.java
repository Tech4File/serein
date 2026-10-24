package io.serein.chat;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.widget.Toast;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

/**
 * App-managed downloaded attachments. Android's app media directory is under
 * Android/media/<application-id>; no broad storage permission is requested.
 * The provider grants a temporary read URI only when the user opens a file.
 */
final class SereinAttachmentStore {
    private static final String APP_FOLDER = "Serein/Downloads";
    private static final long MAX_DOWNLOAD_BYTES = 64L * 1024L * 1024L;
    private static volatile File cachedDirectory;
    private SereinAttachmentStore() {}

    @SuppressWarnings("deprecation")
    static File directory(Context context) throws IOException {
        File cached = cachedDirectory;
        if (cached != null) {
            try { if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState(cached)) && cached.isDirectory()) return cached; }
            catch (Exception ignored) { }
        }
        File[] roots = context.getExternalMediaDirs();
        if (roots != null) {
            for (File root : roots) {
                if (root == null) continue;
                String state;
                try { state = Environment.getExternalStorageState(root); }
                catch (Exception ignored) { state = Environment.getExternalStorageState(); }
                if (!Environment.MEDIA_MOUNTED.equals(state)) continue;
                File directory = new File(root, APP_FOLDER);
                if ((!directory.isDirectory() && !directory.mkdirs()) || !directory.isDirectory()) continue;
                File marker = new File(directory, ".nomedia");
                if (!marker.exists()) try { marker.createNewFile(); } catch (IOException ignored) { }
                cachedDirectory = directory.getCanonicalFile();
                return cachedDirectory;
            }
        }
        throw new IOException("Serein media storage is not currently available.");
    }

    private static String safeName(String filename) {
        String source = filename == null ? "attachment" : filename;
        StringBuilder clean = new StringBuilder(Math.min(source.length(), 150));
        for (int i = 0; i < source.length() && clean.codePointCount(0, clean.length()) < 150;) {
            int codePoint = source.codePointAt(i);
            i += Character.charCount(codePoint);
            clean.appendCodePoint(codePoint == '/' || codePoint == '\\' || Character.isISOControl(codePoint) ? '_' : codePoint);
        }
        String name = clean.toString().trim();
        while (name.startsWith(".")) name = name.substring(1);
        return name.isEmpty() ? "attachment" : name;
    }

    private static String stableName(String transferId, String filename) {
        try { return UUID.fromString(transferId).toString() + "_" + safeName(filename); }
        catch (Exception invalid) { throw new IllegalArgumentException("Invalid transfer identifier."); }
    }

    static void cleanTemporaryFiles(Context context) {
        long cutoff = System.currentTimeMillis() - 24L * 60L * 60L * 1000L;
        cleanPrefix(context.getCacheDir(), new String[]{"serein-clear-", "serein-upload-"}, cutoff);
        try { cleanPrefix(directory(context), new String[]{"."}, cutoff); } catch (Exception ignored) { }
    }

    private static void cleanPrefix(File directory, String[] prefixes, long cutoff) {
        File[] files = directory == null ? null : directory.listFiles();
        if (files == null) return;
        for (File file : files) {
            String name = file.getName();
            boolean matches = false;
            for (String prefix : prefixes) if (name.startsWith(prefix)) { matches = true; break; }
            if (matches && (!".".equals(prefixes[prefixes.length - 1]) || name.endsWith(".part"))
                    && file.isFile() && file.lastModified() > 0 && file.lastModified() < cutoff) file.delete();
        }
    }

    static File existing(Context context, String transferId, String filename, long expectedBytes) {
        try {
            if (expectedBytes < 0 || expectedBytes > MAX_DOWNLOAD_BYTES) return null;
            File root = directory(context);
            File file = new File(root, stableName(transferId, filename)).getCanonicalFile();
            return file.getPath().startsWith(root.getPath() + File.separator) && file.isFile() && file.length() == expectedBytes ? file : null;
        } catch (Exception ignored) { return null; }
    }

    static File save(Context context, String transferId, String filename, InputStream source, long expectedBytes) throws IOException {
        if (source == null || expectedBytes < 0 || expectedBytes > MAX_DOWNLOAD_BYTES) throw new IOException("Attachment data is unavailable or exceeds the allowed size.");
        File root = directory(context);
        File destination = new File(root, stableName(transferId, filename)).getCanonicalFile();
        if (!destination.getPath().startsWith(root.getPath() + File.separator)) throw new IOException("Invalid attachment path.");
        File partial = new File(root, "." + UUID.randomUUID().toString() + ".part");
        long total = 0;
        byte[] buffer = new byte[64 * 1024];
        try (InputStream in = source; FileOutputStream out = new FileOutputStream(partial, false)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > expectedBytes) throw new IOException("Attachment exceeds its authenticated size.");
                out.write(buffer, 0, read);
            }
            out.flush();
            out.getFD().sync();
        } catch (IOException error) {
            // Do not leave incomplete plaintext behind after a failed save.
            //noinspection ResultOfMethodCallIgnored
            partial.delete();
            throw error;
        }
        if (total != expectedBytes) {
            //noinspection ResultOfMethodCallIgnored
            partial.delete();
            throw new IOException("Downloaded file size did not match its authenticated manifest.");
        }
        try {
            try {
                Files.move(partial.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(partial.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException error) {
            //noinspection ResultOfMethodCallIgnored
            partial.delete();
            throw new IOException("The downloaded file could not be finalized.", error);
        }
        return destination;
    }

    static void open(Activity activity, File file, String mimeType) throws IOException {
        if (activity == null || file == null || !file.isFile()) throw new IOException("Downloaded attachment is unavailable.");
        Uri uri = SereinAttachmentProvider.uriFor(activity, file);
        String type = mimeType == null || mimeType.trim().isEmpty() ? "application/octet-stream" : mimeType;
        Intent view = new Intent(Intent.ACTION_VIEW);
        view.setDataAndType(uri, type);
        view.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { activity.startActivity(Intent.createChooser(view, "Open downloaded file")); }
        catch (ActivityNotFoundException error) { Toast.makeText(activity, "No installed app can open this file type.", Toast.LENGTH_LONG).show(); }
    }

    static Uri uriFor(Context context, File file) throws IOException {
        return SereinAttachmentProvider.uriFor(context, file);
    }
}
