package io.serein.chat;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;

/** Local foreground-sync notifications; there is no background push service yet. */
final class SereinNotifications {
    private static final String CHANNEL_SOUND = "serein_messages_sound_v1";
    private static final String CHANNEL_SILENT = "serein_messages_silent_v1";
    private static final String CHANNEL_BACKUP = "serein_backup_v1";
    private static final int BACKUP_NOTIFICATION_ID = 9182;
    private static final String PREFS = "serein";
    private SereinNotifications() { }

    static void ensureChannels(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;
        NotificationChannel sound = new NotificationChannel(CHANNEL_SOUND, "Messages · sound", NotificationManager.IMPORTANCE_DEFAULT);
        NotificationChannel silent = new NotificationChannel(CHANNEL_SILENT, "Messages · silent", NotificationManager.IMPORTANCE_DEFAULT);
        silent.setSound(null, null);
        manager.createNotificationChannel(sound);
        manager.createNotificationChannel(silent);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL_BACKUP, "Backups", NotificationManager.IMPORTANCE_LOW));
    }

    static boolean permissionGranted(Context context) {
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null && !manager.areNotificationsEnabled()) return false;
        return Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
    }

    static void showBackupProgress(Context context,String stage,boolean complete,boolean failed) {
        android.content.SharedPreferences preferences=context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);
        if(!preferences.getBoolean("notifications_enabled",false)||!permissionGranted(context))return;
        ensureChannels(context);NotificationManager manager=(NotificationManager)context.getSystemService(Context.NOTIFICATION_SERVICE);if(manager==null)return;
        String title=failed?"Serein backup failed":complete?"Serein backup ready":"Serein backup in progress";
        Notification.Builder builder=new Notification.Builder(context,CHANNEL_BACKUP).setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle(title).setContentText(stage).setVisibility(Notification.VISIBILITY_PRIVATE).setOnlyAlertOnce(true)
                .setOngoing(!complete&&!failed).setAutoCancel(complete||failed);
        if(!complete&&!failed)builder.setProgress(0,0,true);
        try{manager.notify(BACKUP_NOTIFICATION_ID,builder.build());}catch(SecurityException ignored){ }
    }
    static void clearBackupProgress(Context context){NotificationManager manager=(NotificationManager)context.getSystemService(Context.NOTIFICATION_SERVICE);if(manager!=null)manager.cancel(BACKUP_NOTIFICATION_ID);}

    static void showIncoming(Context context, boolean soundEnabled) {
        android.content.SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        if (!preferences.getBoolean("notifications_enabled", false) || !permissionGranted(context)) return;
        ensureChannels(context);
        NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;
        Intent intent = new Intent(context, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pending = PendingIntent.getActivity(context, 9101, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        String channel = soundEnabled ? CHANNEL_SOUND : CHANNEL_SILENT;
        Notification.Builder builder = new Notification.Builder(context, channel);
        builder.setSmallIcon(android.R.drawable.ic_dialog_email)
                .setContentTitle("New encrypted message")
                .setContentText("You have a new encrypted message in Serein.")
                .setContentIntent(pending)
                .setAutoCancel(true)
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setVisibility(Notification.VISIBILITY_PRIVATE);
        try { manager.notify((int) (System.nanoTime() & 0x7fffffff), builder.build()); }
        catch (SecurityException ignored) { /* Settings may have revoked permission during the sync. */ }
    }
}
