package io.serein.chat;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;

/** Lightweight first-party chat wallpaper; no remote images or UI assets. */
final class SereinChatWallpaper extends Drawable {
    private final int lineColor;
    private final float density;
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

    SereinChatWallpaper(Context context) {
        density = context.getResources().getDisplayMetrics().density;
        lineColor = SereinUi.isDark(context) ? 0xFF17262E : 0xFFDCDAD2;
        paint.setColor(lineColor);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(Math.max(1f, density));
        paint.setStrokeCap(Paint.Cap.ROUND);
        paint.setStrokeJoin(Paint.Join.ROUND);
    }

    @Override public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        if (bounds.isEmpty()) return;
        int save = canvas.save();
        canvas.clipRect(bounds);
        float step = 88f * density;
        float r = 16f * density;
        for (float y = bounds.top - step; y < bounds.bottom + step; y += step) {
            for (float x = bounds.left - step; x < bounds.right + step; x += step) {
                int variant = (Math.round(x / step) * 7 + Math.round(y / step) * 11) & 3;
                float ox = variant * 9f * density;
                if (variant == 0) {
                    canvas.drawRoundRect(x + ox, y + 12*density, x + ox + 34*density, y + 34*density, 7*density, 7*density, paint);
                    canvas.drawCircle(x + ox + 12*density, y + 23*density, 1.2f*density, paint);
                    canvas.drawCircle(x + ox + 18*density, y + 23*density, 1.2f*density, paint);
                    canvas.drawCircle(x + ox + 24*density, y + 23*density, 1.2f*density, paint);
                } else if (variant == 1) {
                    canvas.drawCircle(x + ox + r, y + r, r, paint);
                    canvas.drawArc(x + ox + 5*density, y + 5*density, x + ox + 28*density, y + 28*density, 25, 285, false, paint);
                    canvas.drawLine(x + ox + 22*density, y + 22*density, x + ox + 29*density, y + 29*density, paint);
                } else if (variant == 2) {
                    Path star = new Path();
                    star.moveTo(x + ox + 15*density, y + 5*density);
                    star.lineTo(x + ox + 18*density, y + 12*density);
                    star.lineTo(x + ox + 26*density, y + 15*density);
                    star.lineTo(x + ox + 18*density, y + 18*density);
                    star.lineTo(x + ox + 15*density, y + 26*density);
                    star.lineTo(x + ox + 12*density, y + 18*density);
                    star.lineTo(x + ox + 4*density, y + 15*density);
                    star.lineTo(x + ox + 12*density, y + 12*density);
                    star.close();
                    canvas.drawPath(star, paint);
                } else {
                    canvas.drawOval(x + ox + 4*density, y + 9*density, x + ox + 30*density, y + 27*density, paint);
                    canvas.drawLine(x + ox + 17*density, y + 9*density, x + ox + 17*density, y + 27*density, paint);
                }
            }
        }
        canvas.restoreToCount(save);
    }

    @Override public void setAlpha(int alpha) { paint.setAlpha(alpha); invalidateSelf(); }
    @Override public void setColorFilter(ColorFilter colorFilter) { paint.setColorFilter(colorFilter); invalidateSelf(); }
    @Override public int getOpacity() { return android.graphics.PixelFormat.TRANSLUCENT; }
}
