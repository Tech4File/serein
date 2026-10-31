package io.serein.chat;

import android.app.AlertDialog;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.content.res.ColorStateList;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.EditText;
import android.widget.ImageButton;

/** Small first-party native UI kit. No design-system dependency. */
final class SereinUi {
    private SereinUi() {}
    static final int GREEN = SereinTokens.GREEN;
    static final int DARK_GREEN = SereinTokens.DARK_GREEN;
    static final int WHITE = SereinTokens.WHITE;
    static final int MUTED = SereinTokens.MUTED;
    static final int DARK_MUTED = SereinTokens.DARK_MUTED;
    static boolean isDark(Context c) {
        String choice = c.getSharedPreferences("serein", 0).getString("theme", "system");
        if ("dark".equals(choice)) return true;
        if ("light".equals(choice)) return false;
        int mode = c.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return mode == Configuration.UI_MODE_NIGHT_YES;
    }
    static int bg(Context c) { return isDark(c) ? SereinTokens.BG_DARK : SereinTokens.BG_LIGHT; }
    static int surface(Context c) { return isDark(c) ? SereinTokens.SURFACE_DARK : SereinTokens.SURFACE_LIGHT; }
    static int text(Context c) { return isDark(c) ? SereinTokens.TEXT_DARK : SereinTokens.TEXT_LIGHT; }
    static int muted(Context c) { return isDark(c) ? DARK_MUTED : MUTED; }
    static int accent(Context c) { return isDark(c) ? DARK_GREEN : GREEN; }
    static int chatBackground(Context c) { return isDark(c) ? 0xFF0B141A : 0xFFECEAE2; }
    static int chatIncoming(Context c) { return isDark(c) ? 0xFF202C33 : 0xFFFFFFFF; }
    static int chatOutgoing(Context c) { return isDark(c) ? 0xFF075E54 : 0xFFD9F5DF; }
    static int chatBubbleText(Context c, boolean own) { return own && isDark(c) ? 0xFFF2F7F4 : text(c); }
    static GradientDrawable chatBubble(Context c, boolean own) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(own ? chatOutgoing(c) : chatIncoming(c));
        float large = dp(c, 16), small = dp(c, 5);
        d.setCornerRadii(own
            ? new float[]{large,large,large,large,small,small,large,large}
            : new float[]{large,large,large,large,large,large,small,small});
        return d;
    }
    static int dp(Context c, float v) { return (int)(v * c.getResources().getDisplayMetrics().density + 0.5f); }
    static void showStyledDialog(AlertDialog dialog,boolean destructive) {
        dialog.show();Context c=dialog.getContext();if(dialog.getWindow()!=null)dialog.getWindow().setBackgroundDrawable(shape(c,surface(c),SereinTokens.DIALOG_RADIUS_DP));
        Button positive=dialog.getButton(AlertDialog.BUTTON_POSITIVE);if(positive!=null){positive.setAllCaps(false);positive.setTypeface(Typeface.DEFAULT,Typeface.BOLD);positive.setTextColor(destructive?(isDark(c)?0xFFFF9A9A:0xFFA84347):accent(c));}
        Button negative=dialog.getButton(AlertDialog.BUTTON_NEGATIVE);if(negative!=null){negative.setAllCaps(false);negative.setTypeface(Typeface.DEFAULT,Typeface.BOLD);negative.setTextColor(muted(c));}
    }
    static float fontSize(Context c, float size) { String scale=c.getSharedPreferences("serein",0).getString("font_scale","system"); float factor=SereinTokens.FONT_SCALE_LARGE; if("extra_large".equals(scale))factor=SereinTokens.FONT_SCALE_EXTRA_LARGE;else if(!"large".equals(scale))factor=1f; return Math.max(SereinTokens.MIN_FONT_SIZE_SP,size*factor); }
    static GradientDrawable shape(Context c, int color, int radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(c, radius)); return d;
    }
    static LinearLayout column(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.VERTICAL); return l; }
    static LinearLayout row(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    static TextView text(Context c, String value, float size, int color, boolean bold) {
        TextView t = new TextView(c); t.setText(value); t.setTextSize(fontSize(c,size)); t.setTextColor(color); if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD); return t;
    }
    static TextView label(Context c, String value) { TextView t=text(c,value,10,muted(c),true); t.setLetterSpacing(.12f); return t; }
    static Button button(Context c, String value, boolean primary) {
        Button b = new Button(c); b.setText(value); b.setAllCaps(false); b.setTextSize(fontSize(c,12)); b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        b.setTextColor(primary ? (isDark(c) ? 0xFF0B201A : WHITE) : text(c));
        b.setBackground(shape(c, primary ? accent(c) : surface(c), SereinTokens.BUTTON_RADIUS_DP));
        b.setMinHeight(dp(c,SereinTokens.BUTTON_HEIGHT_DP)); b.setPadding(dp(c,16),dp(c,8),dp(c,16),dp(c,8)); return b;
    }
    static Button iconButton(Context c,String value,String description) {
        Button b=new Button(c);b.setText(value);b.setAllCaps(false);b.setTextSize(fontSize(c,18));b.setTypeface(Typeface.DEFAULT,Typeface.BOLD);b.setGravity(Gravity.CENTER);b.setContentDescription(description);
        GradientDrawable background=shape(c,isDark(c)?SereinTokens.ACCENT_SOFT_DARK:SereinTokens.ACCENT_SOFT_LIGHT,SereinTokens.BUTTON_RADIUS_DP);background.setStroke(dp(c,1),isDark(c)?SereinTokens.BORDER_DARK:SereinTokens.BORDER_LIGHT);b.setBackground(background);
        b.setTextColor(accent(c));b.setMinWidth(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));b.setMinHeight(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));b.setPadding(0,0,0,0);return b;
    }
    static ImageButton composerIconButton(Context c,int icon, String description, boolean primary) {
        ImageButton button=new ImageButton(c);button.setContentDescription(description);button.setFocusable(true);button.setScaleType(android.widget.ImageView.ScaleType.CENTER);button.setPadding(0,0,0,0);
        int fill=primary?accent(c):(isDark(c)?SereinTokens.ACCENT_SOFT_DARK:SereinTokens.ACCENT_SOFT_LIGHT);
        GradientDrawable base=shape(c,fill,14);if(!primary)base.setStroke(dp(c,1),isDark(c)?SereinTokens.BORDER_DARK:SereinTokens.BORDER_LIGHT);
        button.setBackground(new RippleDrawable(ColorStateList.valueOf(primary?0x33FFFFFF:(isDark(c)?0x337BCBB1:0x33187C68)),base,null));
        button.setImageResource(icon);button.setImageTintList(ColorStateList.valueOf(primary?WHITE:accent(c)));button.setMinimumWidth(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));button.setMinimumHeight(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));return button;
    }
    static Button chip(Context c,String value,boolean selected) {
        Button b=new Button(c);b.setText(value);b.setAllCaps(false);b.setTextSize(fontSize(c,11));b.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        b.setTextColor(selected?accent(c):muted(c));b.setMinHeight(dp(c,SereinTokens.CHIP_HEIGHT_DP));b.setPadding(dp(c,14),0,dp(c,14),0);
        GradientDrawable background=shape(c,selected?(isDark(c)?SereinTokens.ACCENT_SOFT_DARK:SereinTokens.ACCENT_SOFT_LIGHT):surface(c),SereinTokens.CHIP_HEIGHT_DP/2);
        background.setStroke(dp(c,1),selected?accent(c):(isDark(c)?SereinTokens.BORDER_DARK:SereinTokens.BORDER_LIGHT));b.setBackground(background);return b;
    }
    static View lockIconButton(Context c,String label) { return new LockIconButton(c,label); }
    private static final class LockIconButton extends View {
        private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        LockIconButton(Context c,String label){super(c);setContentDescription(label);setFocusable(true);setClickable(true);GradientDrawable background=shape(c,isDark(c)?SereinTokens.ACCENT_SOFT_DARK:SereinTokens.ACCENT_SOFT_LIGHT,SereinTokens.BUTTON_RADIUS_DP);background.setStroke(dp(c,1),isDark(c)?SereinTokens.BORDER_DARK:SereinTokens.BORDER_LIGHT);setBackground(new RippleDrawable(ColorStateList.valueOf(isDark(c)?0x337BCBB1:0x33187C68),background,null));setMinimumWidth(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));setMinimumHeight(dp(c,SereinTokens.ICON_BUTTON_SIZE_DP));}
        @Override protected void onDraw(Canvas canvas){super.onDraw(canvas);float unit=dp(getContext(),1),cx=getWidth()/2f,cy=getHeight()/2f;paint.setColor(accent(getContext()));paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(2.2f*unit);paint.setStrokeCap(Paint.Cap.ROUND);paint.setStrokeJoin(Paint.Join.ROUND);RectF body=new RectF(cx-7*unit,cy-1*unit,cx+7*unit,cy+9*unit);canvas.drawRoundRect(body,2*unit,2*unit,paint);Path shackle=new Path();shackle.moveTo(cx-4*unit,cy-1*unit);shackle.lineTo(cx-4*unit,cy-4*unit);shackle.quadTo(cx,cy-10*unit,cx+4*unit,cy-4*unit);shackle.lineTo(cx+4*unit,cy-1*unit);canvas.drawPath(shackle,paint);paint.setStyle(Paint.Style.FILL);canvas.drawCircle(cx,cy+3*unit,1.25f*unit,paint);paint.setStrokeWidth(1.5f*unit);canvas.drawLine(cx,cy+4*unit,cx,cy+6*unit,paint);}
    }
    static EditText field(Context c, String hint, boolean password) {
        EditText e = new EditText(c); e.setSingleLine(true); e.setTextSize(fontSize(c,12)); e.setHint(hint); e.setHintTextColor(muted(c)); e.setTextColor(text(c)); e.setPadding(dp(c,12),0,dp(c,12),0); e.setBackground(shape(c,surface(c),10));
        if (password) e.setInputType(129); return e;
    }
    static View divider(Context c) { View v = new View(c); v.setBackgroundColor(isDark(c)?SereinTokens.BORDER_DARK:SereinTokens.BORDER_LIGHT); return v; }
    static LinearLayout card(Context c) { LinearLayout l=column(c); l.setPadding(dp(c,16),dp(c,15),dp(c,16),dp(c,15)); l.setBackground(shape(c,surface(c),16)); return l; }
    static TextView avatar(Context c, String initials, int size) {
        TextView v=text(c,initials,size*.33f,WHITE,true);v.setGravity(Gravity.CENTER);v.setBackground(shape(c,isDark(c)?SereinTokens.DARK_GREEN:SereinTokens.GREEN,16));LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(dp(c,size),dp(c,size));v.setLayoutParams(lp);return v;
    }
    static LinearLayout.LayoutParams margin(Context c, int w, int h, int left, int top, int right, int bottom) {
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(w<0?w:dp(c,w),h<0?h:dp(c,h));p.setMargins(dp(c,left),dp(c,top),dp(c,right),dp(c,bottom));return p;
    }
}
