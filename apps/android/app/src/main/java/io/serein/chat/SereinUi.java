package io.serein.chat;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.EditText;

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
    static int dp(Context c, float v) { return (int)(v * c.getResources().getDisplayMetrics().density + 0.5f); }
    static GradientDrawable shape(Context c, int color, int radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(c, radius)); return d;
    }
    static LinearLayout column(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.VERTICAL); return l; }
    static LinearLayout row(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    static TextView text(Context c, String value, float size, int color, boolean bold) {
        TextView t = new TextView(c); t.setText(value); t.setTextSize(size); t.setTextColor(color); if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD); return t;
    }
    static TextView label(Context c, String value) { TextView t=text(c,value,10,muted(c),true); t.setLetterSpacing(.12f); return t; }
    static Button button(Context c, String value, boolean primary) {
        Button b = new Button(c); b.setText(value); b.setAllCaps(false); b.setTextSize(12); b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        b.setTextColor(primary ? (isDark(c) ? 0xFF0B201A : WHITE) : text(c));
        b.setBackground(shape(c, primary ? accent(c) : surface(c), 12)); b.setPadding(dp(c,16),dp(c,8),dp(c,16),dp(c,8)); return b;
    }
    static EditText field(Context c, String hint, boolean password) {
        EditText e = new EditText(c); e.setSingleLine(true); e.setTextSize(12); e.setHint(hint); e.setHintTextColor(muted(c)); e.setTextColor(text(c)); e.setPadding(dp(c,12),0,dp(c,12),0); e.setBackground(shape(c,surface(c),10));
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
