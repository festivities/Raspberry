package dev.raspberry;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * Receives raspberry://auth from the browser (manifest: Theme.NoDisplay, VIEW+BROWSABLE).
 * Hands the URI to the live attempt in this process, then brings the game activity back,
 * clearing the Custom Tab above it. The URI never reaches the game activity, which logs
 * its intent data remotely.
 */
public final class AuthReturn extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Intent in = getIntent();
        Raspberry.onAuthReturn(in == null ? null : in.getData());
        try {
            Intent game = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (game != null) {
                game.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                startActivity(game);
            }
        } catch (RuntimeException ignored) {
            // the player can still switch back by hand
        }
        finish();
    }
}
