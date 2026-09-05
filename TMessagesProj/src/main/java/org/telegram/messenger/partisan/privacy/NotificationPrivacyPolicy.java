package org.telegram.messenger.partisan.privacy;

import android.app.Notification;

public final class NotificationPrivacyPolicy {
    public static final int STANDARD = 0;
    public static final int REDACT_ON_LOCK_SCREEN = 1;
    public static final int ALWAYS_REDACT = 2;

    private NotificationPrivacyPolicy() {
    }

    public static boolean shouldRedactContent(int mode, boolean passcodeRequired, boolean fakePasscodeActive) {
        return mode == ALWAYS_REDACT || passcodeRequired || fakePasscodeActive;
    }

    public static int getNotificationVisibility(int mode) {
        switch (mode) {
            case ALWAYS_REDACT:
                return Notification.VISIBILITY_SECRET;
            case REDACT_ON_LOCK_SCREEN:
                return Notification.VISIBILITY_PRIVATE;
            case STANDARD:
            default:
                return Notification.VISIBILITY_PUBLIC;
        }
    }
}
