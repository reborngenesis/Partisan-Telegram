package org.telegram.tgnet.test

import android.app.Notification
import org.junit.Test
import org.telegram.messenger.partisan.privacy.NotificationPrivacyPolicy
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NotificationPrivacyPolicyTest {
    @Test
    fun allLockAndFakePasscodeCombinations() {
        val modes = intArrayOf(NotificationPrivacyPolicy.STANDARD,
                NotificationPrivacyPolicy.REDACT_ON_LOCK_SCREEN, NotificationPrivacyPolicy.ALWAYS_REDACT)
        val states = listOf(false to false, false to true, true to false, true to true)
        val expected = listOf(
                listOf(false, true, true, true),
                listOf(false, true, true, true),
                listOf(true, true, true, true))
        for ((modeIndex, mode) in modes.withIndex()) {
            for ((stateIndex, state) in states.withIndex()) {
                assertEquals(expected[modeIndex][stateIndex],
                        NotificationPrivacyPolicy.shouldRedactContent(mode, state.first, state.second),
                        "mode=$mode, passcode=${state.first}, fake=${state.second}")
            }
        }
    }

    @Test
    fun standardUnlockedIsPublicAndNotRedacted() {
        assertFalse(NotificationPrivacyPolicy.shouldRedactContent(
            NotificationPrivacyPolicy.STANDARD, false, false
        ))
        assertEquals(Notification.VISIBILITY_PUBLIC,
            NotificationPrivacyPolicy.getNotificationVisibility(NotificationPrivacyPolicy.STANDARD))
    }

    @Test
    fun standardPasscodeRequiredIsRedacted() {
        assertTrue(NotificationPrivacyPolicy.shouldRedactContent(
            NotificationPrivacyPolicy.STANDARD, true, false
        ))
    }

    @Test
    fun lockScreenModeKeepsUnlockedContentAndUsesPrivateVisibility() {
        assertFalse(NotificationPrivacyPolicy.shouldRedactContent(
            NotificationPrivacyPolicy.REDACT_ON_LOCK_SCREEN, false, false
        ))
        assertEquals(Notification.VISIBILITY_PRIVATE,
            NotificationPrivacyPolicy.getNotificationVisibility(NotificationPrivacyPolicy.REDACT_ON_LOCK_SCREEN))
    }

    @Test
    fun alwaysModeRedactsAndUsesSecretVisibility() {
        assertTrue(NotificationPrivacyPolicy.shouldRedactContent(
            NotificationPrivacyPolicy.ALWAYS_REDACT, false, false
        ))
        assertEquals(Notification.VISIBILITY_SECRET,
            NotificationPrivacyPolicy.getNotificationVisibility(NotificationPrivacyPolicy.ALWAYS_REDACT))
    }

    @Test
    fun fakePasscodeAlwaysRedacts() {
        val modes = intArrayOf(
            NotificationPrivacyPolicy.STANDARD,
            NotificationPrivacyPolicy.REDACT_ON_LOCK_SCREEN,
            NotificationPrivacyPolicy.ALWAYS_REDACT
        )
        for (mode in modes) {
            assertTrue(NotificationPrivacyPolicy.shouldRedactContent(mode, false, true))
        }
    }
}
