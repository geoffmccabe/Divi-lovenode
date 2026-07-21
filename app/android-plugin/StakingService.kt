// LoveNode — Android foreground service that keeps staking alive with the
// screen off. This is what makes "stake overnight" true on Android.
//
// AUTHORED, NOT YET COMPILED. Drop into the generated Android project. See
// app/README-ANDROID.md.
//
// ── Why a foreground service ────────────────────────────────────────────────
// Android suspends normal background work, which would drop the relay socket the
// moment the screen turns off. A foreground service with a persistent
// notification is the sanctioned way to keep a long-lived connection running.
//
// ── Play compliance (read before shipping) ──────────────────────────────────
// Android 14+ requires a declared foregroundServiceType that MATCHES real
// behaviour, and Play reviews it. `dataSync` is the honest fit here: the app
// maintains a synced connection to a server. Do NOT declare a type you don't use.
// Position the app as a non-custodial wallet with REMOTE staking — Play bans
// on-device mining but permits apps that remotely manage it, which is exactly
// this design (the relay searches; the phone only signs).

package love.divi.lovenode

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder

class StakingService : Service() {

    private val channelId = "lovenode_staking"
    private val notifId = 1

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(notifId, buildNotification("Staking — helping secure the Divi network"))
        // The Rust client loop is launched from the Tauri mobile entry point and
        // keeps running while this service holds the process alive. This service's
        // job is only to keep the process foregrounded; it does not itself sign.
        return START_STICKY // restart if the OS kills us
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Update the ongoing notification text (e.g. after a block is won). */
    fun updateStatus(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(notifId, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("LoveNode")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock) // replace with app icon
            .setOngoing(true)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Staking",
                NotificationManager.IMPORTANCE_LOW // quiet; it's an ongoing status
            )
            channel.description = "Shows while LoveNode is staking in the background"
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }
}

// AndroidManifest.xml additions (documented here so they aren't missed):
//
//   <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
//   <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
//   <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
//   <uses-permission android:name="android.permission.INTERNET" />
//
//   <service
//       android:name=".StakingService"
//       android:foregroundServiceType="dataSync"
//       android:exported="false" />
//
// Also request the battery-optimisation exemption at runtime so the OS does not
// doze the socket:
//   Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
