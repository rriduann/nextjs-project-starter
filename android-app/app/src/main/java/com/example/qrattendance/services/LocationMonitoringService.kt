package com.example.qrattendance.services

import android.app.*
import android.content.Context
import android.content.Intent
import android.location.Location
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.example.qrattendance.MainActivity
import com.example.qrattendance.R
import com.example.qrattendance.security.DeviceSecurityChecker
import com.example.qrattendance.security.LocationSecurityManager
import com.example.qrattendance.security.SecurityViolationHandler
import com.example.qrattendance.utils.SecureStorageManager
import kotlinx.coroutines.*

class LocationMonitoringService : LifecycleService() {
    
    companion object {
        private const val SERVICE_ID = 1000
        private const val CHANNEL_ID = "location_monitoring"
        private const val MONITORING_INTERVAL = 5000L // 5 seconds
        private const val SECURITY_CHECK_INTERVAL = 10000L // 10 seconds
        
        const val ACTION_START_MONITORING = "START_MONITORING"
        const val ACTION_STOP_MONITORING = "STOP_MONITORING"
    }
    
    private lateinit var locationSecurityManager: LocationSecurityManager
    private lateinit var deviceSecurityChecker: DeviceSecurityChecker
    private lateinit var securityViolationHandler: SecurityViolationHandler
    private lateinit var secureStorageManager: SecureStorageManager
    
    private var monitoringJob: Job? = null
    private var securityCheckJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null
    
    private var isMonitoring = false
    private var lastKnownLocation: Location? = null
    private var violationCount = 0
    private var lastSecurityCheck = 0L
    
    override fun onCreate() {
        super.onCreate()
        
        initializeComponents()
        createNotificationChannel()
        acquireWakeLock()
    }
    
    private fun initializeComponents() {
        locationSecurityManager = LocationSecurityManager(this)
        deviceSecurityChecker = DeviceSecurityChecker(this)
        securityViolationHandler = SecurityViolationHandler(this)
        secureStorageManager = SecureStorageManager(this)
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        
        when (intent?.action) {
            ACTION_START_MONITORING -> startLocationMonitoring()
            ACTION_STOP_MONITORING -> stopLocationMonitoring()
            else -> startLocationMonitoring()
        }
        
        return START_STICKY // Restart service if killed
    }
    
    private fun startLocationMonitoring() {
        if (isMonitoring) return
        
        isMonitoring = true
        startForeground(SERVICE_ID, createNotification("Starting location monitoring..."))
        
        // Start location monitoring coroutine
        monitoringJob = lifecycleScope.launch {
            while (isMonitoring) {
                try {
                    performLocationCheck()
                    delay(MONITORING_INTERVAL)
                } catch (e: Exception) {
                    handleMonitoringError(e)
                    delay(MONITORING_INTERVAL * 2) // Back off on error
                }
            }
        }
        
        // Start security check coroutine
        securityCheckJob = lifecycleScope.launch {
            while (isMonitoring) {
                try {
                    performSecurityCheck()
                    delay(SECURITY_CHECK_INTERVAL)
                } catch (e: Exception) {
                    handleSecurityCheckError(e)
                    delay(SECURITY_CHECK_INTERVAL * 2) // Back off on error
                }
            }
        }
    }
    
    private suspend fun performLocationCheck() {
        val currentLocation = locationSecurityManager.getCurrentLocation()
        
        if (currentLocation != null) {
            // Check for mock location
            if (locationSecurityManager.isMockLocationActive()) {
                handleSecurityViolation(
                    SecurityViolationHandler.ViolationType.MOCK_LOCATION,
                    "Mock location detected during monitoring"
                )
                return
            }
            
            // Check location accuracy
            if (currentLocation.accuracy > 100) {
                updateNotification("⚠️ Low GPS accuracy: ${currentLocation.accuracy}m")
            } else {
                updateNotification("✓ Monitoring active - Accuracy: ${currentLocation.accuracy.toInt()}m")
            }
            
            // Check for impossible movement
            lastKnownLocation?.let { lastLocation ->
                if (isMovementImpossible(lastLocation, currentLocation)) {
                    handleSecurityViolation(
                        SecurityViolationHandler.ViolationType.IMPOSSIBLE_MOVEMENT,
                        "Impossible movement detected: ${calculateSpeed(lastLocation, currentLocation)} km/h"
                    )
                }
            }
            
            // Check geofence
            if (!locationSecurityManager.isLocationWithinGeofence(currentLocation)) {
                handleSecurityViolation(
                    SecurityViolationHandler.ViolationType.LOCATION_OUTSIDE_GEOFENCE,
                    "Location outside allowed area"
                )
            }
            
            // Validate IP geolocation
            if (!locationSecurityManager.validateIpGeolocation()) {
                handleSecurityViolation(
                    SecurityViolationHandler.ViolationType.NETWORK_MISMATCH,
                    "IP geolocation does not match GPS location"
                )
            }
            
            lastKnownLocation = currentLocation
            
        } else {
            updateNotification("⚠️ Unable to get location")
        }
    }
    
    private suspend fun performSecurityCheck() {
        val currentTime = System.currentTimeMillis()
        
        // Throttle security checks to avoid excessive processing
        if (currentTime - lastSecurityCheck < SECURITY_CHECK_INTERVAL) {
            return
        }
        
        lastSecurityCheck = currentTime
        
        // Check for VPN
        if (locationSecurityManager.isVpnActive()) {
            handleSecurityViolation(
                SecurityViolationHandler.ViolationType.VPN_DETECTED,
                "VPN connection detected during monitoring"
            )
        }
        
        // Check for newly installed mock location apps
        if (deviceSecurityChecker.isMockLocationAppInstalled()) {
            handleSecurityViolation(
                SecurityViolationHandler.ViolationType.MOCK_LOCATION,
                "Mock location app detected on device"
            )
        }
        
        // Check if developer options were enabled
        if (deviceSecurityChecker.isDeveloperOptionsEnabled()) {
            handleSecurityViolation(
                SecurityViolationHandler.ViolationType.DEBUGGING_ENABLED,
                "Developer options enabled during monitoring"
            )
        }
        
        // Periodic root check (less frequent due to performance impact)
        if (currentTime % (SECURITY_CHECK_INTERVAL * 6) == 0L) { // Every minute
            if (deviceSecurityChecker.isDeviceRooted()) {
                handleSecurityViolation(
                    SecurityViolationHandler.ViolationType.ROOT_ACCESS,
                    "Root access detected during monitoring"
                )
            }
        }
    }
    
    private fun isMovementImpossible(lastLocation: Location, currentLocation: Location): Boolean {
        val timeDifference = (currentLocation.time - lastLocation.time) / 1000.0 // seconds
        
        if (timeDifference < 10) return false // Too short to determine
        
        val distance = lastLocation.distanceTo(currentLocation) // meters
        val speed = (distance / timeDifference) * 3.6 // km/h
        
        // Consider movement impossible if speed exceeds 200 km/h
        return speed > 200
    }
    
    private fun calculateSpeed(lastLocation: Location, currentLocation: Location): Double {
        val timeDifference = (currentLocation.time - lastLocation.time) / 1000.0 // seconds
        val distance = lastLocation.distanceTo(currentLocation) // meters
        return (distance / timeDifference) * 3.6 // km/h
    }
    
    private fun handleSecurityViolation(
        violationType: SecurityViolationHandler.ViolationType,
        details: String
    ) {
        violationCount++
        
        // Handle violation through security handler
        securityViolationHandler.handleViolation(violationType, details)
        
        // Update notification to show violation
        updateNotification("🚨 Security violation detected: ${violationType.description}")
        
        // If too many violations, consider stopping the service or taking stronger action
        if (violationCount > 5) {
            handleExcessiveViolations()
        }
    }
    
    private fun handleExcessiveViolations() {
        // Log excessive violations
        secureStorageManager.logExcessiveViolations(violationCount)
        
        // Update notification
        updateNotification("🚨 Multiple security violations detected - App may be compromised")
        
        // Consider blocking app functionality
        secureStorageManager.setAppBlocked(true, "Excessive security violations detected")
    }
    
    private fun handleMonitoringError(error: Exception) {
        updateNotification("⚠️ Monitoring error: ${error.message}")
        
        // Log error for debugging
        secureStorageManager.logMonitoringError(error.message ?: "Unknown error")
    }
    
    private fun handleSecurityCheckError(error: Exception) {
        // Log security check errors but don't show in notification
        secureStorageManager.logSecurityCheckError(error.message ?: "Unknown error")
    }
    
    private fun stopLocationMonitoring() {
        isMonitoring = false
        
        monitoringJob?.cancel()
        securityCheckJob?.cancel()
        
        locationSecurityManager.cleanup()
        
        stopForeground(true)
        stopSelf()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Location Monitoring",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Continuous location and security monitoring"
                setShowBadge(false)
                enableLights(false)
                enableVibration(false)
            }
            
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(content: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val stopIntent = Intent(this, LocationMonitoringService::class.java).apply {
            action = ACTION_STOP_MONITORING
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("QR Attendance Security")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_location_monitoring)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .addAction(
                R.drawable.ic_stop,
                "Stop Monitoring",
                stopPendingIntent
            )
            .setColor(0xFF2196F3.toInt()) // Blue color
            .build()
    }
    
    private fun updateNotification(content: String) {
        val notification = createNotification(content)
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(SERVICE_ID, notification)
    }
    
    private fun acquireWakeLock() {
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "QRAttendance::LocationMonitoringWakeLock"
            ).apply {
                acquire(10 * 60 * 1000L) // 10 minutes
            }
        } catch (e: Exception) {
            // Handle wake lock acquisition failure
        }
    }
    
    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
        } catch (e: Exception) {
            // Handle wake lock release failure
        }
    }
    
    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null // This is a started service, not bound
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        isMonitoring = false
        
        monitoringJob?.cancel()
        securityCheckJob?.cancel()
        
        locationSecurityManager.cleanup()
        releaseWakeLock()
        
        // Clear security notifications when service stops
        securityViolationHandler.clearSecurityNotifications()
    }
    
    // Service restart handling
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        
        // Restart service if task is removed (app swiped away)
        val restartServiceIntent = Intent(applicationContext, LocationMonitoringService::class.java)
        restartServiceIntent.action = ACTION_START_MONITORING
        
        val restartServicePendingIntent = PendingIntent.getService(
            applicationContext, 1, restartServiceIntent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val alarmService = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        alarmService.set(
            AlarmManager.ELAPSED_REALTIME,
            android.os.SystemClock.elapsedRealtime() + 1000,
            restartServicePendingIntent
        )
        
        super.onTaskRemoved(rootIntent)
    }
}
