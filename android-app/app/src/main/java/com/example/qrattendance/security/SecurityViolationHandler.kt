package com.example.qrattendance.security

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.example.qrattendance.MainActivity
import com.example.qrattendance.R
import com.example.qrattendance.api.ApiClient
import com.example.qrattendance.utils.SecureStorageManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SecurityViolationHandler(private val context: Context) {
    
    private val notificationManager = NotificationManagerCompat.from(context)
    private val secureStorageManager = SecureStorageManager(context)
    private val apiClient = ApiClient(context)
    
    companion object {
        private const val SECURITY_CHANNEL_ID = "security_violations"
        private const val SECURITY_NOTIFICATION_ID = 1001
    }
    
    init {
        createNotificationChannel()
    }
    
    enum class ViolationType(val severity: String, val description: String) {
        MOCK_LOCATION("critical", "Mock location detected"),
        GPS_SPOOFING("high", "GPS spoofing detected"),
        VPN_DETECTED("high", "VPN/Proxy connection detected"),
        ROOT_ACCESS("critical", "Root access detected"),
        DEBUGGING_ENABLED("medium", "USB debugging enabled"),
        UNKNOWN_SOURCES("low", "Unknown sources enabled"),
        XPOSED_FRAMEWORK("high", "Xposed framework detected"),
        EMULATOR_DETECTED("medium", "Running on emulator"),
        LOCATION_OUTSIDE_GEOFENCE("high", "Location outside allowed area"),
        IMPOSSIBLE_MOVEMENT("high", "Impossible movement detected"),
        NETWORK_MISMATCH("medium", "Network location mismatch"),
        UNKNOWN("low", "Unknown security violation")
    }
    
    fun handleViolation(violationType: ViolationType, details: String) {
        // Log violation locally
        logViolationLocally(violationType, details)
        
        // Show persistent notification
        showSecurityNotification(violationType, details)
        
        // Report to server
        reportViolationToServer(violationType, details)
        
        // Take appropriate action based on severity
        when (violationType.severity) {
            "critical" -> handleCriticalViolation(violationType, details)
            "high" -> handleHighViolation(violationType, details)
            "medium" -> handleMediumViolation(violationType, details)
            "low" -> handleLowViolation(violationType, details)
        }
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SECURITY_CHANNEL_ID,
                "Security Violations",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for security violations and threats"
                enableLights(true)
                enableVibration(true)
                setShowBadge(true)
            }
            
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun showSecurityNotification(violationType: ViolationType, details: String) {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, SECURITY_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_security_warning)
            .setContentTitle("🚨 Security Violation Detected")
            .setContentText("${violationType.description}: $details")
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("${violationType.description}\n\nDetails: $details\n\nTap to open app and resolve the issue."))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(false) // Keep notification until manually dismissed
            .setOngoing(violationType.severity == "critical") // Make critical violations persistent
            .setContentIntent(pendingIntent)
            .setColor(when (violationType.severity) {
                "critical" -> 0xFFD32F2F.toInt() // Red
                "high" -> 0xFFFF5722.toInt() // Deep Orange
                "medium" -> 0xFFFF9800.toInt() // Orange
                else -> 0xFFFFC107.toInt() // Amber
            })
            .addAction(
                R.drawable.ic_security_warning,
                "Resolve",
                pendingIntent
            )
            .build()
        
        try {
            notificationManager.notify(SECURITY_NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            // Handle case where notification permission is not granted
        }
    }
    
    private fun logViolationLocally(violationType: ViolationType, details: String) {
        try {
            val timestamp = System.currentTimeMillis()
            val logEntry = SecurityViolationLog(
                type = violationType.name,
                severity = violationType.severity,
                description = violationType.description,
                details = details,
                timestamp = timestamp,
                deviceInfo = getDeviceInfo(),
                resolved = false
            )
            
            // Store in secure local storage
            secureStorageManager.addSecurityViolationLog(logEntry)
            
        } catch (e: Exception) {
            // Log error but don't fail the violation handling
        }
    }
    
    private fun reportViolationToServer(violationType: ViolationType, details: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val violationReport = SecurityViolationReport(
                    type = violationType.name.lowercase(),
                    severity = violationType.severity,
                    employeeId = secureStorageManager.getEmployeeId(),
                    employeeName = secureStorageManager.getEmployeeName(),
                    deviceInfo = getDeviceInfo(),
                    timestamp = System.currentTimeMillis(),
                    description = "${violationType.description}: $details",
                    location = getCurrentLocationData(),
                    additionalData = mapOf(
                        "violationType" to violationType.name,
                        "appVersion" to getAppVersion(),
                        "osVersion" to android.os.Build.VERSION.RELEASE
                    )
                )
                
                apiClient.reportSecurityViolation(violationReport)
                
            } catch (e: Exception) {
                // Store for later retry if network fails
                secureStorageManager.addPendingViolationReport(violationType, details)
            }
        }
    }
    
    private fun handleCriticalViolation(violationType: ViolationType, details: String) {
        // Critical violations: Block app functionality immediately
        when (violationType) {
            ViolationType.MOCK_LOCATION, ViolationType.ROOT_ACCESS -> {
                // Show blocking dialog and exit app
                showCriticalViolationDialog(violationType, details)
                
                // Disable app functionality
                secureStorageManager.setAppBlocked(true, "Critical security violation: ${violationType.description}")
                
                // Send immediate alert to admin
                sendImmediateAdminAlert(violationType, details)
            }
            else -> handleHighViolation(violationType, details)
        }
    }
    
    private fun handleHighViolation(violationType: ViolationType, details: String) {
        // High violations: Restrict functionality but allow basic operations
        when (violationType) {
            ViolationType.GPS_SPOOFING, ViolationType.VPN_DETECTED -> {
                // Block attendance marking but allow app to run
                secureStorageManager.setAttendanceBlocked(true, "Security violation: ${violationType.description}")
                
                // Show warning dialog
                showHighViolationDialog(violationType, details)
            }
            else -> handleMediumViolation(violationType, details)
        }
    }
    
    private fun handleMediumViolation(violationType: ViolationType, details: String) {
        // Medium violations: Show warnings and increase monitoring
        showMediumViolationDialog(violationType, details)
        
        // Increase security monitoring frequency
        secureStorageManager.setEnhancedMonitoring(true)
    }
    
    private fun handleLowViolation(violationType: ViolationType, details: String) {
        // Low violations: Log and show notification only
        // Already handled by notification and logging
    }
    
    private fun showCriticalViolationDialog(violationType: ViolationType, details: String) {
        val intent = Intent(context, SecurityViolationActivity::class.java).apply {
            putExtra("violation_type", violationType.name)
            putExtra("violation_details", details)
            putExtra("violation_severity", "critical")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        context.startActivity(intent)
    }
    
    private fun showHighViolationDialog(violationType: ViolationType, details: String) {
        val intent = Intent(context, SecurityViolationActivity::class.java).apply {
            putExtra("violation_type", violationType.name)
            putExtra("violation_details", details)
            putExtra("violation_severity", "high")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        context.startActivity(intent)
    }
    
    private fun showMediumViolationDialog(violationType: ViolationType, details: String) {
        // For medium violations, just show notification
        // Dialog would be too intrusive for medium severity
    }
    
    private fun sendImmediateAdminAlert(violationType: ViolationType, details: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val alertData = mapOf(
                    "alert_type" to "critical_security_violation",
                    "employee_id" to secureStorageManager.getEmployeeId(),
                    "employee_name" to secureStorageManager.getEmployeeName(),
                    "violation_type" to violationType.name,
                    "violation_details" to details,
                    "timestamp" to System.currentTimeMillis(),
                    "device_info" to getDeviceInfo(),
                    "requires_immediate_attention" to true
                )
                
                apiClient.sendImmediateAlert(alertData)
                
            } catch (e: Exception) {
                // If immediate alert fails, ensure it's logged for retry
                secureStorageManager.addFailedAlert(violationType, details)
            }
        }
    }
    
    private fun getCurrentLocationData(): Map<String, Any>? {
        return try {
            // This would get current location from LocationSecurityManager
            // For now, return null to avoid circular dependency
            null
        } catch (e: Exception) {
            null
        }
    }
    
    private fun getDeviceInfo(): String {
        return "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} (Android ${android.os.Build.VERSION.RELEASE})"
    }
    
    private fun getAppVersion(): String {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName ?: "Unknown"
        } catch (e: Exception) {
            "Unknown"
        }
    }
    
    // Clear all security notifications
    fun clearSecurityNotifications() {
        notificationManager.cancel(SECURITY_NOTIFICATION_ID)
    }
    
    // Check if app is currently blocked due to security violations
    fun isAppBlocked(): Boolean {
        return secureStorageManager.isAppBlocked()
    }
    
    // Check if attendance is blocked due to security violations
    fun isAttendanceBlocked(): Boolean {
        return secureStorageManager.isAttendanceBlocked()
    }
    
    // Get blocking reason
    fun getBlockingReason(): String? {
        return secureStorageManager.getBlockingReason()
    }
    
    // Data classes
    data class SecurityViolationLog(
        val type: String,
        val severity: String,
        val description: String,
        val details: String,
        val timestamp: Long,
        val deviceInfo: String,
        val resolved: Boolean
    )
    
    data class SecurityViolationReport(
        val type: String,
        val severity: String,
        val employeeId: String,
        val employeeName: String,
        val deviceInfo: String,
        val timestamp: Long,
        val description: String,
        val location: Map<String, Any>?,
        val additionalData: Map<String, Any>
    )
}
