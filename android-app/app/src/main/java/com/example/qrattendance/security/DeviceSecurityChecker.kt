package com.example.qrattendance.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.scottyab.rootbeer.RootBeer
import java.io.File

class DeviceSecurityChecker(private val context: Context) {
    
    private val rootBeer = RootBeer(context)
    
    // Root detection using multiple methods
    fun isDeviceRooted(): Boolean {
        return try {
            // Method 1: Use RootBeer library (comprehensive root detection)
            if (rootBeer.isRooted) {
                return true
            }
            
            // Method 2: Check for common root files
            if (checkForRootFiles()) {
                return true
            }
            
            // Method 3: Check for root management apps
            if (checkForRootApps()) {
                return true
            }
            
            // Method 4: Check for dangerous system properties
            if (checkDangerousSystemProperties()) {
                return true
            }
            
            // Method 5: Check for writable system directories
            if (checkWritableSystemDirectories()) {
                return true
            }
            
            false
        } catch (e: Exception) {
            // If detection fails, assume device might be compromised
            true
        }
    }
    
    private fun checkForRootFiles(): Boolean {
        val rootFiles = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/data/local/busybox",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/magisk",
            "/sbin/magisk"
        )
        
        return rootFiles.any { path ->
            try {
                File(path).exists()
            } catch (e: Exception) {
                false
            }
        }
    }
    
    private fun checkForRootApps(): Boolean {
        val rootApps = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot"
        )
        
        val packageManager = context.packageManager
        
        return rootApps.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }
    
    private fun checkDangerousSystemProperties(): Boolean {
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "service.adb.root" to "1"
        )
        
        return dangerousProps.any { (prop, dangerousValue) ->
            try {
                val value = getSystemProperty(prop)
                value == dangerousValue
            } catch (e: Exception) {
                false
            }
        }
    }
    
    private fun getSystemProperty(property: String): String? {
        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            process.inputStream.bufferedReader().readLine()?.trim()
        } catch (e: Exception) {
            null
        }
    }
    
    private fun checkWritableSystemDirectories(): Boolean {
        val systemDirs = arrayOf(
            "/system",
            "/system/bin",
            "/system/sbin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
            "/etc"
        )
        
        return systemDirs.any { dir ->
            try {
                File(dir).canWrite()
            } catch (e: Exception) {
                false
            }
        }
    }
    
    // Developer options detection
    fun isDeveloperOptionsEnabled(): Boolean {
        return try {
            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            ) == 1
        } catch (e: Exception) {
            false
        }
    }
    
    // USB debugging detection
    fun isUsbDebuggingEnabled(): Boolean {
        return try {
            Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.ADB_ENABLED,
                0
            ) == 1
        } catch (e: Exception) {
            false
        }
    }
    
    // Unknown sources detection
    fun isUnknownSourcesEnabled(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // For Android 8.0+, check if app can install unknown apps
                context.packageManager.canRequestPackageInstalls()
            } else {
                // For older versions, check global setting
                Settings.Secure.getInt(
                    context.contentResolver,
                    Settings.Secure.INSTALL_NON_MARKET_APPS,
                    0
                ) == 1
            }
        } catch (e: Exception) {
            false
        }
    }
    
    // Mock location app detection
    fun isMockLocationAppInstalled(): Boolean {
        val mockLocationApps = arrayOf(
            "com.lexa.fakegps",
            "com.incorporateapps.fakegps.fre",
            "com.blogspot.newapphorizons.fakegps",
            "com.evezzon.fakegps",
            "com.gsmartstudio.fakegps",
            "com.rascarlo.quick.settings.tiles",
            "ru.gavrikov.mocklocations",
            "com.theappninjas.gpsjoystick",
            "com.catalystapps.gps.joystick.fake.walk",
            "com.incorporateapps.fakegps_route",
            "com.lexa.fakegps.route",
            "appinventor.ai_progetto_fake_gps.fakegps"
        )
        
        val packageManager = context.packageManager
        
        return mockLocationApps.any { packageName ->
            try {
                packageManager.getPackageInfo(packageName, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }
    
    // Xposed framework detection
    fun isXposedFrameworkInstalled(): Boolean {
        return try {
            // Check for Xposed installer
            val xposedApps = arrayOf(
                "de.robv.android.xposed.installer",
                "org.meowcat.edxposed.manager",
                "top.canyie.dreamland.manager"
            )
            
            val packageManager = context.packageManager
            
            xposedApps.any { packageName ->
                try {
                    packageManager.getPackageInfo(packageName, 0)
                    true
                } catch (e: PackageManager.NameNotFoundException) {
                    false
                }
            }
        } catch (e: Exception) {
            false
        }
    }
    
    // Emulator detection
    fun isRunningOnEmulator(): Boolean {
        return try {
            (Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
            "google_sdk" == Build.PRODUCT)
        } catch (e: Exception) {
            false
        }
    }
    
    // Calculate overall security score
    fun calculateSecurityScore(): Int {
        var score = 100
        
        // Major security violations
        if (isDeviceRooted()) score -= 40
        if (isMockLocationAppInstalled()) score -= 30
        if (isXposedFrameworkInstalled()) score -= 25
        
        // Medium security issues
        if (isDeveloperOptionsEnabled()) score -= 15
        if (isUsbDebuggingEnabled()) score -= 10
        if (isUnknownSourcesEnabled()) score -= 10
        
        // Minor issues
        if (isRunningOnEmulator()) score -= 5
        
        return maxOf(0, score)
    }
    
    // Get security flags for API submission
    fun getSecurityFlags(): SecurityFlags {
        return SecurityFlags(
            isRooted = isDeviceRooted(),
            mockLocationDetected = isMockLocationAppInstalled(),
            vpnActive = false, // This would be checked by LocationSecurityManager
            debuggingEnabled = isUsbDebuggingEnabled(),
            unknownSources = isUnknownSourcesEnabled(),
            xposedInstalled = isXposedFrameworkInstalled(),
            runningOnEmulator = isRunningOnEmulator()
        )
    }
    
    // Get device information
    fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            osVersion = "Android ${Build.VERSION.RELEASE}",
            apiLevel = Build.VERSION.SDK_INT,
            buildId = Build.ID,
            fingerprint = Build.FINGERPRINT,
            bootloader = Build.BOOTLOADER,
            hardware = Build.HARDWARE
        )
    }
    
    // Get detailed security information for display
    fun getDetailedSecurityInfo(): String {
        val securityFlags = getSecurityFlags()
        val securityScore = calculateSecurityScore()
        
        return buildString {
            appendLine("Security Score: $securityScore%")
            appendLine()
            appendLine("Security Status:")
            appendLine("• Root Access: ${if (securityFlags.isRooted) "DETECTED ⚠️" else "Not Detected ✓"}")
            appendLine("• Mock Location Apps: ${if (securityFlags.mockLocationDetected) "DETECTED ⚠️" else "Not Detected ✓"}")
            appendLine("• USB Debugging: ${if (securityFlags.debuggingEnabled) "ENABLED ⚠️" else "Disabled ✓"}")
            appendLine("• Unknown Sources: ${if (securityFlags.unknownSources) "ENABLED ⚠️" else "Disabled ✓"}")
            appendLine("• Xposed Framework: ${if (securityFlags.xposedInstalled) "DETECTED ⚠️" else "Not Detected ✓"}")
            appendLine("• Running on Emulator: ${if (securityFlags.runningOnEmulator) "YES ⚠️" else "No ✓"}")
            appendLine()
            appendLine("Device Information:")
            val deviceInfo = getDeviceInfo()
            appendLine("• Model: ${deviceInfo.manufacturer} ${deviceInfo.model}")
            appendLine("• OS Version: ${deviceInfo.osVersion}")
            appendLine("• API Level: ${deviceInfo.apiLevel}")
        }
    }
    
    // Data classes
    data class SecurityFlags(
        val isRooted: Boolean,
        val mockLocationDetected: Boolean,
        val vpnActive: Boolean,
        val debuggingEnabled: Boolean,
        val unknownSources: Boolean,
        val xposedInstalled: Boolean = false,
        val runningOnEmulator: Boolean = false
    )
    
    data class DeviceInfo(
        val manufacturer: String,
        val model: String,
        val osVersion: String,
        val apiLevel: Int,
        val buildId: String,
        val fingerprint: String,
        val bootloader: String,
        val hardware: String
    )
}
