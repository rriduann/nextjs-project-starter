package com.example.qrattendance

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.qrattendance.databinding.ActivityMainBinding
import com.example.qrattendance.security.DeviceSecurityChecker
import com.example.qrattendance.security.LocationSecurityManager
import com.example.qrattendance.security.SecurityViolationHandler
import com.example.qrattendance.services.LocationMonitoringService
import com.example.qrattendance.utils.SecureStorageManager
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var qrCodeScanner: QRCodeScanner
    private lateinit var locationSecurityManager: LocationSecurityManager
    private lateinit var deviceSecurityChecker: DeviceSecurityChecker
    private lateinit var securityViolationHandler: SecurityViolationHandler
    private lateinit var secureStorageManager: SecureStorageManager
    
    private var isSecurityCheckPassed = false
    private var isLocationMonitoringActive = false
    
    // Permission launcher
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        handlePermissionResults(permissions)
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize security components first
        initializeSecurityComponents()
        
        // Perform comprehensive security checks
        performSecurityChecks()
        
        if (!isSecurityCheckPassed) {
            showSecurityViolationDialog()
            return
        }
        
        // Initialize UI only if security checks pass
        initializeUI()
        
        // Request necessary permissions
        requestRequiredPermissions()
    }
    
    private fun initializeSecurityComponents() {
        secureStorageManager = SecureStorageManager(this)
        deviceSecurityChecker = DeviceSecurityChecker(this)
        locationSecurityManager = LocationSecurityManager(this)
        securityViolationHandler = SecurityViolationHandler(this)
        qrCodeScanner = QRCodeScanner(this)
    }
    
    private fun performSecurityChecks() {
        lifecycleScope.launch {
            try {
                // Check for rooted device
                if (deviceSecurityChecker.isDeviceRooted()) {
                    securityViolationHandler.handleViolation(
                        SecurityViolationHandler.ViolationType.ROOT_ACCESS,
                        "Rooted device detected. App cannot run on rooted devices for security reasons."
                    )
                    return@launch
                }
                
                // Check for developer options
                if (deviceSecurityChecker.isDeveloperOptionsEnabled()) {
                    securityViolationHandler.handleViolation(
                        SecurityViolationHandler.ViolationType.DEBUGGING_ENABLED,
                        "Developer options are enabled. Please disable for security."
                    )
                    return@launch
                }
                
                // Check for mock location apps
                if (deviceSecurityChecker.isMockLocationAppInstalled()) {
                    securityViolationHandler.handleViolation(
                        SecurityViolationHandler.ViolationType.MOCK_LOCATION,
                        "Mock location apps detected. Please uninstall GPS spoofing applications."
                    )
                    return@launch
                }
                
                // Check for VPN/Proxy
                if (locationSecurityManager.isVpnActive()) {
                    securityViolationHandler.handleViolation(
                        SecurityViolationHandler.ViolationType.VPN_DETECTED,
                        "VPN connection detected. Please disable VPN for attendance marking."
                    )
                    return@launch
                }
                
                // All security checks passed
                isSecurityCheckPassed = true
                
            } catch (e: Exception) {
                securityViolationHandler.handleViolation(
                    SecurityViolationHandler.ViolationType.UNKNOWN,
                    "Security check failed: ${e.message}"
                )
            }
        }
    }
    
    private fun initializeUI() {
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        setupQRScanner()
    }
    
    private fun setupUI() {
        // Security status indicator
        updateSecurityStatusUI()
        
        // QR Scan button
        binding.btnScanQR.setOnClickListener {
            if (isLocationMonitoringActive && isSecurityCheckPassed) {
                startQRScanning()
            } else {
                showSecurityWarning("Security monitoring must be active to scan QR codes")
            }
        }
        
        // Security status button
        binding.btnSecurityStatus.setOnClickListener {
            showSecurityStatusDialog()
        }
        
        // Settings button
        binding.btnSettings.setOnClickListener {
            // Open app settings
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = android.net.Uri.fromParts("package", packageName, null)
            }
            startActivity(intent)
        }
    }
    
    private fun setupQRScanner() {
        qrCodeScanner.setOnQRCodeScannedListener { qrData ->
            handleQRCodeScanned(qrData)
        }
        
        qrCodeScanner.setOnScanErrorListener { error ->
            showError("QR Scan Error: $error")
        }
    }
    
    private fun requestRequiredPermissions() {
        val permissions = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION
        )
        
        val missingPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        
        if (missingPermissions.isNotEmpty()) {
            permissionLauncher.launch(missingPermissions.toTypedArray())
        } else {
            onAllPermissionsGranted()
        }
    }
    
    private fun handlePermissionResults(permissions: Map<String, Boolean>) {
        val deniedPermissions = permissions.filter { !it.value }.keys
        
        if (deniedPermissions.isEmpty()) {
            onAllPermissionsGranted()
        } else {
            showPermissionDeniedDialog(deniedPermissions.toList())
        }
    }
    
    private fun onAllPermissionsGranted() {
        // Start location monitoring service
        startLocationMonitoringService()
        
        // Update UI
        updateSecurityStatusUI()
        
        // Enable QR scanning
        binding.btnScanQR.isEnabled = true
    }
    
    private fun startLocationMonitoringService() {
        val serviceIntent = Intent(this, LocationMonitoringService::class.java)
        ContextCompat.startForegroundService(this, serviceIntent)
        isLocationMonitoringActive = true
    }
    
    private fun startQRScanning() {
        // Perform real-time security check before scanning
        lifecycleScope.launch {
            if (performRealTimeSecurityCheck()) {
                qrCodeScanner.startScanning()
            } else {
                showSecurityWarning("Security violation detected. Cannot proceed with QR scanning.")
            }
        }
    }
    
    private suspend fun performRealTimeSecurityCheck(): Boolean {
        // Check for mock location in real-time
        if (locationSecurityManager.isMockLocationActive()) {
            securityViolationHandler.handleViolation(
                SecurityViolationHandler.ViolationType.MOCK_LOCATION,
                "Mock location detected during QR scanning attempt"
            )
            return false
        }
        
        // Check location accuracy
        val location = locationSecurityManager.getCurrentLocation()
        if (location == null || location.accuracy > 50) {
            showSecurityWarning("GPS accuracy too low. Please ensure clear GPS signal.")
            return false
        }
        
        // Validate location against geofence
        if (!locationSecurityManager.isLocationWithinGeofence(location)) {
            securityViolationHandler.handleViolation(
                SecurityViolationHandler.ViolationType.LOCATION_OUTSIDE_GEOFENCE,
                "Location is outside allowed area"
            )
            return false
        }
        
        return true
    }
    
    private fun handleQRCodeScanned(qrData: String) {
        lifecycleScope.launch {
            try {
                // Get current location with high accuracy
                val location = locationSecurityManager.getCurrentLocation()
                if (location == null) {
                    showError("Unable to get current location")
                    return@launch
                }
                
                // Prepare attendance data
                val attendanceData = AttendanceData(
                    employeeId = secureStorageManager.getEmployeeId(),
                    employeeName = secureStorageManager.getEmployeeName(),
                    qrData = qrData,
                    location = LocationData(
                        lat = location.latitude,
                        lng = location.longitude,
                        accuracy = location.accuracy,
                        address = locationSecurityManager.getAddressFromLocation(location)
                    ),
                    deviceInfo = deviceSecurityChecker.getDeviceInfo(),
                    securityFlags = deviceSecurityChecker.getSecurityFlags(),
                    timestamp = System.currentTimeMillis()
                )
                
                // Submit attendance
                val apiClient = ApiClient(this@MainActivity)
                val result = apiClient.submitAttendance(attendanceData)
                
                if (result.isSuccess) {
                    showSuccess("Attendance recorded successfully!")
                } else {
                    showError("Failed to record attendance: ${result.errorMessage}")
                }
                
            } catch (e: Exception) {
                showError("Error processing QR code: ${e.message}")
            }
        }
    }
    
    private fun updateSecurityStatusUI() {
        val securityScore = deviceSecurityChecker.calculateSecurityScore()
        
        binding.tvSecurityScore.text = "Security Score: $securityScore%"
        binding.progressSecurityScore.progress = securityScore
        
        when {
            securityScore >= 80 -> {
                binding.tvSecurityStatus.text = "High Security"
                binding.tvSecurityStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_green_dark))
            }
            securityScore >= 60 -> {
                binding.tvSecurityStatus.text = "Medium Security"
                binding.tvSecurityStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_orange_dark))
            }
            else -> {
                binding.tvSecurityStatus.text = "Low Security"
                binding.tvSecurityStatus.setTextColor(ContextCompat.getColor(this, android.R.color.holo_red_dark))
            }
        }
        
        // Location monitoring status
        binding.tvLocationStatus.text = if (isLocationMonitoringActive) {
            "Location Monitoring: Active"
        } else {
            "Location Monitoring: Inactive"
        }
    }
    
    private fun showSecurityViolationDialog() {
        AlertDialog.Builder(this)
            .setTitle("Security Violation Detected")
            .setMessage("The app cannot run due to security violations. Please ensure your device meets security requirements.")
            .setPositiveButton("Exit") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showPermissionDeniedDialog(deniedPermissions: List<String>) {
        val message = "The following permissions are required for the app to function:\n\n" +
                deniedPermissions.joinToString("\n") { "• ${getPermissionName(it)}" }
        
        AlertDialog.Builder(this)
            .setTitle("Permissions Required")
            .setMessage(message)
            .setPositiveButton("Grant Permissions") { _, _ ->
                requestRequiredPermissions()
            }
            .setNegativeButton("Exit") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showSecurityStatusDialog() {
        val securityInfo = deviceSecurityChecker.getDetailedSecurityInfo()
        
        AlertDialog.Builder(this)
            .setTitle("Security Status")
            .setMessage(securityInfo)
            .setPositiveButton("OK", null)
            .show()
    }
    
    private fun getPermissionName(permission: String): String {
        return when (permission) {
            Manifest.permission.CAMERA -> "Camera (for QR scanning)"
            Manifest.permission.ACCESS_FINE_LOCATION -> "Fine Location (for GPS tracking)"
            Manifest.permission.ACCESS_COARSE_LOCATION -> "Coarse Location (for location services)"
            Manifest.permission.ACCESS_BACKGROUND_LOCATION -> "Background Location (for continuous monitoring)"
            else -> permission
        }
    }
    
    private fun showSuccess(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(ContextCompat.getColor(this, android.R.color.holo_green_dark))
            .show()
    }
    
    private fun showError(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(ContextCompat.getColor(this, android.R.color.holo_red_dark))
            .show()
    }
    
    private fun showSecurityWarning(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(ContextCompat.getColor(this, android.R.color.holo_orange_dark))
            .show()
    }
    
    override fun onResume() {
        super.onResume()
        
        // Re-check security status when app resumes
        if (isSecurityCheckPassed) {
            lifecycleScope.launch {
                performRealTimeSecurityCheck()
                updateSecurityStatusUI()
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        // Clean up resources
        qrCodeScanner.cleanup()
        locationSecurityManager.cleanup()
    }
}
