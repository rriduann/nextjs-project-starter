package com.example.qrattendance.security

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.google.android.gms.location.*
import kotlinx.coroutines.suspendCancellableCoroutine
import java.net.InetAddress
import java.net.NetworkInterface
import kotlin.coroutines.resume
import kotlin.math.*

class LocationSecurityManager(private val context: Context) {
    
    private val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
    private val fusedLocationClient = LocationServices.getFusedLocationProviderClient(context)
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    // Geofence configuration (example coordinates - replace with actual office location)
    private val allowedLocation = LatLng(40.7128, -74.0060) // New York coordinates
    private val allowedRadius = 200.0 // meters
    
    // Mock location detection
    suspend fun isMockLocationActive(): Boolean {
        return try {
            val location = getCurrentLocation() ?: return false
            
            // Method 1: Check isFromMockProvider flag
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                if (location.isFromMockProvider) {
                    return true
                }
            }
            
            // Method 2: Check multiple providers consistency
            if (!areLocationProvidersConsistent()) {
                return true
            }
            
            // Method 3: Check for impossible location changes
            if (isLocationChangeImpossible(location)) {
                return true
            }
            
            // Method 4: Check GPS signal characteristics
            if (isGpsSignalSuspicious(location)) {
                return true
            }
            
            false
        } catch (e: Exception) {
            // If we can't determine, assume it's suspicious
            true
        }
    }
    
    private suspend fun areLocationProvidersConsistent(): Boolean {
        val gpsLocation = getLocationFromProvider(LocationManager.GPS_PROVIDER)
        val networkLocation = getLocationFromProvider(LocationManager.NETWORK_PROVIDER)
        
        if (gpsLocation != null && networkLocation != null) {
            val distance = calculateDistance(
                gpsLocation.latitude, gpsLocation.longitude,
                networkLocation.latitude, networkLocation.longitude
            )
            
            // If GPS and Network locations differ by more than 1km, it's suspicious
            return distance <= 1000
        }
        
        return true // Can't compare, assume consistent
    }
    
    private suspend fun getLocationFromProvider(provider: String): Location? {
        if (!locationManager.isProviderEnabled(provider)) return null
        
        return suspendCancellableCoroutine { continuation ->
            try {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) 
                    == PackageManager.PERMISSION_GRANTED) {
                    
                    locationManager.requestSingleUpdate(provider, object : LocationListener {
                        override fun onLocationChanged(location: Location) {
                            continuation.resume(location)
                        }
                        
                        override fun onProviderEnabled(provider: String) {}
                        override fun onProviderDisabled(provider: String) {
                            continuation.resume(null)
                        }
                    }, null)
                } else {
                    continuation.resume(null)
                }
            } catch (e: Exception) {
                continuation.resume(null)
            }
        }
    }
    
    private var lastKnownLocation: Location? = null
    private var lastLocationTime: Long = 0
    
    private fun isLocationChangeImpossible(currentLocation: Location): Boolean {
        val currentTime = System.currentTimeMillis()
        
        lastKnownLocation?.let { lastLocation ->
            val timeDifference = (currentTime - lastLocationTime) / 1000.0 // seconds
            val distance = calculateDistance(
                lastLocation.latitude, lastLocation.longitude,
                currentLocation.latitude, currentLocation.longitude
            )
            
            // Calculate speed in km/h
            val speed = (distance / 1000.0) / (timeDifference / 3600.0)
            
            // If speed exceeds 200 km/h (impossible for normal human movement), it's suspicious
            if (speed > 200 && timeDifference < 300) { // 5 minutes
                return true
            }
        }
        
        // Update last known location
        lastKnownLocation = currentLocation
        lastLocationTime = currentTime
        
        return false
    }
    
    private fun isGpsSignalSuspicious(location: Location): Boolean {
        // Check accuracy - mock locations often have perfect accuracy
        if (location.accuracy == 0.0f || location.accuracy < 1.0f) {
            return true
        }
        
        // Check if location has altitude (mock locations often don't)
        if (!location.hasAltitude() && location.provider == LocationManager.GPS_PROVIDER) {
            return true
        }
        
        // Check bearing and speed consistency
        if (location.hasBearing() && location.hasSpeed()) {
            // Mock locations often have inconsistent bearing/speed
            if (location.speed == 0.0f && location.bearing != 0.0f) {
                return true
            }
        }
        
        return false
    }
    
    // VPN/Proxy detection
    fun isVpnActive(): Boolean {
        return try {
            // Method 1: Check network interfaces for VPN
            val networkInterfaces = NetworkInterface.getNetworkInterfaces()
            for (networkInterface in networkInterfaces) {
                val name = networkInterface.name.lowercase()
                if (name.contains("tun") || name.contains("tap") || name.contains("ppp")) {
                    return true
                }
            }
            
            // Method 2: Check active network capabilities
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                
                networkCapabilities?.let {
                    if (it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                        return true
                    }
                }
            }
            
            // Method 3: Check for common VPN DNS servers
            isUsingVpnDns()
        } catch (e: Exception) {
            false
        }
    }
    
    private fun isUsingVpnDns(): Boolean {
        return try {
            val dnsServers = getDnsServers()
            val commonVpnDns = listOf(
                "8.8.8.8", "8.8.4.4", // Google DNS (often used by VPNs)
                "1.1.1.1", "1.0.0.1", // Cloudflare DNS
                "9.9.9.9", "149.112.112.112" // Quad9 DNS
            )
            
            dnsServers.any { dns -> commonVpnDns.contains(dns) }
        } catch (e: Exception) {
            false
        }
    }
    
    private fun getDnsServers(): List<String> {
        val dnsServers = mutableListOf<String>()
        
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val linkProperties = connectivityManager.getLinkProperties(activeNetwork)
                
                linkProperties?.dnsServers?.forEach { dns ->
                    dnsServers.add(dns.hostAddress ?: "")
                }
            }
        } catch (e: Exception) {
            // Fallback method using system properties
            try {
                val dns1 = System.getProperty("net.dns1")
                val dns2 = System.getProperty("net.dns2")
                
                dns1?.let { dnsServers.add(it) }
                dns2?.let { dnsServers.add(it) }
            } catch (ex: Exception) {
                // Ignore
            }
        }
        
        return dnsServers
    }
    
    // IP Geolocation validation
    suspend fun validateIpGeolocation(): Boolean {
        return try {
            val currentLocation = getCurrentLocation() ?: return false
            val ipLocation = getIpGeolocation()
            
            if (ipLocation != null) {
                val distance = calculateDistance(
                    currentLocation.latitude, currentLocation.longitude,
                    ipLocation.latitude, ipLocation.longitude
                )
                
                // Allow up to 50km difference between GPS and IP location
                distance <= 50000
            } else {
                true // Can't validate, assume valid
            }
        } catch (e: Exception) {
            true // Error in validation, assume valid
        }
    }
    
    private suspend fun getIpGeolocation(): LatLng? {
        return try {
            // This would typically call an IP geolocation API
            // For demo purposes, returning null
            // In production, implement actual IP geolocation service call
            null
        } catch (e: Exception) {
            null
        }
    }
    
    // Location accuracy and geofence validation
    suspend fun getCurrentLocation(): Location? {
        return suspendCancellableCoroutine { continuation ->
            try {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) 
                    != PackageManager.PERMISSION_GRANTED) {
                    continuation.resume(null)
                    return@suspendCancellableCoroutine
                }
                
                val locationRequest = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 5000)
                    .setWaitForAccurateLocation(true)
                    .setMinUpdateIntervalMillis(2000)
                    .setMaxUpdateDelayMillis(10000)
                    .build()
                
                val locationCallback = object : LocationCallback() {
                    override fun onLocationResult(locationResult: LocationResult) {
                        val location = locationResult.lastLocation
                        fusedLocationClient.removeLocationUpdates(this)
                        continuation.resume(location)
                    }
                }
                
                fusedLocationClient.requestLocationUpdates(locationRequest, locationCallback, null)
                
                // Timeout after 15 seconds
                continuation.invokeOnCancellation {
                    fusedLocationClient.removeLocationUpdates(locationCallback)
                }
                
            } catch (e: Exception) {
                continuation.resume(null)
            }
        }
    }
    
    fun isLocationWithinGeofence(location: Location): Boolean {
        val distance = calculateDistance(
            location.latitude, location.longitude,
            allowedLocation.latitude, allowedLocation.longitude
        )
        
        return distance <= allowedRadius
    }
    
    fun getAddressFromLocation(location: Location): String {
        return try {
            // In production, use Geocoder to get actual address
            // For demo, return formatted coordinates
            "Lat: ${String.format("%.6f", location.latitude)}, " +
            "Lng: ${String.format("%.6f", location.longitude)}"
        } catch (e: Exception) {
            "Unknown Location"
        }
    }
    
    // Mock location app detection
    fun isMockLocationAppInstalled(): Boolean {
        val mockLocationApps = listOf(
            "com.lexa.fakegps",
            "com.incorporateapps.fakegps.fre",
            "com.blogspot.newapphorizons.fakegps",
            "com.evezzon.fakegps",
            "com.gsmartstudio.fakegps",
            "com.rascarlo.quick.settings.tiles",
            "ru.gavrikov.mocklocations"
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
    
    // Developer options check
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
    
    // Utility functions
    private fun calculateDistance(lat1: Double, lng1: Double, lat2: Double, lng2: Double): Double {
        val earthRadius = 6371000.0 // Earth's radius in meters
        
        val dLat = Math.toRadians(lat2 - lat1)
        val dLng = Math.toRadians(lng2 - lng1)
        
        val a = sin(dLat / 2) * sin(dLat / 2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
                sin(dLng / 2) * sin(dLng / 2)
        
        val c = 2 * atan2(sqrt(a), sqrt(1 - a))
        
        return earthRadius * c
    }
    
    fun cleanup() {
        // Clean up any ongoing location requests
        try {
            fusedLocationClient.removeLocationUpdates(object : LocationCallback() {})
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
    }
    
    data class LatLng(val latitude: Double, val longitude: Double)
}
