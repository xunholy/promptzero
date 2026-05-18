package btuuid

// characteristics maps SIG-assigned 16-bit GATT Characteristic
// UUIDs to their canonical names. Source: Bluetooth Assigned
// Numbers — GATT Characteristics document. Covers the
// documented characteristics most commonly encountered when
// enumerating BLE GATT databases.
//
// The full SIG catalog has ~400 entries; we cover the most
// operationally common subset (~120 entries). Operators can
// extend by editing this table.
var characteristics = map[string]string{
	// Generic Access
	"2A00": "Device Name",
	"2A01": "Appearance",
	"2A02": "Peripheral Privacy Flag",
	"2A03": "Reconnection Address",
	"2A04": "Peripheral Preferred Connection Parameters",
	"2A05": "Service Changed",
	"2AA6": "Central Address Resolution",
	"2AC9": "Resolvable Private Address Only",

	// Alert Notification / Phone Alert Status
	"2A06": "Alert Level",
	"2A07": "TX Power Level",
	"2A0F": "Local Time Information",
	"2A12": "Time Accuracy",
	"2A13": "Time Source",
	"2A14": "Reference Time Information",
	"2A16": "Time Update Control Point",
	"2A17": "Time Update State",
	"2A39": "Heart Rate Control Point",
	"2A3F": "Alert Status",
	"2A41": "Ringer Control Point",
	"2A42": "Ringer Setting",
	"2A43": "Alert Category ID Bit Mask",
	"2A44": "Alert Notification Control Point",
	"2A45": "Unread Alert Status",
	"2A46": "New Alert",
	"2A47": "Supported New Alert Category",
	"2A48": "Supported Unread Alert Category",

	// Glucose / Health Thermometer
	"2A18": "Glucose Measurement",
	"2A19": "Battery Level",
	"2A1B": "Battery Power State",
	"2A1C": "Temperature Measurement",
	"2A1D": "Temperature Type",
	"2A1E": "Intermediate Temperature",
	"2A21": "Measurement Interval",
	"2A22": "Boot Keyboard Input Report",
	"2A23": "System ID",
	"2A24": "Model Number String",
	"2A25": "Serial Number String",
	"2A26": "Firmware Revision String",
	"2A27": "Hardware Revision String",
	"2A28": "Software Revision String",
	"2A29": "Manufacturer Name String",
	"2A2A": "IEEE 11073-20601 Regulatory Certification Data List",
	"2A2B": "Current Time",
	"2A2C": "Magnetic Declination",
	"2A2F": "Position 2D",

	// Heart Rate
	"2A37": "Heart Rate Measurement",
	"2A38": "Body Sensor Location",

	// Blood Pressure
	"2A35": "Blood Pressure Measurement",
	"2A36": "Intermediate Cuff Pressure",
	"2A49": "Blood Pressure Feature",

	// HID
	"2A4A": "HID Information",
	"2A4B": "Report Map",
	"2A4C": "HID Control Point",
	"2A4D": "Report",
	"2A4E": "Protocol Mode",
	"2A4F": "Scan Interval Window",
	"2A50": "PnP ID",
	"2A32": "Boot Keyboard Output Report",
	"2A33": "Boot Mouse Input Report",

	// Glucose context
	"2A34": "Glucose Measurement Context",
	"2A51": "Glucose Feature",
	"2A52": "Record Access Control Point",

	// Cycling / Running Speed
	"2A53": "RSC Measurement",
	"2A54": "RSC Feature",
	"2A55": "SC Control Point",
	"2A5B": "CSC Measurement",
	"2A5C": "CSC Feature",
	"2A5D": "Sensor Location",
	"2A63": "Cycling Power Measurement",
	"2A64": "Cycling Power Vector",
	"2A65": "Cycling Power Feature",
	"2A66": "Cycling Power Control Point",
	"2A5E": "PLX Spot-Check Measurement",
	"2A5F": "PLX Continuous Measurement",
	"2A60": "PLX Features",

	// Location and Navigation
	"2A67": "Location and Speed",
	"2A68": "Navigation",
	"2A69": "Position Quality",
	"2A6A": "LN Feature",
	"2A6B": "LN Control Point",
	"2A6C": "Elevation",
	"2A6D": "Pressure",
	"2A6E": "Temperature",
	"2A6F": "Humidity",
	"2A70": "True Wind Speed",
	"2A71": "True Wind Direction",
	"2A72": "Apparent Wind Speed",
	"2A73": "Apparent Wind Direction",
	"2A74": "Gust Factor",
	"2A75": "Pollen Concentration",
	"2A76": "UV Index",
	"2A77": "Irradiance",
	"2A78": "Rainfall",
	"2A79": "Wind Chill",
	"2A7A": "Heat Index",
	"2A7B": "Dew Point",

	// Environmental Sensing
	"2A7D": "Descriptor Value Changed",
	"2A7E": "Aerobic Heart Rate Lower Limit",
	"2A7F": "Aerobic Threshold",
	"2A80": "Age",
	"2A81": "Anaerobic Heart Rate Lower Limit",
	"2A82": "Anaerobic Heart Rate Upper Limit",
	"2A83": "Anaerobic Threshold",
	"2A84": "Aerobic Heart Rate Upper Limit",
	"2A85": "Date of Birth",
	"2A86": "Date of Threshold Assessment",
	"2A87": "Email Address",
	"2A88": "Fat Burn Heart Rate Lower Limit",
	"2A89": "Fat Burn Heart Rate Upper Limit",
	"2A8A": "First Name",
	"2A8B": "Five Zone Heart Rate Limits",
	"2A8C": "Gender",
	"2A8D": "Heart Rate Max",
	"2A8E": "Height",
	"2A8F": "Hip Circumference",
	"2A90": "Last Name",
	"2A91": "Maximum Recommended Heart Rate",
	"2A92": "Resting Heart Rate",
	"2A93": "Sport Type for Aerobic and Anaerobic Thresholds",
	"2A94": "Three Zone Heart Rate Limits",
	"2A95": "Two Zone Heart Rate Limits",
	"2A96": "VO2 Max",
	"2A97": "Waist Circumference",
	"2A98": "Weight",
	"2A99": "Database Change Increment",
	"2A9A": "User Index",
	"2A9B": "Body Composition Feature",
	"2A9C": "Body Composition Measurement",
	"2A9D": "Weight Measurement",
	"2A9E": "Weight Scale Feature",
	"2A9F": "User Control Point",

	// Magnetometer
	"2AA0": "Magnetic Flux Density 2D",
	"2AA1": "Magnetic Flux Density 3D",

	// Pulse Oximeter / Sensor
	"2AA2": "Language",
	"2AA3": "Barometric Pressure Trend",
	"2AA4": "Bond Management Control Point",
	"2AA5": "Bond Management Feature",

	// Indoor Positioning
	"2AAD": "Indoor Positioning Configuration",
	"2AAE": "Latitude",
	"2AAF": "Longitude",
	"2AB0": "Local North Coordinate",
	"2AB1": "Local East Coordinate",
	"2AB2": "Floor Number",
	"2AB3": "Altitude",
	"2AB4": "Uncertainty",

	// HTTP Proxy
	"2AB6": "URI",
	"2AB7": "HTTP Headers",
	"2AB8": "HTTP Status Code",
	"2AB9": "HTTP Entity Body",
	"2ABA": "HTTP Control Point",
	"2ABB": "HTTPS Security",

	// CGM (Continuous Glucose Monitoring)
	"2AA7": "CGM Measurement",
	"2AA8": "CGM Feature",
	"2AA9": "CGM Status",
	"2AAA": "CGM Session Start Time",
	"2AAB": "CGM Session Run Time",
	"2AAC": "CGM Specific Ops Control Point",

	// Mesh
	"2ADB": "Mesh Provisioning Data In",
	"2ADC": "Mesh Provisioning Data Out",
	"2ADD": "Mesh Proxy Data In",
	"2ADE": "Mesh Proxy Data Out",
}
