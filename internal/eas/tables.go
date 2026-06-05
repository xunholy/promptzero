// SPDX-License-Identifier: AGPL-3.0-or-later

package eas

// originatorNames maps the 3-char ORG code to its meaning
// (FCC 47 CFR 11.31).
var originatorNames = map[string]string{
	"PEP": "National Public Warning System (Primary Entry Point)",
	"CIV": "Civil authorities",
	"WXR": "National Weather Service / Environment Canada",
	"EAS": "EAS Participant (broadcast station or cable system)",
	"EAN": "Emergency Action Notification Network (legacy)",
}

// eventNames maps the 3-char EEE event code to its meaning (FCC 47 CFR
// 11.31 + NWS NWSI 10-1712). Unrecognised codes fall back to the
// standard third-letter suffix convention (see eventName).
var eventNames = map[string]string{
	// National / administrative / test
	"EAN": "National Emergency Message", "EAT": "Emergency Action Termination",
	"NIC": "National Information Center", "NPT": "Nationwide Test of the EAS",
	"RMT": "Required Monthly Test", "RWT": "Required Weekly Test",
	"NMN": "Network Notification Message", "DMO": "Practice / Demo Warning",
	"NAT": "National Audible Test", "NST": "National Silent Test",
	"ADR": "Administrative Message",
	// Weather warnings
	"TOR": "Tornado Warning", "SVR": "Severe Thunderstorm Warning",
	"FFW": "Flash Flood Warning", "FLW": "Flood Warning",
	"HWW": "High Wind Warning", "HUW": "Hurricane Warning",
	"TRW": "Tropical Storm Warning", "TSW": "Tsunami Warning",
	"BZW": "Blizzard Warning", "DSW": "Dust Storm Warning",
	"FRW": "Fire Warning", "CFW": "Coastal Flood Warning",
	"SQW": "Snow Squall Warning", "SMW": "Special Marine Warning",
	"WSW": "Winter Storm Warning", "EWW": "Extreme Wind Warning",
	"SSW": "Storm Surge Warning", "VOW": "Volcano Warning",
	"EQW": "Earthquake Warning",
	// Weather watches
	"TOA": "Tornado Watch", "SVA": "Severe Thunderstorm Watch",
	"FFA": "Flash Flood Watch", "FLA": "Flood Watch",
	"HUA": "Hurricane Watch", "TRA": "Tropical Storm Watch",
	"TSA": "Tsunami Watch", "HWA": "High Wind Watch",
	"CFA": "Coastal Flood Watch", "WSA": "Winter Storm Watch",
	"AVA": "Avalanche Watch", "SSA": "Storm Surge Watch",
	// Weather statements
	"FFS": "Flash Flood Statement", "FLS": "Flood Statement",
	"SVS": "Severe Weather Statement", "SPS": "Special Weather Statement",
	"HLS": "Hurricane Local Statement",
	// Civil / non-weather
	"CAE": "Child Abduction Emergency", "CDW": "Civil Danger Warning",
	"CEM": "Civil Emergency Message", "EVI": "Evacuation Immediate",
	"HMW": "Hazardous Materials Warning", "LEW": "Law Enforcement Warning",
	"NUW": "Nuclear Power Plant Warning", "RHW": "Radiological Hazard Warning",
	"SPW": "Shelter-in-Place Warning", "TOE": "911 Telephone Outage Emergency",
	"AVW": "Avalanche Warning", "BLU": "Blue Alert",
	"DBW": "Dam Break Warning", "LAE": "Local Area Emergency",
	"MEP": "Missing / Endangered Persons", "DEW": "Contagious Disease Warning",
	// Transmitter-internal (not normally displayed)
	"TXB": "Transmitter Backup On", "TXF": "Transmitter Carrier Off",
	"TXO": "Transmitter Carrier On", "TXP": "Transmitter Primary On",
}

func originatorName(o string) string {
	if n, ok := originatorNames[o]; ok {
		return n
	}
	return "unknown originator"
}

// eventName resolves an event code, falling back to the standard
// third-letter suffix convention for codes not in the table.
func eventName(e string) string {
	if n, ok := eventNames[e]; ok {
		return n
	}
	if len(e) == 3 {
		switch e[2] {
		case 'W':
			return "unrecognised Warning"
		case 'A':
			return "unrecognised Watch"
		case 'E':
			return "unrecognised Emergency"
		case 'S':
			return "unrecognised Statement"
		case 'T':
			return "unrecognised Test"
		case 'M':
			return "unrecognised Message"
		case 'N':
			return "unrecognised Notification"
		}
	}
	return "unknown event code"
}

// stateNames maps the 2-digit ANSI/FIPS state code to its name. Codes
// in the 60s-70s are US territories; 0 is used for offshore marine /
// nationwide. The 5-2 standard table.
var stateNames = map[int]string{
	0: "(offshore / nationwide)",
	1: "Alabama", 2: "Alaska", 4: "Arizona", 5: "Arkansas", 6: "California",
	8: "Colorado", 9: "Connecticut", 10: "Delaware", 11: "District of Columbia",
	12: "Florida", 13: "Georgia", 15: "Hawaii", 16: "Idaho", 17: "Illinois",
	18: "Indiana", 19: "Iowa", 20: "Kansas", 21: "Kentucky", 22: "Louisiana",
	23: "Maine", 24: "Maryland", 25: "Massachusetts", 26: "Michigan",
	27: "Minnesota", 28: "Mississippi", 29: "Missouri", 30: "Montana",
	31: "Nebraska", 32: "Nevada", 33: "New Hampshire", 34: "New Jersey",
	35: "New Mexico", 36: "New York", 37: "North Carolina", 38: "North Dakota",
	39: "Ohio", 40: "Oklahoma", 41: "Oregon", 42: "Pennsylvania",
	44: "Rhode Island", 45: "South Carolina", 46: "South Dakota",
	47: "Tennessee", 48: "Texas", 49: "Utah", 50: "Vermont", 51: "Virginia",
	53: "Washington", 54: "West Virginia", 55: "Wisconsin", 56: "Wyoming",
	60: "American Samoa", 64: "Federated States of Micronesia", 66: "Guam",
	68: "Marshall Islands", 69: "Northern Mariana Islands", 70: "Palau",
	72: "Puerto Rico", 74: "U.S. Minor Outlying Islands", 78: "U.S. Virgin Islands",
}

func stateName(s int) string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return "unknown state/territory"
}
