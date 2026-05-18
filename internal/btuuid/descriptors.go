package btuuid

// descriptors maps SIG-assigned 16-bit GATT Descriptor UUIDs to
// their canonical names. Source: Bluetooth Assigned Numbers —
// GATT Descriptors document. Most descriptors live in the
// 0x2900-0x290F range.
var descriptors = map[string]string{
	"2900": "Characteristic Extended Properties",
	"2901": "Characteristic User Description",
	"2902": "Client Characteristic Configuration",
	"2903": "Server Characteristic Configuration",
	"2904": "Characteristic Presentation Format",
	"2905": "Characteristic Aggregate Format",
	"2906": "Valid Range",
	"2907": "External Report Reference",
	"2908": "Report Reference",
	"2909": "Number of Digitals",
	"290A": "Value Trigger Setting",
	"290B": "Environmental Sensing Configuration",
	"290C": "Environmental Sensing Measurement",
	"290D": "Environmental Sensing Trigger Setting",
	"290E": "Time Trigger Setting",
	"290F": "Complete BR-EDR Transport Block Data",
}
