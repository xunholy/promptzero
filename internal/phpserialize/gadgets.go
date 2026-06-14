package phpserialize

import "strings"

// gadgetPrefix flags class names whose namespace is a known phpggc / public
// PHP Object Injection gadget family. A match is a strong signal the blob is a
// crafted POP-chain payload, not benign application state.
var gadgetPrefix = []struct{ prefix, reason string }{ //nolint:gochecknoglobals
	{"Monolog\\", "Monolog gadget (phpggc — RCE via log handlers)"},
	{"GuzzleHttp\\", "Guzzle gadget (phpggc — RCE / file-write / SSRF)"},
	{"Illuminate\\", "Laravel/Illuminate gadget (phpggc — RCE)"},
	{"Faker\\", "Faker gadget (phpggc — Laravel RCE chain)"},
	{"Symfony\\Component\\", "Symfony gadget (phpggc — RCE / file ops)"},
	{"Doctrine\\", "Doctrine gadget (phpggc)"},
	{"Swift_", "SwiftMailer gadget (phpggc — file-write)"},
	{"Slim\\", "Slim gadget (phpggc — RCE)"},
	{"think\\", "ThinkPHP gadget (RCE)"},
	{"Requests_Utility_", "WordPress Requests gadget (phpggc — SSRF/RCE)"},
	{"GuzzleHttp\\Psr7\\", "Guzzle PSR-7 gadget (phpggc)"},
	{"phpseclib\\", "phpseclib gadget"},
	{"Phar", "Phar deserialization surface"},
	{"yii\\", "Yii gadget (RCE)"},
	{"Codeception\\", "Codeception gadget"},
	{"Laminas\\", "Laminas/Zend gadget"},
	{"Zend\\", "Zend gadget"},
	{"PHPUnit\\", "PHPUnit gadget (phpggc — RCE)"},
	{"Drupal\\", "Drupal gadget"},
	{"Magento\\", "Magento gadget"},
	{"CodeIgniter\\", "CodeIgniter gadget"},
}

// gadgetExact flags specific high-signal sink classes.
var gadgetExact = map[string]string{ //nolint:gochecknoglobals
	"GuzzleHttp\\Psr7\\FnStream":                 "Guzzle FnStream (phpggc RCE sink)",
	"GuzzleHttp\\HandlerStack":                   "Guzzle HandlerStack (phpggc RCE sink)",
	"GuzzleHttp\\Cookie\\FileCookieJar":          "Guzzle FileCookieJar (phpggc file-write)",
	"Monolog\\Handler\\SyslogUdpHandler":         "Monolog SyslogUdpHandler (phpggc RCE)",
	"Monolog\\Handler\\BufferHandler":            "Monolog BufferHandler (phpggc RCE)",
	"Illuminate\\Broadcasting\\PendingBroadcast": "Laravel PendingBroadcast (phpggc RCE)",
	"Faker\\Generator":                           "Faker Generator (phpggc Laravel RCE)",
	"Faker\\DefaultGenerator":                    "Faker DefaultGenerator (phpggc Laravel RCE)",
}

// gadgetReason returns the gadget reason for a class name, or "" if benign.
func gadgetReason(name string) string {
	if r, ok := gadgetExact[name]; ok {
		return r
	}
	for _, g := range gadgetPrefix {
		if strings.HasPrefix(name, g.prefix) {
			return g.reason
		}
	}
	return ""
}
