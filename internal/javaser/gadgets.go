package javaser

import "strings"

// gadgetExact maps a class name to the gadget family it belongs to. These are
// the classes ysoserial and the public deserialization-gadget research use to
// turn readObject() into RCE / SSRF / file-write. Presence is a strong signal
// the stream is a crafted payload, not benign application state.
var gadgetExact = map[string]string{ //nolint:gochecknoglobals
	// Commons-Collections (CC1-7) — the canonical RCE chains.
	"org.apache.commons.collections.functors.InvokerTransformer":     "CommonsCollections gadget (reflective method invoke)",
	"org.apache.commons.collections.functors.ChainedTransformer":     "CommonsCollections gadget (transformer chain)",
	"org.apache.commons.collections.functors.ConstantTransformer":    "CommonsCollections gadget",
	"org.apache.commons.collections.functors.InstantiateTransformer": "CommonsCollections gadget",
	"org.apache.commons.collections.map.LazyMap":                     "CommonsCollections gadget (lazy-map trigger)",
	"org.apache.commons.collections.map.TransformedMap":              "CommonsCollections gadget (transformed-map trigger)",
	"org.apache.commons.collections.keyvalue.TiedMapEntry":           "CommonsCollections gadget",
	"org.apache.commons.collections4.functors.InvokerTransformer":    "CommonsCollections4 gadget (reflective method invoke)",
	"org.apache.commons.collections4.functors.ChainedTransformer":    "CommonsCollections4 gadget",
	"org.apache.commons.collections4.functors.ConstantTransformer":   "CommonsCollections4 gadget",
	"org.apache.commons.collections4.map.LazyMap":                    "CommonsCollections4 gadget",
	"org.apache.commons.collections4.map.TransformedMap":             "CommonsCollections4 gadget",
	// Xalan TemplatesImpl — load arbitrary bytecode (CC3/4, Spring, etc.).
	"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": "TemplatesImpl gadget (loads attacker bytecode)",
	// Reflection / JRE-only chains.
	"sun.reflect.annotation.AnnotationInvocationHandler":        "JRE reflection gadget (annotation handler)",
	"javax.management.BadAttributeValueExpException":            "JRE gadget (toString trigger)",
	"java.rmi.server.RemoteObjectInvocationHandler":             "JRMP / RMI gadget",
	"java.rmi.server.UnicastRemoteObject":                       "RMI gadget",
	"javax.management.openmbean.CompositeDataInvocationHandler": "JMX gadget",
	// Commons-BeanUtils / Groovy / Spring / C3P0 / Clojure / Hibernate.
	"org.apache.commons.beanutils.BeanComparator":                               "CommonsBeanutils gadget (TemplatesImpl loader)",
	"org.codehaus.groovy.runtime.ConvertedClosure":                              "Groovy gadget",
	"org.codehaus.groovy.runtime.MethodClosure":                                 "Groovy gadget",
	"org.springframework.beans.factory.ObjectFactory":                           "Spring gadget",
	"org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider": "Spring gadget",
	"com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase":                         "C3P0 gadget (JNDI / classloader fetch)",
	"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource":                       "C3P0 gadget",
	"org.hibernate.engine.spi.TypedValue":                                       "Hibernate gadget",
	"org.hibernate.tuple.component.AbstractComponentTuplizer":                   "Hibernate gadget",
	// JNDI / LDAP fetch + ROME + misc.
	"javax.naming.InitialContext":             "JNDI gadget (remote object fetch)",
	"com.rometools.rome.feed.impl.ObjectBean": "ROME gadget",
	"com.sun.rowset.JdbcRowSetImpl":           "JdbcRowSet gadget (JNDI lookup)",
}

// gadgetPrefix flags whole dangerous packages even when the exact class isn't in
// the table above (gadget research adds variants constantly).
var gadgetPrefix = []struct{ prefix, reason string }{ //nolint:gochecknoglobals
	{"org.apache.commons.collections.functors.", "CommonsCollections functor (gadget family)"},
	{"org.apache.commons.collections4.functors.", "CommonsCollections4 functor (gadget family)"},
	{"com.mchange.v2.c3p0.", "C3P0 (gadget family)"},
	{"org.codehaus.groovy.runtime.", "Groovy runtime (gadget family)"},
	{"clojure.", "Clojure (gadget family)"},
	{"org.apache.myfaces.", "MyFaces (gadget family)"},
	{"org.apache.xbean.", "XBean (gadget family)"},
}

// gadgetReason returns the gadget reason for a class name, or "" if it is not a
// known gadget. The leading '[' / 'L' of array element class names is stripped.
func gadgetReason(name string) string {
	n := strings.TrimLeft(name, "[")
	n = strings.TrimPrefix(n, "L")
	n = strings.TrimSuffix(n, ";")
	if r, ok := gadgetExact[n]; ok {
		return r
	}
	for _, g := range gadgetPrefix {
		if strings.HasPrefix(n, g.prefix) {
			return g.reason
		}
	}
	return ""
}
