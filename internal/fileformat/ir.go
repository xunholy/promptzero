package fileformat

import (
	"fmt"
	"strconv"
	"strings"
)

// IRSignal is one button entry in a Flipper .ir remote file. Parsed-type
// entries carry Protocol/Address/Command; raw-type entries carry Frequency,
// DutyCycle, and a Data timing list (microseconds).
type IRSignal struct {
	Name      string
	Type      string
	Protocol  string
	Address   string
	Command   string
	Frequency int
	DutyCycle float64
	Data      []int
}

// IRFile is a parsed .ir universal-remote / capture file — zero or more
// signals separated by "#" marker lines.
type IRFile struct {
	Filetype string
	Version  int
	Signals  []IRSignal
}

// ParseIR parses a Flipper .ir remote/library file. Accepts CRLF, LF, a
// missing final newline, blank lines, and treats leading "#" lines as
// signal separators.
func ParseIR(data []byte) (*IRFile, error) {
	f := &IRFile{}
	var current *IRSignal
	commit := func() {
		if current != nil {
			f.Signals = append(f.Signals, *current)
			current = nil
		}
	}
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			commit()
			current = &IRSignal{}
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		if current == nil {
			// Header block before the first signal separator.
			switch key {
			case "Filetype":
				f.Filetype = value
			case "Version":
				v, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("ir: invalid Version %q: %w", value, err)
				}
				f.Version = v
			}
			continue
		}
		switch key {
		case "name":
			current.Name = value
		case "type":
			current.Type = value
		case "protocol":
			current.Protocol = value
		case "address":
			current.Address = value
		case "command":
			current.Command = value
		case "frequency":
			v, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("ir: invalid frequency %q: %w", value, err)
			}
			current.Frequency = v
		case "duty_cycle":
			v, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return nil, fmt.Errorf("ir: invalid duty_cycle %q: %w", value, err)
			}
			current.DutyCycle = v
		case "data":
			for _, tok := range strings.Fields(value) {
				n, err := strconv.Atoi(tok)
				if err != nil {
					return nil, fmt.Errorf("ir: invalid data token %q: %w", tok, err)
				}
				current.Data = append(current.Data, n)
			}
		}
	}
	commit()
	if f.Filetype == "" {
		return nil, fmt.Errorf("ir: missing Filetype header")
	}
	return f, nil
}

// Marshal serializes f back to canonical .ir bytes. Header lines first,
// then one "#"-separated block per signal. Parsed signals emit
// name/type/protocol/address/command; raw signals emit
// name/type/frequency/duty_cycle/data.
func (f *IRFile) Marshal() []byte {
	var b strings.Builder
	writeKV(&b, "Filetype", f.Filetype)
	if f.Version != 0 {
		writeKV(&b, "Version", strconv.Itoa(f.Version))
	}
	for _, sig := range f.Signals {
		b.WriteString("#\n")
		if sig.Name != "" {
			writeKV(&b, "name", sig.Name)
		}
		if sig.Type != "" {
			writeKV(&b, "type", sig.Type)
		}
		if sig.Type == "raw" {
			if sig.Frequency != 0 {
				writeKV(&b, "frequency", strconv.Itoa(sig.Frequency))
			}
			if sig.DutyCycle != 0 {
				writeKV(&b, "duty_cycle", strconv.FormatFloat(sig.DutyCycle, 'f', 6, 64))
			}
			if len(sig.Data) > 0 {
				parts := make([]string, len(sig.Data))
				for i, v := range sig.Data {
					parts[i] = strconv.Itoa(v)
				}
				writeKV(&b, "data", strings.Join(parts, " "))
			}
			continue
		}
		if sig.Protocol != "" {
			writeKV(&b, "protocol", sig.Protocol)
		}
		if sig.Address != "" {
			writeKV(&b, "address", sig.Address)
		}
		if sig.Command != "" {
			writeKV(&b, "command", sig.Command)
		}
	}
	return []byte(b.String())
}

func applyIREdits(f *IRFile, edits map[string]interface{}) error {
	for k, v := range edits {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, "signal_") {
			return fmt.Errorf("unknown .ir edit key %q (allowed: signal_<n>_name, signal_<n>_address, signal_<n>_command)", k)
		}
		rest := strings.TrimPrefix(lk, "signal_")
		sep := strings.IndexByte(rest, '_')
		if sep <= 0 {
			return fmt.Errorf("invalid .ir edit key %q: expected signal_<n>_<field>", k)
		}
		idx, err := strconv.Atoi(rest[:sep])
		if err != nil {
			return fmt.Errorf("invalid signal index in %q: %w", k, err)
		}
		if idx < 0 || idx >= len(f.Signals) {
			return fmt.Errorf("signal index %d out of range (0..%d)", idx, len(f.Signals)-1)
		}
		field := rest[sep+1:]
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("signal edits must be strings: %q", k)
		}
		switch field {
		case "name":
			f.Signals[idx].Name = str
		case "address":
			f.Signals[idx].Address = str
		case "command":
			f.Signals[idx].Command = str
		default:
			return fmt.Errorf("unknown .ir signal field %q (allowed: name, address, command)", field)
		}
	}
	return nil
}
