package agent

import "github.com/anthropics/anthropic-sdk-go/v2"

// anthropic-sdk-go v2 replaced the MessageParam {Role, Content} struct
// with a union (OfUser / OfAssistant / OfSystem), each arm carrying its
// own typed role constant and Content slice. These helpers recover the
// role string and content-block accessors the agent's history logic
// relied on, so the union lives in one place instead of every call site.

// Role strings, matching the wire values the SDK marshals for each arm.
const (
	roleUser      = "user"
	roleAssistant = "assistant"
	roleSystem    = "system"
)

// paramRole returns the role string for a MessageParam union arm, or ""
// when the union is empty (zero value).
func paramRole(m anthropic.MessageParam) string {
	switch {
	case m.OfUser != nil:
		return roleUser
	case m.OfAssistant != nil:
		return roleAssistant
	case m.OfSystem != nil:
		return roleSystem
	default:
		return ""
	}
}

// paramContent returns the content blocks for a user or assistant
// MessageParam. System messages carry []TextBlockParam rather than
// content-block unions and return nil here (the agent never inspects
// system-message blocks via this path).
func paramContent(m anthropic.MessageParam) []anthropic.ContentBlockParamUnion {
	switch {
	case m.OfUser != nil:
		return m.OfUser.Content
	case m.OfAssistant != nil:
		return m.OfAssistant.Content
	default:
		return nil
	}
}
