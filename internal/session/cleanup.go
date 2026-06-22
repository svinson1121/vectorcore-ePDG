package session

// MarkFailed must be called with s.Lock held.
func (s *Session) MarkFailed(code, text string) {
	s.FailureCode = code
	s.FailureText = text
	_ = s.Transition(StateFailed)
}
