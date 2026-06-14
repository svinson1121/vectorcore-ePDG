package session

func (s *Session) MarkFailed(code, text string) {
	s.FailureCode = code
	s.FailureText = text
	_ = s.Transition(StateFailed)
}
