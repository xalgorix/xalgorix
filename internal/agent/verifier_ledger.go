package agent

import "github.com/xalgord/xalgorix/v4/internal/scanctx"

// settleVerifierHypothesis sets the ledger status of a hypothesis a verifier
// just recorded exploit evidence on. Upsert alone cannot do this: when the
// confirmation merges into an existing record (an engine seed, a lead the model
// queued or rejected, or one that was auto-exhausted), Upsert keeps that
// record's status, so a confirmed exploit could sit on a record every gate
// ignores.
//
// A deterministic in-band differential (proven: a DBMS error break/recover, an
// evaluated random product, leaked file content, a timing differential) marks
// the hypothesis proven, so the finish gate holds the scan until it is
// reported. Other signals (out-of-band callbacks, cross-identity response
// comparisons) reopen queued, blocked or exhausted work as testing for the
// model to conclude, but never override a model rejection. When a delegated
// specialist ran the verifier, the hypothesis is assigned to it so the
// specialist's own finish gate sees the work.
func (a *Agent) settleVerifierHypothesis(l *scanctx.LedgerStore, id string, proven bool, note string) {
	if l == nil || id == "" {
		return
	}
	if a.delegatedAgentID != "" {
		l.MarkAssigned(id, a.delegatedAgentID)
	}
	cur, ok := l.Get(id)
	if !ok || cur.Status == scanctx.HypothesisProven {
		return
	}
	if proven {
		l.SetStatus(id, scanctx.HypothesisProven, note)
		return
	}
	switch cur.Status {
	case scanctx.HypothesisQueued, scanctx.HypothesisBlocked, scanctx.HypothesisExhausted:
		l.SetStatus(id, scanctx.HypothesisTesting, note)
	}
}
