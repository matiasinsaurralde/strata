LANGUAGE APPENDIX: Go

Containment — what `recover()` does and does not catch.
A `panic` unwinds and is catchable, so a framework's recovery middleware
genuinely contains it. These are *runtime aborts*, not panics; the process
dies even with recovery middleware installed, and `recover()` never runs:

  - fatal error: concurrent map writes
  - fatal error: concurrent map read and map write
  - fatal error: all goroutines are asleep - deadlock
  - out of memory / stack exhaustion

A panic in a goroutine the framework did not spawn is likewise uncatchable by
that framework's middleware — `recover()` is per-goroutine. An unbounded loop
is unrecoverable too: nothing unwinds a spinning goroutine.

So do not reason "the framework installs Recovery(), therefore contained".
Establish which of the two you have first.

Reachability — the documented-concurrency case.
A concurrency bug in an API the library DOCUMENTS for concurrent use (a
`Copy()`/`Clone()` handed to a goroutine, a `sync.Pool`, a shared cache) is
reachable by ordinary traffic from an application following the documented
pattern. That is not developer misuse: the library shipped the pattern. If
concurrent requests through the documented path produce a data race or a
fatal runtime abort, it is a fix.

Reachability — struct construction.
A nil dereference only reachable by a caller hand-constructing a struct that
the package's own constructors never produce is not attacker-reachable.
