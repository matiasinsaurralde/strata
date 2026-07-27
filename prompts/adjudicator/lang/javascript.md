LANGUAGE APPENDIX: JavaScript / TypeScript (Node.js)

Containment — what `try/catch` does and does not catch.
A synchronous throw inside a framework's handler is contained. These are not:

  - a rejected promise nobody awaited: under Node's default
    `--unhandled-rejections=throw` this terminates the process
  - a throw inside a callback invoked from the event loop (a stream `data`
    handler, a timer, an `EventEmitter` listener) — the surrounding
    `try/catch` has already returned. An `'error'` event with no listener
    throws and exits.
  - `process.exit`, an OOM abort, a V8 fatal error
  - a blocking synchronous call or an unbounded loop: the single-threaded
    event loop is blocked, so this starves EVERY concurrent request, not just
    the one that triggered it. Catastrophic-backtracking regexes (ReDoS) are
    the usual form and are always a denial of service, never merely slow.

Reachability.
Prototype pollution is the pattern to check for by default: any recursive
merge, `JSON.parse` result spread into an object, or query-string parser that
does not reject `__proto__`, `constructor` and `prototype` keys. A fix adding
one of those guards is narrowing a real surface.

Other sinks worth tracing to their argument: `child_process.exec`,
`vm.runInNewContext`, `require()` of a computed path, and any template or
`innerHTML` sink reached from a request.
