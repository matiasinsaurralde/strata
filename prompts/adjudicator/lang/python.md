LANGUAGE APPENDIX: Python

Containment — what `except` does and does not catch.
`except Exception` is the usual containment boundary and a WSGI/ASGI server
wraps each request in one, so an ordinary exception is contained. These
escape it:

  - `MemoryError` and `RecursionError` reached through a deep or unbounded
    structure — often survivable per-request, but a repeated hit degrades
    the whole worker
  - a segfault or abort inside a C extension (`ctypes`, a native parser, a
    crypto binding): the interpreter dies, no handler runs
  - `os._exit`, `sys.exit` from a signal handler, an OOM kill
  - an unbounded loop or a blocking call with no timeout: nothing unwinds it,
    and in an async server it also starves every other coroutine on the loop
  - an exception raised in a thread or an un-awaited task, which never
    reaches the request's handler

Concurrency.
The GIL prevents torn machine words, not logical races. Check-then-act on a
module-level dict or a cached client is still a TOCTOU, and in async code any
`await` inside a critical section is a yield point where another request
interleaves.

Reachability.
Deserialisation sinks are the common one: `pickle.loads`, `yaml.load` without
`SafeLoader`, `eval`/`exec`, `subprocess(..., shell=True)`, and
`jinja2.Template(...)` built from a request string. Trace whether the argument
is attacker-controlled rather than assuming it from the call alone.
