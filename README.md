# A Cobalt Strike memory injector


## What is this tool?

This tool will inject data into another process's memory address
space. The payload is **not** actually run.

## Why do I want to use it?

This tool is used to test memory scanning abilities of security
tools. The sample we inject comes from a Cobalt Strike beacon (from
Virus Total) and so it should trigger memory based detections.  Note
that since the payload is never executed, it is benign but it looks
real enough for virus scanners.

Usually Windows Defender will scan a process's memory soon after
scanning so we implement a short wait before we actually inject the
data. This is purely to avoid Windows Defender triggering on the
memory injector itself.
