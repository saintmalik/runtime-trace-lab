// Promote policy: allowlist what you expect — do NOT denylist attacker domains.
// You will not know C2 DNS ahead of time. Unknown named destinations fail.
//
// Pure numeric IPs are allowed here because host Tetragon on GHA is full of
// dockerd/Azure/apk mirror IPs; that is a scoping limitation, not a perfect model.
predicateType: "https://in-toto.io/attestation/runtime-trace/v0.1"

predicate: {
	monitorLog: {
		// Unexpected dropper paths (e.g. /tmp/curl-exfil) — no need to know C2.
		process: [...{
			processBinary: !~"^/tmp/"
		}]
		network: [...{
			destination: =~"^([0-9.]+|\\[[0-9a-fA-F:]+\\])(:[0-9]+)?$|^(proxy\\.golang\\.org|sum\\.golang\\.org|storage\\.googleapis\\.com|github\\.com|ghcr\\.io|objects\\.githubusercontent\\.com|registry\\.npmjs\\.org|dl-cdn\\.alpinelinux\\.org)(:[0-9]+)?$"
		}]
	}
}
