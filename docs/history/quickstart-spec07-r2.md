# Historical pre-policy walkthrough

Archived 2026-09-04. Commands and output below describe the named older bookmark, not this release. Use [the current quickstart](../quickstart.md).

# Quickstart

Boot a kernel, define a Kind, admit an instance, collect a denial, export the
chain, and verify it on a machine with no network. Every command below was run
against this repository at bookmark `verifier-spec-07-r2` on 2026-09-02; the
outputs are that run's.

Requires Elixir 1.19, Erlang/OTP 28 and Rust 1.92 with Cargo
(`.tool-versions` pins all three), plus `curl`, `python3` and `jq`. Rust builds
the Cedar policy engine NIF. For the container path instead, skip to
[Docker](#docker).

## 1. Start the kernel

```sh
mix deps.get
mix run --no-halt
# meta-API listening on http://localhost:4545
```

State lands in `.r5e/`. On first boot the node generates an ed25519 keypair
under `.r5e/keys/`, mode 0600; the private key never leaves that directory.
`R5E_DATA_DIR` and `R5E_PORT` override both.

The kernel writes ten events before any caller arrives — its nine core Kind
seeds, then the node key's Endorsement of the retention key:

```sh
curl -s http://localhost:4545/events | jq '.events | length'
# 10
```

## 2. A signing client

Every admission is a signed request object in a DSSE envelope (spec/06 §1).
The kernel does not sign for callers, so a client holds its own key. Save this
as `sign.exs` **in `../r5e-core/verifier`** — it needs canonical encoding and
the key-id derivation, and that Apache-licensed package is the one
implementation of both:

```elixir
# mix run --no-start sign.exs ORIGIN GROUP/VERSION/KIND SPEC_JSON [NAME]
[origin, target, spec_json | rest] = System.argv()
spec = Jason.decode!(spec_json)
{pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
keyid = RecurseVerify.DSSE.key_id!("ed25519", pub)
[g, v, k] = String.split(target, "/")

request = %{
  "origin" => origin,
  "actor" => keyid,
  "target" => %{"group" => g, "version" => v, "kind" => k, "name" => List.first(rest)},
  "specAddress" =>
    "sha256:" <>
      Base.encode16(:crypto.hash(:sha256, RecurseVerify.Canonical.encode(spec)), case: :lower),
  "derivedFrom" => nil,
  "authority" => [],
  "nonce" => Base.encode64(:crypto.strong_rand_bytes(16)),
  "expires" => DateTime.utc_now() |> DateTime.add(3600) |> DateTime.to_iso8601()
}

type = "application/vnd.r5e.admission-request+json;v=1"
payload = RecurseVerify.Canonical.encode(request)
sig = :crypto.sign(:eddsa, :none, RecurseVerify.DSSE.pae(type, payload), [priv, :ed25519])

envelope = %{
  "payloadType" => type,
  "payload" => Base.encode64(payload),
  "signatures" => [%{"keyid" => keyid, "sig" => Base.encode64(sig)}],
  "publicKeys" => [%{"keyid" => keyid, "algorithm" => "ed25519", "bytes" => Base.encode64(pub)}]
}

IO.puts(Jason.encode!(%{"envelope" => envelope, "spec" => spec, "name" => List.first(rest)}))
```

It mints a fresh key per invocation, which keeps the example short and is the
one thing a real client must not do.

Inside this repository the same object is built by `R5e.Request.sign/3`, which
is the only writer: bootstrap, the retention sweeper and the vector runner all
go through it, so nothing here can sign a shape the gate would refuse.

The origin is on the chain, in event 1's payload, and it is signed — so an
envelope minted for one chain cannot be replayed onto another:

```sh
ORIGIN=$(curl -s http://localhost:4545/events \
  | python3 -c 'import json,sys,urllib.request;e=json.load(sys.stdin)["events"][0];
print(json.load(urllib.request.urlopen("http://localhost:4545/cas/"+e["payload"]))["origin"])')
```

## 3. Define a Kind

Vocabulary enters through the same door as everything else. `epistemicScope`
is omitted deliberately below: it gets the modest default and is flagged
`scopeDefaulted` everywhere it appears afterwards.

```sh
cd ../r5e-core/verifier
mix run --no-start sign.exs "$ORIGIN" core.r5e.io/v1/KindDefinition \
  '{"group":"recurse.r5e.io","kind":"Note","version":"v1alpha1","substrate":"resource",
    "naming":{"mode":"caller"},"predicates":[],
    "schema":{"required":["title"],"properties":{"title":{"type":"string"}},
              "additionalProperties":false}}' > kind.json

curl -s -X POST http://localhost:4545/apis/core.r5e.io/v1/KindDefinition \
  -H 'content-type: application/json' -d @kind.json
# {"outcome":"admitted","name":"recurse.r5e.io/v1alpha1/Note","identity":"signed","seq":11, …}
```

The route must equal the signed target; the signature covers the *address* of
the spec, so the spec bytes travel beside the envelope rather than inside it.

## 4. Admit an instance, then a denial

```sh
mix run --no-start sign.exs "$ORIGIN" recurse.r5e.io/v1alpha1/Note \
  '{"title":"hello, chain"}' first-note > note.json

curl -s -X POST http://localhost:4545/apis/recurse.r5e.io/v1alpha1/Note \
  -H 'content-type: application/json' -d @note.json
# {"outcome":"admitted","name":"first-note","seq":12,"scopeDefaulted":true,
#  "specAddress":"sha256:15ca7b2dd6b60ae3dd96fae4c94790e2392c18c491af01a0858450f9b592d715", …}
```

A request the schema refuses is refused *and recorded*:

```sh
mix run --no-start sign.exs "$ORIGIN" recurse.r5e.io/v1alpha1/Note \
  '{"headline":"no title here"}' second-note > bad.json

curl -s -X POST http://localhost:4545/apis/recurse.r5e.io/v1alpha1/Note \
  -H 'content-type: application/json' -d @bad.json
# {"outcome":"denied","recorded":true,"seq":13,
#  "reason":"validateStructure: schema: /: undeclared key \"headline\" (additionalProperties is false)", …}
```

Two refusals happen before anything is recorded — a malformed envelope and a
signature that does not verify. Those carry `"recorded": false`: nobody is
known to have asked, so nothing is written and no nonce is spent.

## 5. Export and verify offline

```sh
BUNDLE=$(curl -s -X POST http://localhost:4545/export \
  -H 'content-type: application/json' -d '{}' | jq -r .bundle)
mix r5e.verify "$BUNDLE"          # from r5e-kernel
```

Or without this repository at all — build the escript in
`../r5e-core/verifier` and hand it the same directory:

```sh
mix escript.build
./recurse_verify "$BUNDLE"
```

The first lines of that run:

```
checked:
  chain: intact -- 13 events, seq contiguous, every hash recomputed from canonical encoding, every prev link verified
  checkpoint signature: verified (ed25519 over DSSE PAE) against bundled key sha256:2136a9a53915... -- proves log integrity as attested by that key, NOT the key holder's identity
  STH: signed chain head matches the last event hash (seq 13)
  merkle: root rebuilt from 13 event hashes matches the signed STH root; inclusion proofs generated and verified for all 13 events
  payloads: 13/13 event payloads present in bundle CAS and matching their address
  claims: 12 admissions, 1 denials, by 4 actor(s) …
  signatures: 12 of 12 admissions signed and verified with the keys on their payloads; 0 legacy unsigned
```

Read the whole output, including the `not checked` block. What it proves and
does not is the verifier's own subject: see
[`../../r5e-core/verifier/README.md`](../../r5e-core/verifier/README.md) and
`r5e-core/spec/07-verifier.md`.

Given an earlier export, `--prior` additionally proves the log extends that
signed tree head append-only (RFC 9162 consistency):

```sh
mix r5e.verify "$BUNDLE" --prior "$OLD_BUNDLE"
# consistency: prior STH (tree size 12, signature verified against its own bundled key
# sha256:2136a9a53915...) is consistent with this log (tree size 13) -- the log extends
# the earlier checkpoint append-only, nothing before seq 12 was rewritten
```

A bundle carrying an admitted Badge needs `--posture house|commons`, which
`mix r5e.verify` does not pass through; use the escript for those.

## Raw bytes

Anything a Kind cites as `bytes:sha256:…` enters through `PUT /cas`, which is
an admission of a `core.r5e.io/v1/CasObject`. The kernel hashes the body,
builds the spec itself, and writes the bytes as the `admit` step of a granted
admission — so the client signs a request whose `specAddress` is the address of
`{"address","size","class","mediaType"}`, and the envelope rides in a header
because the body is the object:

```sh
curl -s -X PUT http://localhost:4545/cas \
  -H 'content-type: text/plain' \
  -H "x-r5e-request: $(base64 < envelope.json)" \
  --data-binary 'list the files, then remove the temp directory'
# {"outcome":"admitted","address":"bytes:sha256:2d419df2d3309e4b…","size":46,
#  "eventRef":"event:sha256:ada2f9bae4989c1a…","identity":"signed", …}

curl -s http://localhost:4545/cas/bytes:sha256:2d419df2d3309e4b…
# list the files, then remove the temp directory
```

## Docker

The kernel has a path dependency on the verifier in `../r5e-core`, so the
build context is the parent directory holding both repositories side by side.

```sh
cd ..
docker build -f r5e-kernel/Dockerfile -t r5e-kernel .
docker run -d --name r5e -p 4545:4545 -v r5e-data:/data r5e-kernel
```

`r5e-kernel/Dockerfile.dockerignore` trims that context to the two trees, and
BuildKit is what reads it. Without buildx the legacy builder still produces the
image — it just sends the whole parent directory as context. Both were run on
2026-09-02; the resulting image is 54 MB.

Steps 2 to 5 above then work unchanged against `http://localhost:4545`. The
export lands inside the container, and the image carries `recurse_verify` on
PATH:

```sh
BUNDLE=$(curl -s -X POST http://localhost:4545/export \
  -H 'content-type: application/json' -d '{}' | jq -r .bundle)
docker exec r5e recurse_verify "$BUNDLE"
# chain: intact -- 10 events, …
```

To verify outside the container, copy the bundle out and hand it to any build
of the verifier — `docker cp r5e:"$BUNDLE" ./bundle`.

`docker compose up -d --build` does the build and run in one command, from
`r5e-kernel/`; it needs BuildKit.
