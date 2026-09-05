#!/usr/bin/env python3
"""Generate backend/go.work mapping unreachable module hosts to their canonical
GitHub mirrors. Local dev-sandbox artifact only — go.mod/go.sum stay untouched."""
import re
from pathlib import Path

MOD = Path(__file__).resolve().parent.parent / "backend" / "go.sum"
OUT = Path(__file__).resolve().parent.parent / "backend" / "go.work"

text = MOD.read_text()
mods = {}
for line in text.splitlines():
    parts = line.split()
    if len(parts) < 2:
        continue
    path, ver = parts[0], parts[1]
    if ver.endswith("/go.mod"):
        ver = ver[: -len("/go.mod")]
    if not re.match(r"^v[0-9]", ver):
        continue
    mods.setdefault(path, set()).add(ver)

# canonical GitHub mirrors for hosts unreachable from this sandbox
def mirror(path: str):
    if path.startswith("golang.org/x/"):
        return "github.com/golang/" + path[len("golang.org/x/"):]
    if path == "google.golang.org/protobuf":
        return "github.com/protocolbuffers/protobuf-go"
    if path == "google.golang.org/grpc":
        return "github.com/grpc/grpc-go"
    if path == "google.golang.org/api":
        return "github.com/googleapis/google-api-go-client"
    if path == "google.golang.org/genai":
        return "github.com/googleapis/go-genai"
    if path == "google.golang.org/appengine":
        return "github.com/golang/appengine"
    if path.startswith("google.golang.org/genproto"):
        return "github.com/googleapis/go-genproto" + path[len("google.golang.org/genproto"):]
    if path == "cloud.google.com/go":
        return "github.com/googleapis/google-cloud-go"
    if path.startswith("cloud.google.com/go/"):
        return "github.com/googleapis/google-cloud-go/" + path[len("cloud.google.com/go/"):]
    if path == "go.opentelemetry.io/otel" or path.startswith("go.opentelemetry.io/otel/"):
        return "github.com/open-telemetry/opentelemetry-go" + path[len("go.opentelemetry.io/otel"):]
    if path == "go.opentelemetry.io/auto/sdk":
        return "github.com/open-telemetry/opentelemetry-go/auto/sdk"
    if path.startswith("go.opentelemetry.io/contrib/"):
        return "github.com/open-telemetry/opentelemetry-go-contrib/" + path[len("go.opentelemetry.io/contrib/"):]
    if path == "go.opentelemetry.io/proto/otlp":
        return "github.com/open-telemetry/opentelemetry-proto-go/otlp"
    if path.startswith("go.uber.org/"):
        return "github.com/uber-go/" + path[len("go.uber.org/"):]
    if path == "gopkg.in/yaml.v2":
        return "github.com/go-yaml/yaml"
    if path == "gopkg.in/yaml.v3":
        return "github.com/go-yaml/yaml"
    if path == "gopkg.in/check.v1":
        return "github.com/go-check/check"
    if path == "gopkg.in/go-playground/assert.v1":
        return "github.com/go-playground/assert"
    if path == "gopkg.in/go-playground/validator.v8":
        return "github.com/go-playground/validator"
    if path.startswith("gitlab.com/golang-commonmark/"):
        return "github.com/golang-commonmark/" + path[len("gitlab.com/golang-commonmark/"):]
    if path == "gitlab.com/opennota/wd":
        return "github.com/opennota/wd"
    if path == "dario.cat/mergo":
        return "github.com/imdario/mergo"
    if path == "filippo.io/edwards25519":
        return "github.com/FiloSottile/edwards25519"
    if path == "go.starlark.net":
        return "github.com/google/starlark-go"
    if path == "gonum.org/v1/gonum":
        return "github.com/gonum/gonum"
    if path == "gotest.tools/v3":
        return "github.com/gotestyourself/gotest.tools"
    if path == "howett.net/plist":
        return "github.com/DHowett/go-plist"
    if path == "mellium.im/sasl":
        return "github.com/mellium/sasl"
    if path.startswith("modernc.org/"):
        return "github.com/modernc/" + path[len("modernc.org/"):]
    if path == "nhooyr.io/websocket":
        return "github.com/nhooyr/websocket"
    if path == "pgregory.net/rapid":
        return "github.com/flyingmutant/rapid"
    if path == "sigs.k8s.io/yaml":
        return "github.com/kubernetes-sigs/yaml"
    if path == "nullprogram.com/x/optparse":
        return "github.com/skeeto/optparse"
    if path == "rsc.io/pdf":
        return "github.com/rsc/pdf"
    return None

replaces = []
unmapped = []
for path in sorted(mods):
    # skip go.mod-only modules that are pure transitive metadata of github deps
    dst = mirror(path)
    if dst is None:
        unmapped.append(path)
        continue
    for ver in sorted(mods[path]):
        replaces.append(f"\treplace {path} {ver} => {dst} {ver}")

lines = ["go 1.26.5", "", "use .", ""]
lines += replaces
OUT.write_text("\n".join(lines) + "\n")
print(f"wrote {OUT} with {len(replaces)} replaces")
if unmapped:
    print("UNMAPPED:", *unmapped, sep="\n  ")
