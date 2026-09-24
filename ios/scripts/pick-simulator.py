"""Print the UDID of an available iPhone simulator on the newest iOS runtime.

Reads `xcrun simctl list devices available -j` on stdin. Prefers a plain
"iPhone NN" (a common 6.1" size) so screenshots stay comparable across runs.
"""
import json
import re
import sys

# Only runtimes the selected Xcode's SDK can target: CoreSimulator is shared
# between installed Xcodes, so a newer runtime may be listed that this SDK
# cannot build for (cold review r1 B2).
max_sdk = tuple(int(x) for x in sys.argv[1].split(".")[:2]) if len(sys.argv) > 1 else (99, 99)
devices = json.load(sys.stdin)["devices"]
best = None
for runtime, devs in devices.items():
    m = re.search(r"iOS-(\d+)-(\d+)", runtime)
    if not m:
        continue
    version = (int(m.group(1)), int(m.group(2)))
    if version > max_sdk:
        continue
    for d in devs:
        name = d["name"]
        if not name.startswith("iPhone") or not d.get("isAvailable", True):
            continue
        plain = re.fullmatch(r"iPhone \d+", name) is not None
        key = (version, plain, name)
        if best is None or key > best[0]:
            best = (key, d["udid"])
if best is None:
    sys.exit("no iPhone simulator available")
print(f"picked {best[0]}", file=sys.stderr)
print(best[1])
