# Analysis: Diffing `Release` Files to Optimize Syncing

## Feasibility: Highly Feasible
Diffing the `Release` files (specifically, the old one residing in the `mirror` directory from the previous successful run, and the new one just downloaded into the `skel` directory) is **highly feasible** and a very elegant optimization.

Since `apt-mirror2` uses an atomic movement strategy (moving metadata from `skel` to `mirror` only after a successful sync), we are guaranteed that the `Release` file on disk (`Release_old`) accurately reflects the current state of our synced mirror.

By parsing both `Release_old` and `Release_new`, we can do a simple set difference on their `(filepath, size, hash)` tuples.

## 1. Context: Reducing Network Requests
Currently, when `apt-mirror2` processes metadata files listed in the `Release` file:
1. It looks at all requested compression variants (`.xz`, `.gz`, etc.).
2. It attempts a local `_check_hash` check (via `xattr` or full hash computation).
3. If that local check evaluates to `False` (e.g. hash changed, or `check_local_hash` is off), it triggers a download, which issues an HTTP request.
4. For unchanged files, the endpoint often returns a `304 Not Modified`, but *this still incurs a network round-trip for every single variant*.

**Impact of diffing `Release`:** 
If an entry (e.g. `main/binary-amd64/Packages.xz`) is identical in both `Release_old` and `Release_new`, we know with 100% certainty that the file upstream has not changed. We can mark it as unmodified **instantly**, completely bypassing the network request. This eliminates hundreds of superfluous HTTP requests (and TLS handshakes) per repository sync.

## 2. Context: Reducing Hash Computation Time
Currently, `_check_hash` looks for extended attributes (`user.apt_mirror.sha256`) to expedite local checks. When a file *is* updated upstream (i.e. its hash changed), the `_check_hash` function will:
1. See that the expected hash from `Release` does not match the `xattr`.
2. Fallback to computing the full hash of the file by reading the entire file from disk (attempting to see if the file contents somehow match the new hash).
3. Inevitably fail (since the old file content has the old hash), and then proceed to download the new file.

Furthermore, if the underlying filesystem doesn't support `xattr` or they get stripped, `apt-mirror2` recalculates the hashes for *every* metadata file, even unchanged ones.

**Impact of diffing `Release`:**
By using the diff as the source of truth, we know exactly which files are identical and which have changed, bypassing both the `xattr` check and the expensive fallback hash computation. We strictly compute hashes *only* for newly downloaded bytes.

## 3. Robustness Considerations
**Assume Reliable Storage:** 
Since we are assuming our NAS/disk is reliable, the diffing approach is entirely robust. 
- If a sync is interrupted or fails, the old `Release` file is never overwritten, meaning the next run will correctly diff against the last known-good state.
- Because `apt-mirror2` already supports self-healing and by-hash fetches, replacing the broad `_check_hash` with an upfront diff perfectly aligns with its architecture.

### What about `.deb` pools?
One critical detail to keep in mind is that while diffing `Release` files tells us which `Packages.xz` files didn't change, we **still need to parse those unchanged `Packages.xz` files locally**. 
If we simply ignore unchanged `Packages.xz` files, the `get_pool_files` component won't yield the `.deb` files they contain, which could cause the cleaner (`PathCleaner`) to flag all older packages for deletion. 
**Solution:** We skip the *fetch/hash* queue for unchanged index variants, but we still feed those existing files into `PackagesParser` to extract their package list.

## Conclusion
This approach is highly recommended. It transforms a mostly O(N) network-bound operation (where N is the number of metadata variants in the repository) into a lightweight O(1) CPU comparison of text files. 

It is also much faster than relying purely on filesystem stats and `need_update`. As long as local corruption isn't a factor (which can be handled by periodic "verify" runs executing the full hash checks), diffing the metadata index is the most efficient syncing method.
