// Proof of Existence: anchor a file's hash on-chain (C2PA Content Credential).
// Backend (lovenode-c2pa + an anchor tx) lands in a later slice; this is the
// screen shell so the flow is navigable.
export function ProofOfExistence() {
  return (
    <div className="card">
      <p className="h">Proof of Existence</p>
      <p className="sub">
        Anchor a photo or document so you can later prove it existed by a certain
        time. Anchored content also carries a standard Content Credential.
      </p>
      <div style={{ height: 12 }} />
      <button className="ghost-btn" disabled>Choose a file to anchor</button>
      <p className="sub" style={{ marginTop: 10 }}>Anchoring wiring is in progress.</p>
    </div>
  );
}
