// Generic placeholder for greyed nav items (Collectibles, Meta Tokens, My Agent,
// Human Readable Addresses). Visible so the roadmap is legible, clearly not live.
export function ComingSoon({ label }: { label: string }) {
  return (
    <div className="card">
      <div className="coming">
        <div className="big">{label}</div>
        <div>Coming soon.</div>
      </div>
    </div>
  );
}
