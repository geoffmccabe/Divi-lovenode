// Network Map: embeds the live map from scan.divi.love. Sandboxed so the map page
// can never reach the wallet's keys or app internals -- it is display-only. The
// exact embed URL is set at build time; a placeholder is shown if unset.
// MUST stay a REMOTE, cross-origin URL. `allow-same-origin` below is only safe
// because the framed site is cross-origin (it cannot then remove its own sandbox
// or reach the key-holding parent). Never point this at a same-origin/local path.
const MAP_URL = "https://scan.divi.love/map"; // TODO: confirm the embed path

export function NetworkMap() {
  return (
    <div className="card">
      <p className="h">Divi network</p>
      <iframe
        className="map-frame"
        src={MAP_URL}
        title="Divi network map"
        sandbox="allow-scripts allow-same-origin"
        referrerPolicy="no-referrer"
      />
      <p className="sub">Live map of Divi nodes, served by scan.divi.love.</p>
    </div>
  );
}
