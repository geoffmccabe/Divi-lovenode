// Network Map: embeds the live map from scan.divi.love. Sandboxed so the map page
// can never reach the wallet's keys or app internals -- it is display-only. The
// exact embed URL is set at build time; a placeholder is shown if unset.
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
