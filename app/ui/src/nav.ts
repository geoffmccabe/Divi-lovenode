// LoveNode navigation model. Hybrid: `primary` items are the bottom tab bar;
// everything appears in the slide-out menu. `comingSoon` items render greyed with
// a "Coming soon" placeholder instead of a live screen.
//
// Adapted from DD69's nav, trimmed for the phone: no separate Transaction History
// (the Overview covers it) and no Governance (yet).

export interface NavItem {
  id: string;
  label: string;
  /** Shown in the bottom tab bar (the most-used screens). */
  primary?: boolean;
  /** Greyed, not yet built — renders a "Coming soon" placeholder. */
  comingSoon?: boolean;
}

export const NAV: NavItem[] = [
  { id: "overview", label: "Overview", primary: true },
  { id: "send", label: "Send", primary: true },
  { id: "receive", label: "Receive", primary: true },
  { id: "poe", label: "Proof of Existence" },
  { id: "addressbook", label: "Address Book" },
  { id: "map", label: "Network Map" },
  { id: "settings", label: "Settings" },
  // greyed "Coming soon" slots — visible so the roadmap is legible
  { id: "agent", label: "My Agent", comingSoon: true },
  { id: "hra", label: "Human Readable Addresses", comingSoon: true },
  { id: "collectibles", label: "Divi Collectibles", comingSoon: true },
  { id: "tokens", label: "Divi Meta Tokens", comingSoon: true },
];

export const PRIMARY = NAV.filter((n) => n.primary);
