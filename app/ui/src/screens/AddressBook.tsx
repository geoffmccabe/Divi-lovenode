// Address Book: saved contacts, stored locally on the device. Full editing lands
// in a later slice; this shell reads/writes localStorage so it is usable now.
import { useEffect, useState } from "react";

interface Contact { name: string; address: string }
const KEY = "lovenode.contacts";

export function AddressBook() {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  useEffect(() => {
    try { setContacts(JSON.parse(localStorage.getItem(KEY) || "[]")); } catch { /* empty */ }
  }, []);
  const save = (next: Contact[]) => { setContacts(next); localStorage.setItem(KEY, JSON.stringify(next)); };
  const add = () => {
    if (!name.trim() || !address.trim()) return;
    save([...contacts, { name: name.trim(), address: address.trim() }]);
    setName(""); setAddress("");
  };

  return (
    <div className="card">
      <p className="h">Address Book</p>
      {contacts.length === 0 && <p className="sub">No contacts yet.</p>}
      {contacts.map((c, i) => (
        <div className="rowline" key={i}>
          <span>{c.name}</span>
          <span className="mono">{c.address.slice(0, 12)}…</span>
        </div>
      ))}
      <label>Name</label>
      <input value={name} onChange={(e) => setName(e.target.value)} />
      <label>Address</label>
      <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="D…" />
      <div style={{ height: 12 }} />
      <button className="ghost-btn" onClick={add}>Add contact</button>
    </div>
  );
}
