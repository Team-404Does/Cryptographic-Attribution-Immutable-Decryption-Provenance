import { useEffect, useState } from "react";
import { api } from "../api.js";

/** id -> display name for operators, recipients and documents (best effort, for readable logs). */
export function useNames() {
  const [names, setNames] = useState({});
  useEffect(() => {
    let alive = true;
    Promise.allSettled([api.get("/api/auth/operators"), api.get("/api/recipients"), api.get("/api/documents")])
      .then(([o, r, d]) => {
        if (!alive) return;
        const m = {};
        (o.value || []).forEach((x) => { m[x.id] = x.name; });
        (r.value || []).forEach((x) => { m[x.id] = x.name; });
        (d.value || []).forEach((x) => { m[x.id] = x.title; });
        setNames(m);
      });
    return () => { alive = false; };
  }, []);
  return names;
}
