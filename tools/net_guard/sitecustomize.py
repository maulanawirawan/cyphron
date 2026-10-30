"""Entry tipis sitecustomize untuk net-guard Fase 2-B.

Python meng-import module bernama `sitecustomize` secara otomatis saat
startup. Runner Rust memuat modul ini lewat PYTHONPATH yang memuat
tools/net_guard. Hanya bertindak bila CYPHRON_NET_GUARD=1 (dilihat
core/net_guard.auto_install_from_env); tanpa env itu, Python biasa —
perilaku skill manual tidak berubah.

Import core.net_guard butuh <root> repo di sys.path — runner memasukkan
root di PYTHONPATH juga. Kalau import gagal pada mode guard, tulis
peringatan ke stderr; runner yang memverifikasi audit log akan menandai
skill tanpa bukti guard (fase berikutnya) — fail-closed dua lapis.
"""
import sys

try:
    from core.net_guard import auto_install_from_env
    auto_install_from_env()
except Exception as _exc:  # pragma: no cover — jalur startup
    if sys.modules.get("cyphron_net_guard_expected"):
        print(f"WARN: sitecustomize net-guard gagal: {_exc}",
              file=sys.stderr)
