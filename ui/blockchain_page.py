"""Halaman Blockchain: log audit + verifikasi integritas aset penting."""
import json

import streamlit as st

from modules.database import execute_query
from modules.integrity import ASSET_LABEL, audit, record
from ui.common import flash, render_header, show_flash


def render(current_user, blockchain):
    render_header("Blockchain Audit Trail", "Setiap aktivitas & sidik jari aset penting tercatat permanen dengan SHA-256")
    show_flash()
    tab_log, tab_assets = st.tabs(["⛓️ Rantai Blok", "🛡️ Integritas Aset Penting"])

    with tab_log:
        c1, c2 = st.columns([1, 1])
        if c1.button("🔍 Validasi Integritas Blockchain"):
            ok, msg = blockchain.validate_chain()
            (st.success if ok else st.error)(("✅ " if ok else "❌ ") + msg)
        logs = execute_query("SELECT * FROM blockchain_logs ORDER BY block_index DESC", fetch=True) or []
        c2.download_button(
            "⬇️ Ekspor ledger (JSON)", file_name="blockchain_ledger.json", mime="application/json",
            data=json.dumps([{**l, "timestamp": str(l["timestamp"])} for l in reversed(logs)], indent=2, ensure_ascii=False),
        )
        st.caption(f"Total blok: {len(logs)} · Setiap blok menyimpan hash blok sebelumnya → mengubah satu blok "
                   f"merusak seluruh rantai setelahnya.")
        for log in logs[:200]:
            with st.container(border=True):
                st.markdown(f"**Block #{log['block_index']}** · {log['timestamp']}")
                st.code(log["data_payload"])
                st.caption(f"prev: `{log['previous_hash'][:24]}…` · hash: `{log['current_hash'][:24]}…`")
        if len(logs) > 200:
            st.caption("Menampilkan 200 blok terbaru. Gunakan ekspor JSON untuk melihat semuanya.")

    with tab_assets:
        st.markdown(
            "Sidik jari SHA-256 tiap aset penting (bank soal, file PDF, gambar token, nilai mahasiswa, template "
            "biometrik) dibandingkan dengan yang tercatat di blockchain. Jika ada yang mengubah data langsung di "
            "database (mis. menaikkan nilai lewat phpMyAdmin), statusnya menjadi **❌ DIMANIPULASI**."
        )
        chain_ok, chain_msg = blockchain.validate_chain()
        (st.success if chain_ok else st.error)(("⛓️ Rantai valid: " if chain_ok else "⛓️ Rantai rusak: ") + chain_msg)
        results = audit()
        if current_user["role"] == "student":
            mine = {f"submission:{s['id']}" for s in execute_query(
                "SELECT id FROM student_submissions WHERE user_id=%s", (current_user["id"],), fetch=True) or []}
            mine.add(f"biometric:{current_user['id']}")
            results = [r for r in results if r["key"] in mine or r["kind"] == "exam"]
        counts = {s: sum(1 for r in results if r["status"] == s) for s in ("valid", "tampered", "unrecorded")}
        m1, m2, m3 = st.columns(3)
        m1.metric("✅ Utuh", counts["valid"])
        m2.metric("❌ Dimanipulasi", counts["tampered"])
        m3.metric("⚠️ Tidak tercatat", counts["unrecorded"])

        icon = {"valid": "✅ Utuh", "tampered": "❌ DIMANIPULASI", "unrecorded": "⚠️ Tidak tercatat"}
        for kind, label in ASSET_LABEL.items():
            group = [r for r in results if r["kind"] == kind]
            if not group:
                continue
            st.markdown(f"#### {label}")
            for r in group:
                with st.container(border=True):
                    a, b = st.columns([3, 1])
                    a.markdown(f"**{r['label']}** · `{r['key']}`")
                    a.caption(f"Hash saat ini: `{r['current'][:32]}…`" +
                              (f" · tercatat di blok #{r['block']} ({r['event']})" if r["block"] is not None else ""))
                    if r["status"] == "tampered":
                        a.error(f"Hash di blockchain `{(r['recorded'] or '')[:32]}…` ≠ hash database. "
                                "Data diubah di luar aplikasi!")
                    b.markdown(f"### {icon[r['status']]}")
                    if current_user["role"] == "proctor" and r["status"] != "valid":
                        if b.button("📌 Catat ulang", key=f"rebase_{r['key']}",
                                    help="Jadikan kondisi sekarang sebagai acuan baru (setelah diperiksa)."):
                            record(blockchain, "REBASELINE_ASSET", r["kind"], r["id"],
                                   previous_status=r["status"], by=current_user["username"])
                            flash(f"📌 {r['key']} dicatat ulang di blockchain.")
                            st.rerun()
