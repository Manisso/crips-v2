"""
Crips Framework — ssl_mod.py
SSL/TLS Certificate Inspector — ssl stdlib + pyOpenSSL
"""

import ssl
import socket
import datetime
from modules.colors import *
from modules.utils import prompt, resolve


def ssl_inspect():
    title_box("SSL/TLS INSPECTOR", "Certificate, ciphers & TLS version info")

    target = prompt("Enter Domain or IP")
    if not target:
        return
    port = prompt("Port", "443")
    try:
        port = int(port)
    except ValueError:
        port = 443

    ip = resolve(target)
    if not ip:
        return
    sep()
    print(f"    {WHITE}Connecting to:{RST} {CYAN}{target}:{port}{RST}\n")

    # ── stdlib ssl — basic cert info (always works) ───────────
    header("Certificate Details  [ssl stdlib]")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET), server_hostname=target
        ) as ssock:
            ssock.settimeout(8)
            ssock.connect((ip, port))
            cert    = ssock.getpeercert()
            cipher  = ssock.cipher()
            version = ssock.version()
            der     = ssock.getpeercert(binary_form=True)

        # TLS version & cipher
        tls_color = GREEN if version in ("TLSv1.3", "TLSv1.2") else RED
        print(f"    {YELLOW}TLS Version       {RST}: {tls_color}{version}{RST}")
        if cipher:
            print(f"    {YELLOW}Cipher Suite      {RST}: {WHITE}{cipher[0]}{RST}")
            print(f"    {YELLOW}Key Bits          {RST}: {WHITE}{cipher[2]}{RST}")
        print()

        # Subject
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        fields = [
            ("Common Name",         subj.get("commonName")),
            ("Organization",        subj.get("organizationName")),
            ("Org Unit",            subj.get("organizationalUnitName")),
            ("Country",             subj.get("countryName")),
            ("State",               subj.get("stateOrProvinceName")),
            ("Issued By",           issuer.get("commonName")),
            ("Issuer Org",          issuer.get("organizationName")),
        ]
        for k, v in fields:
            if v:
                kv(k, v)

        # Validity
        print()
        not_before = cert.get("notBefore")
        not_after  = cert.get("notAfter")
        if not_before and not_after:
            fmt = "%b %d %H:%M:%S %Y %Z"
            nb  = datetime.datetime.strptime(not_before, fmt)
            na  = datetime.datetime.strptime(not_after, fmt)
            now = datetime.datetime.utcnow()
            days_left = (na - now).days

            exp_color = GREEN if days_left > 30 else YELLOW if days_left > 7 else RED
            kv("Valid From",  nb.strftime("%Y-%m-%d %H:%M UTC"))
            kv("Valid Until", na.strftime("%Y-%m-%d %H:%M UTC"))
            kv("Days Left",   f"{exp_color}{days_left} days{RST}")

            if days_left < 0:
                err("Certificate has EXPIRED!")
            elif days_left < 30:
                warn(f"Certificate expires soon ({days_left} days)!")
            else:
                ok(f"Certificate valid for {days_left} more days.")

        # SANs (Subject Alternative Names)
        sans = cert.get("subjectAltName", [])
        if sans:
            print()
            header("Subject Alternative Names (SANs)")
            dns_sans  = [v for t, v in sans if t == "DNS"]
            ip_sans   = [v for t, v in sans if t == "IP Address"]
            for s in dns_sans[:20]:
                print(f"    {CYAN}  DNS: {s}{RST}")
            for s in ip_sans:
                print(f"    {CYAN}  IP:  {s}{RST}")
            if len(dns_sans) > 20:
                info(f"  ... and {len(dns_sans)-20} more DNS SANs")
            kv("Total SANs", str(len(sans)))

    except ssl.SSLCertVerificationError as e:
        warn(f"Certificate verification failed (showing anyway): {e}")
    except ConnectionRefusedError:
        err(f"Connection refused on port {port}")
        sep()
        return
    except Exception as e:
        err(f"SSL connection error: {e}")

    # ── pyOpenSSL — extended info ─────────────────────────────
    header("Extended Info  [pyOpenSSL]")
    try:
        from OpenSSL import SSL, crypto

        ctx2 = SSL.Context(SSL.TLS_METHOD)
        ctx2.set_verify(SSL.VERIFY_NONE, lambda *a: True)
        conn2 = SSL.Connection(ctx2, socket.socket())
        conn2.settimeout(8)
        conn2.connect((ip, port))
        conn2.set_tlsext_host_name(target.encode())
        conn2.do_handshake()

        cert_obj  = conn2.get_peer_certificate()
        chain     = conn2.get_peer_cert_chain()

        serial    = format(cert_obj.get_serial_number(), "x").upper()
        sha1      = cert_obj.digest("sha1").decode()
        sha256    = cert_obj.digest("sha256").decode()
        sig_alg   = cert_obj.get_signature_algorithm().decode()
        pubkey    = cert_obj.get_pubkey()
        key_bits  = pubkey.bits()
        key_type  = "RSA" if pubkey.type() == crypto.TYPE_RSA else \
                    "EC"  if pubkey.type() == crypto.TYPE_EC  else "Other"

        kv("Serial Number",  serial)
        kv("Signature Alg",  sig_alg)
        kv("Public Key",     f"{key_type} {key_bits}-bit")
        kv("SHA1 Fingerprint",   sha1)
        kv("SHA256 Fingerprint", sha256)

        # Cert chain
        if chain and len(chain) > 1:
            print()
            header("Certificate Chain")
            for i, c in enumerate(chain):
                subj2 = c.get_subject()
                iss2  = c.get_issuer()
                label = "  [LEAF]" if i == 0 else f"  [CA {i}]"
                print(f"    {CYAN}{label}{RST}  {WHITE}{subj2.CN or 'N/A'}{RST}"
                      f"  {GRAY}issued by {iss2.CN or 'N/A'}{RST}")

        conn2.close()

    except ImportError:
        warn("pyOpenSSL not installed — install for extended info: pip install pyOpenSSL")
    except Exception as e:
        warn(f"pyOpenSSL info unavailable: {e}")

    # ── TLS version support matrix ────────────────────────────
    header("TLS Version Support Matrix")
    TLS_VERSIONS = [
        ("SSL 2.0",  ssl.PROTOCOL_TLS_CLIENT, "SSLv2"),
        ("SSL 3.0",  ssl.PROTOCOL_TLS_CLIENT, "SSLv3"),
        ("TLS 1.0",  ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
        ("TLS 1.1",  ssl.PROTOCOL_TLS_CLIENT, "TLSv1.1"),
        ("TLS 1.2",  ssl.PROTOCOL_TLS_CLIENT, "TLSv1.2"),
        ("TLS 1.3",  ssl.PROTOCOL_TLS_CLIENT, "TLSv1.3"),
    ]
    for name, proto, ver_str in TLS_VERSIONS:
        try:
            ctx3 = ssl.SSLContext(proto)
            ctx3.check_hostname = False
            ctx3.verify_mode = ssl.CERT_NONE
            # Force specific version
            if hasattr(ssl, "OP_NO_TLSv1_3") and ver_str != "TLSv1.3":
                ctx3.options |= ssl.OP_NO_TLSv1_3
            with ctx3.wrap_socket(
                socket.socket(), server_hostname=target
            ) as ts:
                ts.settimeout(3)
                ts.connect((ip, port))
                actual = ts.version()
                safe = actual in ("TLSv1.3", "TLSv1.2")
                color = GREEN if safe else RED
                print(f"    {color}{'✓' if actual else '✗'}{RST}  "
                      f"{YELLOW}{name:<10}{RST}  {color}{actual or 'not supported'}{RST}")
        except ssl.SSLError:
            print(f"    {GRAY}✗  {name:<10}  not supported{RST}")
        except Exception:
            pass

    sep()
