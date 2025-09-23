#!/usr/bin/env python3
import argparse, sys, time
import miniupnpc

def main():
    p = argparse.ArgumentParser(description="UPnP port mapping tester")
    p.add_argument("--port", type=int, default=8080, help="Internal/external port to map")
    p.add_argument("--proto", choices=["TCP", "UDP"], default="TCP", help="Protocol")
    p.add_argument("--lease", type=int, default=3600, help="Lease duration (seconds)")
    p.add_argument("--desc", default="TinyWeb-UPnP-Test", help="Mapping description")
    p.add_argument("--ext-port", type=int, default=None, help="External port (default: same as --port)")
    p.add_argument("--remove", action="store_true", help="Remove mapping and exit")
    p.add_argument("--list", action="store_true", help="List existing mappings and exit")
    args = p.parse_args()

    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 200
    ndevices = upnp.discover()
    if ndevices == 0:
        print("No UPnP IGD found on the network.")
        sys.exit(1)

    try:
        upnp.selectigd()
    except Exception as e:
        print(f"Failed to select IGD: {e}")
        sys.exit(1)

    lan_ip = upnp.lanaddr
    try:
        wan_ip = upnp.externalipaddress()
    except Exception as e:
        print(f"Failed to get external IP: {e}")
        sys.exit(1)

    print(f"LAN IP: {lan_ip}")
    print(f"WAN IP: {wan_ip}")
    print(f"IGD: {upnp.urlbase if hasattr(upnp, 'urlbase') else 'selected'}")

    if args.list:
        i = 0
        while True:
            try:
                e = upnp.getgenericportmapping(i)
            except Exception:
                break
            if not e:
                break
            (ext_port, proto, int_client, int_port, desc, _, enabled, lease, _) = (
                int(e[0]), e[1], e[2], int(e[3]), e[4], e[5], e[6], e[7], e[8]
            )
            print(f"[{i}] {proto} {wan_ip}:{ext_port} -> {int_client}:{int_port} "
                  f"desc='{desc}' enabled={enabled} lease={lease}")
            i += 1
        sys.exit(0)

    ext_port = args.ext_port if args.ext_port is not None else args.port
    proto = args.proto

    if args.remove:
        try:
            ok = upnp.deleteportmapping(ext_port, proto)
            print(f"Remove {proto} {ext_port}: {'OK' if ok else 'FAILED'}")
        except Exception as e:
            print(f"Remove failed: {e}")
        sys.exit(0)

    # Add mapping
    try:
        ok = upnp.addportmapping(
            ext_port, proto, lan_ip, args.port, args.desc, "", args.lease
        )
    except Exception as e:
        print(f"Add mapping failed: {e}")
        sys.exit(1)

    if not ok:
        print("Add mapping returned failure.")
        sys.exit(1)

    print(f"Added mapping: {proto} {wan_ip}:{ext_port} -> {lan_ip}:{args.port} "
          f"(lease {args.lease}s, desc '{args.desc}')")

    # Verify
    time.sleep(0.1)
    found = False
    i = 0
    while True:
        try:
            e = upnp.getgenericportmapping(i)
        except Exception:
            break
        if not e:
            break
        if int(e[0]) == ext_port and e[1] == proto:
            print(f"Verified mapping at index {i}: {e}")
            found = True
            break
        i += 1

    if not found:
        print("Warning: Could not verify mapping via table enumeration.")

    print("\nTo remove mapping later:")
    print(f"  python upnp_test.py --remove --proto {proto} --port {args.port} --ext-port {ext_port}")

if __name__ == "__main__":
    main()