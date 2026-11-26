#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026
#
# Verify that RPKI (ROA) validation results feed BGP route maps and that
# invalid and not-found (unknown) prefixes can be tagged separately using the
# ordinary route-map syntax.  Twenty prefixes are originated:
#
#   10.10.0.0/24  .. 10.10.6.0/24   valid     (matching ROA, AS 65530)
#   10.10.7.0/24  .. 10.10.13.0/24  invalid   (ROA exists for another AS)
#   10.10.14.0/24 .. 10.10.19.0/24  not-found (no ROA)
#
# The test also checks that changing the policy only triggers a route refresh
# and does not reset the established BGP session.

import os
import sys
import json
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import (  # noqa: E402
    Topogen,
    TopoRouter,
    get_topogen,
)

pytestmark = [pytest.mark.bgpd]

PEER = "192.168.1.1"

TAGS = {"valid": 100, "invalid": 666, "notfound": 777}


def _state_of(index):
    if index < 7:
        return "valid"
    if index < 14:
        return "invalid"
    return "notfound"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


rtrd_process = {}
base_counters = {}


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        extra = " -M bgpd_rpki" if rname == "r2" else ""
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, "{}/bgpd.conf".format(rname)),
            extra,
        )

    tgen.start_router()

    rname = "r1"
    rtr_path = os.path.join(CWD, rname)
    log_dir = os.path.join(tgen.logdir, rname)
    log_file = os.path.join(log_dir, "rtrd.log")

    tgen.gears[rname].run("chmod u+x {}/rtrd.py".format(rtr_path))
    rtrd_process[rname] = tgen.gears[rname].popen(
        "{}/rtrd.py {}".format(rtr_path, log_file)
    )


def teardown_module(mod):
    tgen = get_topogen()
    proc = rtrd_process.get("r1")
    if proc is not None:
        proc.kill()
    tgen.stop_topology()


def _dut():
    return get_topogen().gears["r2"]


def _routes():
    output = _dut().vtysh_cmd("show bgp ipv4 unicast json")
    return json.loads(output).get("routes", {})


def _peer_counters():
    output = _dut().vtysh_cmd("show bgp summary json")
    peer = json.loads(output)["ipv4Unicast"]["peers"][PEER]
    return (
        peer.get("state"),
        peer.get("connectionsEstablished"),
        peer.get("connectionsDropped"),
    )


def _wait_until(predicate, timeout=90, interval=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception:
            pass
        time.sleep(interval)
    raise AssertionError("condition not met; last={!r}".format(last))


def _path(routes, index):
    entry = routes.get("10.10.{}.0/24".format(index))
    if not entry:
        return None
    return entry[0] if isinstance(entry, list) else entry


def test_01_twenty_prefixes_classified():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def classified():
        routes = _routes()
        if len(routes) != 20:
            return None
        counts = {"valid": 0, "invalid": 0, "notfound": 0}
        for index in range(20):
            path = _path(routes, index)
            if path is None:
                return None
            if path.get("rpkiValid"):
                counts["valid"] += 1
            elif path.get("rpkiInvalid"):
                counts["invalid"] += 1
            elif path.get("rpkiNotFound"):
                counts["notfound"] += 1
            else:
                return None
        if counts != {"valid": 7, "invalid": 7, "notfound": 6}:
            raise AssertionError("unexpected RPKI distribution: {}".format(counts))
        base_counters["before_tag"] = _peer_counters()
        return counts

    result = _wait_until(classified)
    assert result == {"valid": 7, "invalid": 7, "notfound": 6}


def test_02_tag_invalid_and_unknown_separately():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _dut().vtysh_cmd(
        """
configure terminal
route-map RPKI-TAG permit 10
 match rpki valid
 set tag 100
exit
route-map RPKI-TAG permit 20
 match rpki notfound
 set tag 777
exit
route-map RPKI-TAG permit 30
 match rpki invalid
 set tag 666
exit
route-map RPKI-TAG permit 40
exit
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.168.1.1 route-map RPKI-TAG in
 exit-address-family
end
"""
    )

    def tags_applied():
        routes = _routes()
        if len(routes) != 20:
            return False
        for index in range(20):
            path = _path(routes, index)
            if path is None or path.get("tag") != TAGS[_state_of(index)]:
                return False
        return True

    assert _wait_until(tags_applied), "RPKI state tags were not applied to all prefixes"

    state, established, dropped = _peer_counters()
    before = base_counters.get("before_tag")
    assert state == "Established"
    if before and before[1] is not None:
        assert established == before[1], "session was reset while applying tag map"
        assert dropped == before[2]


def test_03_accept_reject_matches_rpki_and_no_session_reset():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    before = _peer_counters()
    invalid = {"10.10.{}.0/24".format(i) for i in range(7, 14)}

    _dut().vtysh_cmd(
        """
configure terminal
route-map RPKI-IN deny 10
 match rpki invalid
exit
route-map RPKI-IN permit 20
 match rpki notfound
 set tag 777
exit
route-map RPKI-IN permit 30
 match rpki valid
 set tag 100
exit
route-map RPKI-IN permit 40
exit
router bgp 65002
 address-family ipv4 unicast
  neighbor 192.168.1.1 route-map RPKI-IN in
 exit-address-family
end
"""
    )

    def filtered():
        routes = _routes()
        if len(routes) != 13:
            return False
        if any(prefix in routes for prefix in invalid):
            return False
        for index in list(range(0, 7)) + list(range(14, 20)):
            path = _path(routes, index)
            if path is None or path.get("tag") != TAGS[_state_of(index)]:
                return False
        return True

    assert _wait_until(filtered), "invalid prefixes were not rejected as expected"

    state, established, dropped = _peer_counters()
    assert state == "Established"
    assert established == before[1], "session reset when filter applied"
    assert dropped == before[2]

    # Repeated policy edits must only trigger route refresh, never a reset.
    for preference in (150, 160, 170):
        _dut().vtysh_cmd(
            """
configure terminal
route-map RPKI-IN permit 40
 set local-preference {}
exit
end
""".format(
                preference
            )
        )
        assert _wait_until(filtered)

    state, established, dropped = _peer_counters()
    assert state == "Established"
    assert established == before[1], "session reset after policy edits"
    assert dropped == before[2]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
