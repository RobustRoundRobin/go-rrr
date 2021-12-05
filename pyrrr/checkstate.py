"""Crude utility to assess the DRGB state alignment based on rrr logs"""
import sys
import argparse
import glob
import os
from .clicommon import run_and_exit


class RoundSamples:

    def __init__(self, args=None):
        self.args = args
        self.minround = -1
        self.maxround = 0
        self.rounds = {}
        self.peertotalfails = {}
        self.peertotalunknown = {}
        self.leadersfailed = 0
        self.endorsersfailed = 0
        self.activefailed = 0

    def scrape_files(self, filenames):

        self.peernames = filenames[:]

        for p in self.peernames:
            self.peertotalfails[p] = 0
            self.peertotalunknown[p] = 0

        for p in filenames:  # filename is a proxy for peername
            with open(p, "r") as fp:
                for line in fp:

                    sample = scrape_round_result(line)
                    if sample:
                        self.update_round_sample(p, sample)
                        if sample["y"] is False:
                            self.peertotalfails[p] += 1
                            if sample["ro"] == "leader":
                                self.leadersfailed += 1
                            elif sample["ro"] == "endorser":
                                self.endorsersfailed += 1
                            else:
                                self.activefailed += 1

                        elif sample["y"] is None:
                            self.peertotalunknown[p] += 1
                        continue

                    # this will capture the head block details in the sample for
                    # the round it was accumulated on for each peer
                    sample = scrape_active_sample(line)
                    if sample:
                        self.update_round_sample(p, sample)
                        continue

                    # This will capture the DRGB state, and everything that affects
                    # it, in the sample for each round
                    sample = scrape_drng_sample(line)
                    if sample:
                        self.update_round_sample(p, sample)
                        continue

                    # This will capture each candidate in each round and record it
                    # along side the peer sample
                    cand = scrape_round_candidate(line)
                    if cand:
                        self.add_round_cand(p, cand)
                        continue

                    ends = scrape_round_endorser(line)
                    if ends:
                        self.add_round_ends(p, ends)
                        continue
                
                    act = scrape_round_active_id(line)
                    if act:
                        self.add_round_active(p, act)
                        continue

    def update_round_range(self, r):

        if r < self.minround or self.minround < 0:
            self.minround = r
        if r > self.maxround:
            self.maxround = r


    def update_round_sample(self, source, update):

        r = self._prune_round(None, update)
        if r is None:
            return

        # every source gets a single sample record per round (and may have other records besides)
        sample = self.rounds.setdefault(r, {}).setdefault(source, {}).setdefault("sample", {})
        sample.update(**update)

        self.update_round_range(r)


    def add_round_cand(self, source, cand):
        """collect the candidates selected for each round"""

        r = self._prune_round(None, cand)
        if r is None:
            return

        self.rounds.setdefault(r, {}).setdefault(source, {}).setdefault('cands', {})[cand['ic']] = cand
        self.update_round_range(r)


    def add_round_ends(self, source, ends):
        """collect the endorsers selected for each round"""

        r = self._prune_round(None, ends)
        if r is None:
            return

        self.rounds.setdefault(r, {}).setdefault(source, {}).setdefault('ends', {})[ends['ie']] = ends
        self.update_round_range(r)

    def add_round_active(self, source, act):
        """collect the endorsers selected for each round"""

        r = self._prune_round(None, act)
        if r is None:
            return

        self.rounds.setdefault(r, {}).setdefault(source, {}).setdefault('act', {})[act['ia']] = act
        self.update_round_range(r)

    def _prune_round(self, r, update):
        if "r" in update:
            rr = update.pop("r")
            if r is not None and r != rr:
                raise ValueError(f"inconsistent round {r} vs {rr} in update: {update}")

            if r is None:
                r = rr
        else:
            if r is None:
                raise ValueError("round number missing for update")

        if r > self.args.minround:
            return r

        if r < self.args.maxround and self.args.maxround != 0:
            return r


    DRGB_FIELDS="ns s c a kn drng_ns drng_s drng_a drng_bn drng_br drng_h".split()
    SCALAR_FIELDS="y ns a kn bn bh ha hr hn hb drng_ns drng_a drng_bn drng_br drng_h acc_a acc_hr acc_bn acc_h".split()
    TUPLE_FIELDS="s drng_s".split()
    NUMERIC_FIELDS="ns a kn bn ha hr hn drng_ns drng_a drng_bn drng_br acc_a acc_hr acc_bn".split()

    DIVERGENCE_FIELDS="y e c ns s a act idle bn bh hr hn ha drng_ns drng_s drng_a drng_bn drng_br drng_h acc_a acc_hr acc_bn acc_h".split()

    def collate_samples(self):
        """process all the samples looking for divergence accross peers"""

        scalar_fields = self.SCALAR_FIELDS[:]
        numeric_fields = self.NUMERIC_FIELDS[:]

        on = dict((k, 0) for k in scalar_fields + self.TUPLE_FIELDS + ['c', 'e', 'act', 'idle'])

        divergence_fields = self.DIVERGENCE_FIELDS

        if self.args.divon:
            divergence_fields = list(set(self.args.divergent_on.split(",")))
        if self.args.divon_extend:
            divergence_fields = set(divergence_fields)
            for xon in self.args.divon_extend.split(","):
                if xon not in divergence_fields:
                    divergence_fields.add(xon)
                    scalar_fields.append(xon)
                    numeric_fields.append(xon)

            divergence_fields = list(divergence_fields)

        quieton = []
        if self.args.quieton:
            quieton = self.args.quieton.split(",")

        rounds = self.rounds

        maxdivergent = 0
        numdivergentrounds = 0
        numdrgb_divergent = 0
        same_head_drgb_divergent = 0

        for r in range(self.minround, self.maxround):

            if r < self.args.minround:
                continue

            if r > self.args.maxround and self.args.maxround != 0:
                continue

            col = dict((k, {}) for k in on)

            snmax = dict((k, 0) for k in scalar_fields if k in numeric_fields)
            snmin = dict((k, -1) for k in scalar_fields if k in numeric_fields)

            for p in self.peernames:

                if r not in rounds:
                    continue
                if not p in rounds[r]:
                    # idle[p].append(r)
                    # print(f"r={r} no sample from {p}")
                    continue
                sample = rounds[r][p].get('sample')
                if sample:
                    for k in col:
                        if k not in sample:
                            continue
                        v = sample[k]
                        if k in self.TUPLE_FIELDS:
                            v = tuple(v)

                        # If all peers have the same value we are not divergent.
                        # If some peers are missing a sample we ignore that
                        # (they may have been offline)
                        col[k].setdefault(v, []).append(p)

                        if k in numeric_fields:
                            if sample[k] < snmin[k] or snmin[k] < 0:
                                snmin[k] = sample[k]
                            if sample[k] > snmax[k]:
                                snmax[k] = sample[k]

                # candidate and endorser selection for a round needs special handling
                cands = rounds[r][p].get('cands')
                if cands:
                    ics = [ic for ic in cands]
                    ics.sort()
                    col["c"].setdefault(tuple([cands[ic]["id"] for ic in ics]), []).append(p)

                ends = rounds[r][p].get('ends')
                if ends:
                    ies = [ie for ie in ends]
                    ies.sort()
                    col["e"].setdefault(tuple([ends[ie]["id"] for ie in ies]), []).append(p)

                act = rounds[r][p].get('act')
                if act:
                    ias = [ia for ia in act]
                    ias.sort()
                    col["act"].setdefault(tuple([act[ia]["id"] for ia in ias]), []).append(p)
                    col["idle"].setdefault(tuple(sorted([act[ia]["id"] for ia in ias if act[ia]['idle'] is True])), []).append(p)


            if "act" not in quieton:
                nidle = max((len(idles) for idles in col["idle"]), default=0)
                print(f"round {r} selection ------------- [idle={nidle}]")
                if len(col["c"]) == 1 and len(col["e"]) == 1:
                    print(f"select-aligned: |{', '.join(list(col['c'])[0])}|{', '.join(list(col['e'])[0])}")
                else:
                    if len(col["c"]) == 0:
                        print(f"cands: not found")
                    elif len(col["c"]) == 1:
                        print(f"cands-aligned: {', '.join(list(col['c'])[0])}")
                    else:
                        for i, selection in enumerate(col["c"]):
                            print(f"{i}:cands-diverged: {', '.join(selection)}")

                    if len(col["e"]) == 0:
                        print(f"ends: not found")
                    if len(col["e"]) == 1:
                        print(f"ends-aligned: {', '.join(list(col['e'])[0])}")
                    else:
                        for i, selection in enumerate(col["e"]):
                            print(f"{i}:ends-diverged: {', '.join(selection)}")

                print(f".................................")
                if len(col["act"]) == 1 and len(col["idle"]) == 1:
                    print(f"active-aligned: {', '.join(list(col['act'])[0])}")
                    if list(col['idle'])[0]:
                        print(f"idle: {', '.join(list(col['idle'])[0])}")
                else:
                    for i, selection in enumerate(col["act"]):
                        print(f"{i}:active-diverged: {', '.join(selection)}")
                    for i, idle in enumerate(col["idle"]):
                        print(f"{i}:idle-diverged: {', '.join(idle)}")

            for k in col.keys():
                if not len(col[k]) > 1:
                    continue
                on[k] += 1
                if k in numeric_fields:
                    vals = f" blocks={[v for v in col['bn']]}, ok={len(col['y'].get(True, []))}"
                    if self.args.show_values and k not in quieton:
                        vals += f" {[v for v in col[k]]}"
                    print(
                        f"{k}: r={r} {snmax[k]-snmin[k]} divn={len(col[k])}"
                        f" dist={[len(v) for v in col[k].values()]}"
                        + vals 
                        )
                    continue
                if k not in scalar_fields:
                    vals = f" blocks={[v for v in col['bn']]}, ok={len(col['y'].get(True, []))}"
                    if self.args.show_values and k not in quieton:
                        vals += f" {[v for v in col[k]]}"
                    print(
                        f"{k}: r={r} divn={len(col[k])}"
                        f" dist={[len(v) for v in col[k].values()]}"
                        + vals 
                        )
                    continue

            divergent_on = [f for f in divergence_fields if len(col.get(f, [])) > 1]
            divergent = len(divergent_on) > 0

            if divergent:
                print(f"divergent_on: {divergent_on}")

                numdivergentrounds += 1

                for f in divergence_fields:
                    if len(col.get(f, [])) > maxdivergent:
                        maxdivergent = len(col[f])

            drgb_divergent_on = [f for f in self.DRGB_FIELDS if len(col.get(f, [])) > 1]
            drgb_divergent = len(drgb_divergent_on) > 0
            if drgb_divergent:
                numdrgb_divergent += 1
            if len(col["bn"]) == 1 and divergent:
                same_head_drgb_divergent +=1

        if numdivergentrounds > 0:
            ons = ", ".join([f"{k}={on[k]}" for k in on if on[k] > 1])
            print(
                  f"nrounds: {self.maxround - self.minround}, round range: {self.minround} - {self.maxround}, divergent rounds: {numdivergentrounds}"
                  f", max round states: {maxdivergent}"
                  f", same_head_drgb_divergent: {same_head_drgb_divergent}"
                  f", {ons}")

        for p in self.peernames:
            print(f"{p} rounds  failed: {self.peertotalfails[p]}")
            print(f"{p} rounds unknown: {self.peertotalunknown[p]}")

        print(f"leaders failed: {self.leadersfailed}, endorsers failed: {self.endorsersfailed}, active failed: {self.activefailed}")


def scrape_round_result(line):
    """
    lines like::

       RRR PhaseTick - ROUND SUCCESS ++++++++   r=337
       RRR PhaseTick - ROUND FAILED  xxxxxxxx   r=337 f=2
    """
    marker = "RRR PhaseTick - ROUND"
    i = line.find(marker)
    if i < 0:
        return None
    content=line[i+len(marker):].strip()
    r, content = split_named_num("r", content)
    try:
        ro = named("ro", content)
    except IndexError:
        ro = "unknown"
    # f = named_num("f", content)

    result = None
    if "ROUND SUCCESS" in line:
        result = True
    if "ROUND FAILED" in line:
        result = False

    return dict(r=r, y=result, ro=ro)


def scrape_accumulate_head(line):
    """
    lines like::

        RRR accumulateActive - for block         r=13  hr=123 a=123 bn=1 #=aab8be2c6a33b250e3455e08497779d8fa88df5a401a6aa9e8276cf5f467cc82

    This is the log record of where AccumulateActive started - which is the
    most recent block delivered by NewChainHead.
    """
    marker = "RRR accumulateActive - for block"
    i = line.find(marker)
    if i < 0:
        return None
    content=line[i+len(marker):].strip()

    r, content = split_named_num("r", content)
    hr = named_num("hr", content)
    a = named_num("a", content)
    br = named_num("br", content)
    bn = named_num("bn", content)
    h = named_num("#", content)

    return dict(r=r, acc_a=a, acc_hr=hr, acc_bn=bn, acc_h=h)


def scrape_drng_sample(line):
    """
    lines like::

        RRR DRGB SAMPLE   ...........            r=12 ns=197 s="[21 8 25 2 26 20 12 15 11 6 0 3]"     a=30 df=1 bn=123 br=123 #=0xabc
    """

    marker = "RRR DRGB SAMPLE   ...........            "

    i = line.find(marker)
    if i < 0:
        return None
    content = line[i+len(marker):].strip()

    r, content = split_named_num("r", content)
    ns = named_num("ns", content)
    s = named_numlist("s", content)
    a = named_num("a", content)
    df = named_num("df", content)
    bn = named_num("bn", content)
    br = named_num("br", content)
    h = named("#", content)

    return dict(r=r, drng_ns=ns, drng_s=s, drng_a=a, df=df, drng_bn=bn, drng_br=br, drng_h=h)

def scrape_round_active_id(line):
    """
    lines like::

        RRR AccumulateActive - ordered           r=33 id=eff3fd71bbab2ba839767210b5c542d4b4787214 ia=0  idle=false
    """
    marker = "RRR AccumulateActive - ordered"
    i = line.find(marker)
    if i < 0 :
        return None

    content = line[i+len(marker):].strip()
    r = named_num("r", content)
    id = named("id", content)
    ia = named_num("ia", content)
    idle = named("idle", content)
    if idle == "true":
        idle = True
    if idle == "false":
        idle = False

    return dict(r=r, id=id, ia=ia, idle=idle)

def scrape_round_candidate(line):
    """
    lines like::

        RRR selectCandEs - select cand=4834d1e3235c7191980f89ea7c292695608894f0:00000.00 ic=0 a=0  r=123 ar=123

    """

    marker = "RRR selectCandEs - select"
    i = line.find(marker)
    if i < 0 or "cand=" not in line:
        return None
    content = line[i+len(marker):].strip()
    id = named("cand", content, termsep=":")
    ic = named_num("ic", content)
    a = named_num("a", content)
    r = named_num("r", content)
    ar = named_num("ar", content)

    return dict(r=r, id=id, ic=ic, a=a, ar=ar)


def scrape_round_endorser(line):
    """
    lines like::

        RRR selectCandEs - select endo=4834d1e3235c7191980f89ea7c292695608894f0:00000.00 ic=0 a=0  r=123 ar=123

    """

    marker = "RRR selectCandEs - select"
    i = line.find(marker)
    if i < 0 or "endo=" not in line:
        return None
    content = line[i+len(marker):].strip()
    id = named("endo", content, termsep=":")
    ie = named_num("ie", content)
    a = named_num("a", content)
    r = named_num("r", content)
    ar = named_num("ar", content)

    return dict(r=r, id=id, ie=ie, a=a, ar=ar)


def scrape_active_sample(line):
    """
    lines like::

         RRR ACTIVE SAMPLE >>>>>>>>>              s="[21 8 25 2 26 20 12 15 11 6 0 3]"     ns=197 r=13 bn=0 #head=c5aaad9cd25dd7012fe19b65c1e50cbc919cbfecabcea469ae8d374ae

    """

    active_sample_marker="ACTIVE SAMPLE >>>>>>>>>"
    i = line.find(active_sample_marker)
    if i < 0:
        return None

    content = line[i+len(active_sample_marker):].strip()

    s = named_numlist("s", content)
    ns = named_num("ns", content)
    r = named_num("r", content)
    bn = named_num("bn", content)
    bh = named("#head", content)

    return dict(r=r, ns=ns, s=s, bn=bn, bh=bh)



def find_marker(marker, content):

    # prioritise ws word boundary match
    i = content.find(" " + marker)
    if i > -1:
        return i + 1 + len(marker)

    # account for startswith
    if content.startswith(marker):
        return 0 + len(marker)
    raise IndexError(f"{marker} not found in {content}")

def find_named_var(name, content):
    return find_marker(f"{name}=", content)


def split_named(name, content, termsep=None):

    i = find_named_var(name, content)
    var, *content = content[i:].split(termsep, 1)
    return var, content and content[0] or ''


def named(name, content, termsep=None):
    return split_named(name, content, termsep=termsep)[0]


def split_named_num(name, content, termsep=None):
    var, content = split_named(name, content, termsep=termsep)
    return int(var), content


def named_num(name, content, termsep=None):
    return split_named_num(name, content, termsep=termsep)[0]


def split_named_numlist(name, content):
    i = find_marker(name + "=\"[", content)
    var, content = content[i:].split("]", 1)
    return [int(n) for n in var.split()], content


def named_numlist(name, content):
    return split_named_numlist(name, content)[0]


def cmd_scrape(args):
    """Scrape a set of rrr node logs"""

    rounds = RoundSamples(args)

    files = []
    for fnpattern in args.files:
        files.extend(glob.glob(fnpattern))
    if not files:
        print("no files found")
        sys.exit(-1)

    rounds.scrape_files(files)
    rounds.collate_samples()

def run(args=None):
    if args is None:
        args = sys.argv[1:]

    top = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    top.set_defaults(func=lambda a: print("see sub commands in help"))

    subcmd = top.add_subparsers(title="Available commands")
    p = subcmd.add_parser("scrape", help=cmd_scrape.__doc__)
    p.add_argument("files", nargs="+")
    p.add_argument("-m", "--minround", type=int, default=1)  # the logs for r=0 don't make sense (round is miss logged until first block arrives)
    p.add_argument("-x", "--maxround", type=int, default=0)
    p.add_argument("-V", "--no-show-values", dest="show_values", default=True, action="store_false")
    p.add_argument("-o", "--divon", help="comma seperated list")
    p.add_argument("-a", "--divon-extend", help="comma seperated list, added to defaults")
    p.add_argument("-q", "--quieton", help="comma seperated list")

    p.set_defaults(func=cmd_scrape)
    args = top.parse_args()
    args.func(args)

def main():
    run_and_exit(run)

if __name__ == "__main__":
    main()
